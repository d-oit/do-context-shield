//! Explicit opt-in JSON-file vault for CLI-to-CLI workflows.

use do_context_shield_plugin_api::{Mapping, ScopeId, Vault, VaultError};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

#[derive(Default, Serialize, Deserialize)]
struct State {
    mappings: Vec<MappingRecord>,
    counters: Vec<CounterRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MappingRecord {
    scope: String,
    mapping: Mapping,
}

#[derive(Clone, Serialize, Deserialize)]
struct CounterRecord {
    scope: String,
    kind: String,
    value: usize,
}

/// Advisory lock over the vault file, released when dropped.
///
/// Every read-modify-write cycle (`get_or_insert`, `delete_scope`) holds the
/// exclusive lock; `open` holds a shared lock while reading, so a reader never
/// observes a half-written file. The OS releases the lock when the file
/// closes, so a crashed process cannot leave a stale lock behind.
struct Lock {
    file: File,
}

impl Lock {
    /// Take the exclusive (writer) lock for `path`.
    fn exclusive(path: &Path) -> Result<Self, VaultError> {
        Self::acquire(path, true)
    }

    /// Take the shared (reader) lock for `path`.
    fn shared(path: &Path) -> Result<Self, VaultError> {
        Self::acquire(path, false)
    }

    fn acquire(path: &Path, exclusive: bool) -> Result<Self, VaultError> {
        let lock_path = lock_path(path);
        if let Some(parent) = lock_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| io_error(&error))?;
            }
        }
        let file = restricted_file(&lock_path)?;
        // Fully qualified calls avoid the collision with the inherent
        // `File::lock_shared`/`lock_exclusive` methods added in newer std.
        let result = if exclusive {
            FileExt::lock_exclusive(&file)
        } else {
            FileExt::lock_shared(&file)
        };
        result.map_err(|error| io_error(&error))?;
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Best-effort release; closing the file releases it in any case.
        let _ = FileExt::unlock(&self.file);
    }
}

/// Lock file beside `path` (`vault.json` → `vault.json.lock`).
fn lock_path(path: &Path) -> PathBuf {
    path.with_extension("json.lock")
}

/// File-backed local vault. Use only with an access-controlled local path.
///
/// The vault file holds original values by design and is created with
/// owner-only permissions on Unix. Sequential processes share state by
/// reloading the file on every insert; concurrent writers are serialized
/// through an advisory lock on `<path>.lock`.
pub struct JsonVault {
    path: PathBuf,
    state: State,
}

impl JsonVault {
    /// Open or create a JSON vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read, parsed, or created.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let path = path.into();
        if path.exists() {
            let loaded: State = {
                let _lock = Lock::shared(&path)?;
                let file = File::open(&path).map_err(|error| io_error(&error))?;
                serde_json::from_reader(BufReader::new(file)).map_err(|error| json_error(&error))?
            };
            restrict_permissions(&path)?;
            Ok(Self {
                path,
                state: loaded,
            })
        } else {
            Ok(Self {
                path,
                state: State::default(),
            })
        }
    }

    /// Reload state from disk so sequential processes observe each other's
    /// inserts. Missing files mean empty state; corrupt files are errors.
    ///
    /// The caller must already hold the exclusive [`Lock`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read or parsed.
    fn reload_locked(&mut self) -> Result<(), VaultError> {
        if self.path.exists() {
            let file = File::open(&self.path).map_err(|error| io_error(&error))?;
            self.state = serde_json::from_reader(BufReader::new(file))
                .map_err(|error| json_error(&error))?;
        }
        Ok(())
    }

    /// Write state through a temporary file and an atomic rename.
    ///
    /// The caller must already hold the exclusive [`Lock`].
    fn persist_locked(&self) -> Result<(), VaultError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| io_error(&error))?;
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let file = restricted_file(&tmp)?;
            serde_json::to_writer(BufWriter::new(file), &self.state)
                .map_err(|error| json_error(&error))?;
        }
        fs::rename(&tmp, &self.path).map_err(|error| io_error(&error))?;
        Ok(())
    }
}

/// Create a file readable only by its owner (Unix); default creation elsewhere.
fn restricted_file(path: &std::path::Path) -> Result<File, VaultError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| io_error(&error))
}

/// Tighten an existing vault file to owner-only permissions (Unix no-op elsewhere).
fn restrict_permissions(path: &std::path::Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error(&error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

impl Vault for JsonVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        // Serialize the whole reload-modify-persist cycle so concurrent
        // writers cannot lose each other's mappings or reuse a counter.
        let _lock = Lock::exclusive(&self.path)?;
        // Reload so sequential CLI processes share counters and mappings.
        self.reload_locked()?;
        if let Some(existing) = self.state.mappings.iter().find(|record| {
            record.scope == scope.0
                && record.mapping.kind == kind
                && record.mapping.original == original
        }) {
            return Ok(existing.mapping.clone());
        }

        let counter = self
            .state
            .counters
            .iter_mut()
            .find(|record| record.scope == scope.0 && record.kind == kind);
        let next = if let Some(record) = counter {
            record.value += 1;
            record.value
        } else {
            self.state.counters.push(CounterRecord {
                scope: scope.0.clone(),
                kind: kind.to_owned(),
                value: 1,
            });
            1
        };

        let mapping = Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token: format!("__DO_PRIVATE_{}_{}__", kind.to_ascii_uppercase(), next),
        };
        self.state.mappings.push(MappingRecord {
            scope: scope.0.clone(),
            mapping: mapping.clone(),
        });
        self.persist_locked()?;
        Ok(mapping)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        Ok(self
            .state
            .mappings
            .iter()
            .find(|record| record.scope == scope.0 && record.mapping.token == token)
            .map(|record| record.mapping.clone()))
    }

    fn delete_scope(&mut self, scope: &ScopeId) -> Result<(), VaultError> {
        let _lock = Lock::exclusive(&self.path)?;
        self.reload_locked()?;
        self.state.mappings.retain(|record| record.scope != scope.0);
        self.state.counters.retain(|record| record.scope != scope.0);
        self.persist_locked()
    }
}

fn io_error(error: &io::Error) -> VaultError {
    VaultError::Message(error.to_string())
}

fn json_error(error: &serde_json::Error) -> VaultError {
    VaultError::Message(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "do-context-shield-vault-test-{}-{id}.json",
            std::process::id()
        ))
    }

    fn stored(vault: &mut JsonVault, scope: &ScopeId, kind: &str, original: &str) -> Mapping {
        match vault.get_or_insert(scope, kind, original) {
            Ok(mapping) => mapping,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn resolved(vault: &JsonVault, scope: &ScopeId, token: &str) -> Option<Mapping> {
        match vault.resolve(scope, token) {
            Ok(mapping) => mapping,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn open(path: &PathBuf) -> JsonVault {
        match JsonVault::open(path) {
            Ok(vault) => vault,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn scope(name: &str) -> ScopeId {
        ScopeId(name.to_owned())
    }

    fn cleanup(path: &PathBuf) {
        fs::remove_file(path).ok();
        fs::remove_file(lock_path(path)).ok();
        fs::remove_file(path.with_extension("json.tmp")).ok();
    }

    #[test]
    fn mappings_survive_reopen_and_share_counters() {
        let path = temp_path();
        let scope = scope("s");
        let first = match JsonVault::open(&path) {
            Ok(mut vault) => stored(&mut vault, &scope, "email", "alice@example.com"),
            Err(error) => panic!("unexpected error: {error}"),
        };
        let mut reopened = match JsonVault::open(&path) {
            Ok(vault) => vault,
            Err(error) => panic!("unexpected error: {error}"),
        };
        match reopened.resolve(&scope, &first.token) {
            Ok(resolved) => assert_eq!(resolved, Some(first.clone())),
            Err(error) => panic!("unexpected error: {error}"),
        }
        let second = stored(&mut reopened, &scope, "email", "bob@example.com");
        assert_ne!(first.token, second.token);
        assert!(second.token.ends_with("_2__"));
        cleanup(&path);
    }

    #[test]
    fn same_value_under_different_kinds_gets_distinct_tokens() {
        let path = temp_path();
        let mut vault = match JsonVault::open(&path) {
            Ok(vault) => vault,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let scope = scope("s");
        let email = stored(&mut vault, &scope, "email", "alice@example.com");
        let person = stored(&mut vault, &scope, "person", "alice@example.com");
        assert_ne!(email.token, person.token);
        cleanup(&path);
    }

    #[test]
    fn delete_scope_persists_and_reloads() {
        let path = temp_path();
        let doomed = scope("doomed");
        let kept = scope("kept");
        let mut vault = open(&path);
        let gone = stored(&mut vault, &doomed, "email", "alice@example.com");
        let kept_mapping = stored(&mut vault, &kept, "email", "bob@example.com");
        match vault.delete_scope(&doomed) {
            Ok(()) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }

        let mut reopened = open(&path);
        assert_eq!(resolved(&reopened, &doomed, &gone.token), None);
        assert_eq!(
            resolved(&reopened, &kept, &kept_mapping.token),
            Some(kept_mapping)
        );
        assert!(
            reopened
                .state
                .mappings
                .iter()
                .all(|record| record.scope != "doomed"),
            "deleted scope still on disk"
        );
        // The deleted scope's counter is gone, so it restarts at 1.
        let reissued = stored(&mut reopened, &doomed, "email", "carol@example.com");
        assert_eq!(reissued.token, "__DO_PRIVATE_EMAIL_1__");
        cleanup(&path);
    }

    #[test]
    fn concurrent_writers_keep_every_mapping() {
        let path = temp_path();
        let scope = scope("s");
        let handles: Vec<_> = [open(&path), open(&path)]
            .into_iter()
            .zip(["a", "b"])
            .map(|(mut vault, tag)| {
                let scope = scope.clone();
                std::thread::spawn(move || {
                    for index in 0..10 {
                        stored(
                            &mut vault,
                            &scope,
                            "email",
                            &format!("{tag}{index}@example.com"),
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            match handle.join() {
                Ok(()) => {}
                Err(payload) => panic!("writer thread panicked: {payload:?}"),
            }
        }

        let reopened = open(&path);
        assert_eq!(reopened.state.mappings.len(), 20);
        let tokens: std::collections::HashSet<&str> = reopened
            .state
            .mappings
            .iter()
            .map(|record| record.mapping.token.as_str())
            .collect();
        assert_eq!(tokens.len(), 20, "tokens were reused across writers");
        cleanup(&path);
    }

    #[test]
    fn corrupt_file_is_an_error() {
        let path = temp_path();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).ok();
            }
        }
        fs::write(&path, "{not json").ok();
        assert!(
            JsonVault::open(&path).is_err(),
            "expected corrupt file error"
        );
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path();
        let mut vault = match JsonVault::open(&path) {
            Ok(vault) => vault,
            Err(error) => panic!("unexpected error: {error}"),
        };
        stored(&mut vault, &scope("s"), "email", "alice@example.com");
        let mode = match fs::metadata(&path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(mode, 0o600);
        cleanup(&path);
    }
}
