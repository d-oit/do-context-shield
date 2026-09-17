//! Explicit opt-in JSON-file vault for CLI-to-CLI workflows.

use do_context_shield_plugin_api::{Mapping, ScopeId, Vault, VaultError};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter};
use std::path::PathBuf;

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

/// File-backed local vault. Use only with an access-controlled local path.
///
/// The vault file holds original values by design and is created with
/// owner-only permissions on Unix. Sequential processes share state by
/// reloading the file on every insert; concurrent writers are not supported.
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
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read or parsed.
    fn reload(&mut self) -> Result<(), VaultError> {
        if self.path.exists() {
            let file = File::open(&self.path).map_err(|error| io_error(&error))?;
            self.state = serde_json::from_reader(BufReader::new(file))
                .map_err(|error| json_error(&error))?;
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), VaultError> {
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
        // Reload so sequential CLI processes share counters and mappings.
        self.reload()?;
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
        self.persist()?;
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

    fn scope(name: &str) -> ScopeId {
        ScopeId(name.to_owned())
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
        fs::remove_file(&path).ok();
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
        fs::remove_file(&path).ok();
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
        fs::remove_file(&path).ok();
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
        fs::remove_file(&path).ok();
    }
}
