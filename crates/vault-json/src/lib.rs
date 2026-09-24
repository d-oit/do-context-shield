//! Explicit opt-in JSON-file vault for CLI-to-CLI workflows.

use do_context_shield_plugin_api::{
    Mapping, ScopeId, Vault, VaultError, is_minted_placeholder_token, mint_placeholder,
};
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
    value: u64,
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

    /// Load state from disk while the caller holds the appropriate lock.
    ///
    /// Missing files mean empty state; corrupt files are errors.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read or parsed.
    fn load_state(path: &Path) -> Result<State, VaultError> {
        if path.exists() {
            let file = File::open(path).map_err(|error| io_error(&error))?;
            serde_json::from_reader(BufReader::new(file)).map_err(|error| json_error(&error))
        } else {
            Ok(State::default())
        }
    }

    /// Read a current state snapshot while holding a shared lock.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the lock or vault file cannot be read or
    /// parsed.
    fn read_state(path: &Path) -> Result<State, VaultError> {
        let _lock = Lock::shared(path)?;
        Self::load_state(path)
    }

    /// Reload state from disk so sequential processes observe each other's
    /// inserts and deletions. Missing files mean empty state; corrupt files
    /// are errors.
    ///
    /// The caller must already hold the exclusive [`Lock`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read or parsed.
    fn reload_locked(&mut self) -> Result<(), VaultError> {
        self.state = Self::load_state(&self.path)?;
        Ok(())
    }

    /// Reserve the next counter for a scope and kind.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the persisted counter is exhausted.
    fn next_counter(&mut self, scope: &ScopeId, kind: &str) -> Result<u64, VaultError> {
        if let Some(record) = self
            .state
            .counters
            .iter_mut()
            .find(|record| record.scope == scope.0 && record.kind == kind)
        {
            record.value = record.value.checked_add(1).ok_or_else(|| {
                VaultError::Message("vault counter exhausted for this scope and kind".to_owned())
            })?;
            Ok(record.value)
        } else {
            self.state.counters.push(CounterRecord {
                scope: scope.0.clone(),
                kind: kind.to_owned(),
                value: 1,
            });
            Ok(1)
        }
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
        let file = restricted_file(&tmp)?;
        write_state(BufWriter::new(file), &self.state)?;
        fs::rename(&tmp, &self.path).map_err(|error| io_error(&error))?;
        Ok(())
    }
}

/// Serialize `state` and flush the writer, surfacing every I/O failure.
///
/// The flush is explicit on purpose: a `BufWriter` discards flush errors when
/// it drops, which would let a failed write rename a truncated temporary file
/// over a healthy vault while the caller still saw success.
fn write_state<W: io::Write>(mut writer: W, state: &State) -> Result<(), VaultError> {
    serde_json::to_writer(&mut writer, state).map_err(|error| json_error(&error))?;
    writer.flush().map_err(|error| io_error(&error))
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
        if let Some(index) = self.state.mappings.iter().position(|record| {
            record.scope == scope.0
                && record.mapping.kind == kind
                && record.mapping.original == original
        }) {
            if is_minted_placeholder_token(&self.state.mappings[index].mapping.token) {
                return Ok(self.state.mappings[index].mapping.clone());
            }
            // A vault created before entropy-bearing tokens was introduced
            // must never keep its guessable token as a live alias. Rotate the
            // mapping on first use and make the old token permanently miss.
            let next = self.next_counter(scope, kind)?;
            let token = mint_placeholder(kind, next)?;
            self.state.mappings[index].mapping.token = token;
            let mapping = self.state.mappings[index].mapping.clone();
            self.persist_locked()?;
            return Ok(mapping);
        }

        let next = self.next_counter(scope, kind)?;
        let mapping = Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token: mint_placeholder(kind, next)?,
        };
        self.state.mappings.push(MappingRecord {
            scope: scope.0.clone(),
            mapping: mapping.clone(),
        });
        self.persist_locked()?;
        Ok(mapping)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        let state = Self::read_state(&self.path)?;
        Ok(state
            .mappings
            .into_iter()
            .find(|record| {
                record.scope == scope.0
                    && record.mapping.token == token
                    && is_minted_placeholder_token(&record.mapping.token)
            })
            .map(|record| record.mapping))
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
mod tests;
