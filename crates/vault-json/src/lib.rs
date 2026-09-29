//! Explicit opt-in JSON-file vault for CLI-to-CLI workflows.

use do_context_shield_plugin_api::{
    Mapping, ScopeId, Vault, VaultError, is_minted_placeholder_token, mint_placeholder,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};

mod encrypted;

pub use encrypted::VaultKey;

/// How vault state is stored on disk.
enum Format {
    /// Plain JSON state, the format vaults had before at-rest encryption.
    Plaintext,
    /// XChaCha20-Poly1305 envelope; original values never touch the disk in
    /// the clear.
    Encrypted(VaultKey),
}

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
/// owner-only permissions on Unix. With a [`VaultKey`] the state is encrypted
/// at rest (XChaCha20-Poly1305) and a file that is not in the expected format
/// fails closed instead of being silently reinterpreted. Sequential processes
/// share state by reloading the file on every insert; concurrent writers are
/// serialized through an advisory lock on `<path>.lock`.
pub struct JsonVault {
    path: PathBuf,
    state: State,
    format: Format,
}

impl JsonVault {
    /// Open or create a plaintext JSON vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read, parsed, or
    /// created, or when the file is an encrypted envelope (open it with
    /// [`JsonVault::open_encrypted`] instead).
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        Self::open_with_format(path.into(), Format::Plaintext)
    }

    /// Open or create a vault whose state is encrypted at rest with `key`.
    ///
    /// A missing file starts empty and is written encrypted on the first save.
    /// An existing plaintext file is rejected; migrate it with
    /// [`JsonVault::encrypt_in_place`] first, so a key cannot silently rewrite
    /// a vault whose backup or plaintext copy the operator still expects.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the file cannot be read or decrypted, or
    /// when it is not in the encrypted format.
    pub fn open_encrypted(path: impl Into<PathBuf>, key: VaultKey) -> Result<Self, VaultError> {
        Self::open_with_format(path.into(), Format::Encrypted(key))
    }

    /// Open a vault in plaintext, or encrypted with `key_file` when it is set.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the key file cannot be read or is accessible
    /// beyond its owner, the vault file cannot be read or decrypted, or the
    /// file is in the other format than the key selects.
    pub fn open_with_key_file(
        path: impl Into<PathBuf>,
        key_file: Option<&Path>,
    ) -> Result<Self, VaultError> {
        match key_file {
            Some(key_file) => Self::open_encrypted(path, VaultKey::from_file(key_file)?),
            None => Self::open(path),
        }
    }

    /// Rewrite an existing plaintext vault file in the encrypted format.
    ///
    /// The rewrite goes through the same temporary-file-and-rename path as a
    /// normal save, so a failure cannot corrupt the existing vault. An
    /// already-encrypted file is left untouched.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the file is missing, unreadable, already
    /// encrypted, or not plaintext vault state.
    pub fn encrypt_in_place(path: impl Into<PathBuf>, key: VaultKey) -> Result<(), VaultError> {
        let path = path.into();
        let _lock = Lock::exclusive(&path)?;
        if !path.exists() {
            return Err(VaultError::Message(format!(
                "vault file `{}` does not exist",
                path.display()
            )));
        }
        let bytes = fs::read(&path).map_err(|error| io_error(&error))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| json_error(&error))?;
        if encrypted::is_envelope(&value) {
            return Err(VaultError::Message(format!(
                "vault file `{}` is already encrypted",
                path.display()
            )));
        }
        let state: State = serde_json::from_value(value).map_err(|error| json_error(&error))?;
        Self {
            path,
            state,
            format: Format::Encrypted(key),
        }
        .persist_locked()
    }

    /// Open a vault in `format`, loading whatever state the file holds.
    fn open_with_format(path: PathBuf, format: Format) -> Result<Self, VaultError> {
        let state = {
            let _lock = Lock::shared(&path)?;
            Self::load_state(&path, &format)?
        };
        if path.exists() {
            restrict_permissions(&path)?;
        }
        Ok(Self {
            path,
            state,
            format,
        })
    }

    /// Load state from disk while the caller holds the appropriate lock.
    ///
    /// Missing files mean empty state; corrupt files and files in the other
    /// format are errors.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read, cannot be
    /// decrypted with the configured key, or is not in the expected format.
    fn load_state(path: &Path, format: &Format) -> Result<State, VaultError> {
        if !path.exists() {
            return Ok(State::default());
        }
        let bytes = fs::read(path).map_err(|error| io_error(&error))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| json_error(&error))?;
        match format {
            Format::Plaintext => {
                if encrypted::is_envelope(&value) {
                    return Err(VaultError::Message(format!(
                        "vault file `{}` is encrypted; provide the vault key (`--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`)",
                        path.display()
                    )));
                }
                serde_json::from_value(value).map_err(|error| json_error(&error))
            }
            Format::Encrypted(key) => {
                if !encrypted::is_envelope(&value) {
                    return Err(VaultError::Message(format!(
                        "vault file `{}` is not encrypted; migrate it with `do-context-shield encrypt-vault --vault-file <path> --vault-key-file <path>`",
                        path.display()
                    )));
                }
                let plaintext = encrypted::decrypt(value, key)?;
                serde_json::from_slice(&plaintext).map_err(|error| json_error(&error))
            }
        }
    }

    /// Read a current state snapshot while holding a shared lock.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the lock cannot be taken or the vault file
    /// cannot be read, decrypted, or parsed.
    fn read_state(path: &Path, format: &Format) -> Result<State, VaultError> {
        let _lock = Lock::shared(path)?;
        Self::load_state(path, format)
    }

    /// Reload state from disk so sequential processes observe each other's
    /// inserts and deletions. Missing files mean empty state; corrupt files
    /// are errors.
    ///
    /// The caller must already hold the exclusive [`Lock`].
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read, decrypted,
    /// or parsed.
    fn reload_locked(&mut self) -> Result<(), VaultError> {
        self.state = Self::load_state(&self.path, &self.format)?;
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
        let state_json = serde_json::to_vec(&self.state).map_err(|error| json_error(&error))?;
        let bytes = match &self.format {
            Format::Plaintext => state_json,
            Format::Encrypted(key) => encrypted::encrypt(&state_json, key)?,
        };
        let tmp = self.path.with_extension("json.tmp");
        let file = restricted_file(&tmp)?;
        write_bytes(BufWriter::new(file), &bytes)?;
        fs::rename(&tmp, &self.path).map_err(|error| io_error(&error))?;
        Ok(())
    }
}

/// Write `bytes` and flush the writer, surfacing every I/O failure.
///
/// The flush is explicit on purpose: a `BufWriter` discards flush errors when
/// it drops, which would let a failed write rename a truncated temporary file
/// over a healthy vault while the caller still saw success.
fn write_bytes<W: io::Write>(mut writer: W, bytes: &[u8]) -> Result<(), VaultError> {
    writer.write_all(bytes).map_err(|error| io_error(&error))?;
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
        let state = Self::read_state(&self.path, &self.format)?;
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
