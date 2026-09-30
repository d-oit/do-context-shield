//! Explicit opt-in JSON-file vault for CLI-to-CLI workflows.

use do_context_shield_plugin_api::{Mapping, ScopeId, VaultError};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

mod vault;

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    /// Unix seconds when the record was written; `None` for records written
    /// before a TTL was configured (see [`JsonVault::with_ttl`]).
    #[serde(default)]
    created_at: Option<u64>,
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
///
/// With [`JsonVault::with_ttl`] every stored mapping carries the time it was
/// written and stops resolving once it is older than the TTL:
///
/// - reads (`resolve`, `resolve_many`) hide an expired mapping;
/// - locked writes and [`Vault::expire`] stamp undated records and purge
///   expired ones from the file, so a mapping is never deleted before its TTL
///   elapsed and a read never has to write;
/// - counters are never reset, so a token that expired is never reissued for
///   a different value;
/// - records written before a TTL was configured have no timestamp; they keep
///   resolving until the first locked write or `expire` stamps them, after
///   which the TTL applies normally. `forget` remains the immediate eraser.
pub struct JsonVault {
    path: PathBuf,
    state: State,
    format: Format,
    /// Lifetime after which a stored mapping stops resolving; `None` keeps
    /// mappings until the scope is forgotten or the file is deleted.
    ttl: Option<Duration>,
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

    /// Bound how long stored mappings stay resolvable.
    ///
    /// See the type-level notes for the exact semantics: reads hide expired
    /// mappings, locked writes and [`Vault::expire`] purge them, counters are
    /// never reset, and records written before the TTL was configured are
    /// stamped at the next locked write instead of being purged on sight.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
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
            ttl: None,
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
            ttl: None,
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

fn io_error(error: &io::Error) -> VaultError {
    VaultError::Message(error.to_string())
}

/// Unix seconds, or `None` when the clock reads before the epoch.
///
/// A missing clock reading never expires or stamps anything: without an age
/// there is nothing to compare, and purging on a broken clock could destroy
/// mappings that are still wanted.
fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn json_error(error: &serde_json::Error) -> VaultError {
    VaultError::Message(error.to_string())
}

#[cfg(test)]
mod tests;
