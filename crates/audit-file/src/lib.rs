//! Explicit opt-in, owner-private append-only JSONL audit sink with a
//! tamper-evident hash chain.
//!
//! Every record is a versioned envelope around the existing structure-only
//! [`AuditEvent`] schema:
//!
//! ```text
//! {"v":2,"sequence":1,"previous_hash":"<64 hex>","record_hash":"<64 hex>","event":{...}}
//! ```
//!
//! `record_hash` is SHA-256 over the previous hash, the sequence number, and
//! the canonical event bytes, so a modified, deleted, truncated, or reordered
//! record fails verification. The chain is **tamper-evident, not
//! tamper-proof**: an attacker who can rewrite the whole file as the same user
//! can rebuild it. It adds no event content — an audit record still cannot
//! represent originals, minted tokens, vault mappings, or free-form purpose
//! text.
//!
//! Retention and rotation are opt-in through [`Retention`]: the default keeps
//! the historical unbounded append behavior, and a configured bound rotates
//! the current file to `<name>.1` (replacing a previous rotation) and starts a
//! fresh chain. Legacy (version-1, bare `AuditEvent` JSONL) files are
//! recognized and **never rewritten, upgraded, or truncated**; the sink
//! refuses to append to them, so migration is an explicit operator action.
//!
//! Unix uses strict descriptor, ownership, permission, link, and locking
//! checks. Opt-in logging is explicitly unavailable on non-Unix platforms;
//! unaudited workflows remain available there.

use do_context_shield_plugin_api::{AuditError, AuditEvent, AuditSink};
use std::path::Path;

mod chain;
mod report;
#[cfg(test)]
mod tests;
#[cfg(unix)]
mod unix;

pub use chain::{Envelope, FORMAT_VERSION, compute_record_hash, is_hex_hash, verify};
pub use report::{VerificationReport, VerifyCategory};

#[cfg(unix)]
use std::path::PathBuf;

/// Opt-in retention bounds for the audit destination.
///
/// Both bounds are `None` by default: the sink then appends without limit and
/// never rotates or deletes, matching earlier releases. When a bound is set
/// and the next record would exceed it, the current file is renamed to
/// `<name>.1` (replacing the previous rotation file) and a new chain starts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Retention {
    /// Maximum records in the current file before rotating.
    pub max_records: Option<u64>,
    /// Maximum bytes in the current file before rotating.
    pub max_bytes: Option<u64>,
}

impl Retention {
    /// The historical behavior: no bound, no rotation, no deletion.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            max_records: None,
            max_bytes: None,
        }
    }

    /// Drop zero bounds: `Some(0)` cannot hold even one record, so it is
    /// treated as "unset" rather than rotating on every write.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn sanitized(self) -> Self {
        Self {
            max_records: self.max_records.filter(|max| *max > 0),
            max_bytes: self.max_bytes.filter(|max| *max > 0),
        }
    }
}

/// A local append-only, hash-chained audit file, reopened and revalidated for
/// every event.
///
/// The file is created immediately by [`FileAuditSink::open`], with requested
/// mode `0600`. Existing files are rejected rather than chmodded when their
/// owner or permissions do not satisfy the Unix security contract, and the
/// whole chain is verified before any append is accepted. Each record is
/// serialized from the existing event type into a versioned envelope,
/// newline-terminated, flushed, and synced before success.
#[cfg(unix)]
pub struct FileAuditSink {
    path: PathBuf,
    identity: unix::FileIdentity,
    retention: Retention,
}

/// Non-Unix placeholder type; its operations return the explicit unsupported
/// error rather than weakening filesystem guarantees.
#[cfg(not(unix))]
pub struct FileAuditSink {}

impl FileAuditSink {
    /// Open and validate the explicitly configured destination.
    ///
    /// The parent directory must already exist. Relative paths are anchored to
    /// the process working directory at startup. The destination must be an
    /// owner-only, single-link regular file owned by the effective user; an
    /// existing file is never chmodded or truncated.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the path has no file name, the parent is
    /// missing or inaccessible, Unix ownership/permissions/type/link checks
    /// fail, the destination changes during validation, the existing chain
    /// fails verification (including a modified, deleted, truncated, or
    /// reordered record), the file is a legacy v1 log, or Unix filesystem
    /// guarantees are unavailable. Diagnostics carry fixed labels and the
    /// safe verification category only: never a path, event value, or record
    /// bytes.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        Self::open_with(path, Retention::unbounded())
    }

    /// Open with explicit retention bounds; see [`Retention`].
    ///
    /// # Errors
    ///
    /// Same as [`FileAuditSink::open`].
    pub fn open_with(path: &Path, retention: Retention) -> Result<Self, AuditError> {
        #[cfg(unix)]
        {
            let (path, identity, _tail) = unix::open(path)?;
            Ok(Self {
                path,
                identity,
                retention: retention.sanitized(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (path, retention);
            Err(AuditError::Message(
                "file audit logging requires Unix filesystem guarantees".to_owned(),
            ))
        }
    }
}

impl AuditSink for FileAuditSink {
    /// Append one existing structure-only event as the next chained envelope
    /// and sync it before success.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the destination cannot be reopened,
    /// revalidated, locked, extended from a valid tail, rotated, appended,
    /// flushed, or synced. Diagnostics contain only fixed operation labels,
    /// error kinds, and safe verification categories; they never include
    /// paths, event values, serialized records, or parser source text.
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        #[cfg(unix)]
        {
            let identity = unix::record(&self.path, self.identity, self.retention, event)?;
            self.identity = identity;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = (self, event);
            Err(AuditError::Message(
                "file audit logging requires Unix filesystem guarantees".to_owned(),
            ))
        }
    }
}

/// Verify an audit file's integrity chain.
///
/// The report carries only a format marker, a record count, and — on failure —
/// a 1-based record index plus a safe [`VerifyCategory`]. It never contains
/// serialized events, raw JSON, paths, or parser diagnostics.
///
/// # Errors
///
/// Returns [`AuditError`] when the file cannot be read, or when filesystem
/// guarantees are unavailable on this platform.
pub fn verify_file(path: &Path) -> Result<VerificationReport, AuditError> {
    #[cfg(unix)]
    {
        let contents = std::fs::read(path).map_err(|error| {
            AuditError::Message(format!("audit verify read failed ({:?})", error.kind()))
        })?;
        Ok(verify(&contents))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(AuditError::Message(
            "audit verification requires Unix filesystem guarantees".to_owned(),
        ))
    }
}
