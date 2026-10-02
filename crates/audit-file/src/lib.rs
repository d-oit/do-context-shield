//! Explicit opt-in, owner-private append-only JSONL audit sink.
//!
//! The sink serializes the existing [`AuditEvent`] schema directly. The event
//! retains its opaque session identifier and structural operation/context
//! metadata; it cannot represent originals, minted tokens, vault mappings, or
//! free-form purpose text. Retention and deletion remain operator-controlled:
//! this implementation never rotates, truncates, rewrites, or deletes records.
//! It is intended for an access-controlled local directory, not as a
//! tamper-proof ledger or protection from a malicious process running as the
//! same user.
//!
//! Unix uses strict descriptor, ownership, permission, link, and locking
//! checks. Opt-in logging is explicitly unavailable on non-Unix platforms;
//! unaudited workflows remain available there.

use do_context_shield_plugin_api::{AuditError, AuditEvent, AuditSink};
use std::path::Path;

#[cfg(test)]
mod tests;
#[cfg(unix)]
mod unix;

#[cfg(unix)]
use std::path::PathBuf;

/// A local append-only audit file, reopened and revalidated for every event.
///
/// The file is created immediately by [`FileAuditSink::open`], with requested
/// mode `0600`. Existing files are rejected rather than chmodded when their
/// owner or permissions do not satisfy the Unix security contract. Each record
/// is serialized from the existing event type, newline-terminated, flushed,
/// and synced before success. Operators control retention; the sink performs
/// no rotation or deletion.
#[cfg(unix)]
pub struct FileAuditSink {
    path: PathBuf,
    identity: unix::FileIdentity,
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
    /// existing file is never chmodded or truncated. A nonempty file must be
    /// newline-terminated JSONL whose first record deserializes as the existing
    /// [`AuditEvent`] schema.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the path has no file name, the parent is
    /// missing or inaccessible, Unix ownership/permissions/type/link checks
    /// fail, the destination changes during validation, the existing JSONL
    /// boundary is malformed, or Unix filesystem guarantees are unavailable.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        #[cfg(unix)]
        {
            let (path, identity) = unix::open(path)?;
            Ok(Self { path, identity })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(AuditError::Message(
                "file audit logging requires Unix filesystem guarantees".to_owned(),
            ))
        }
    }
}

impl AuditSink for FileAuditSink {
    /// Append one existing structure-only event and sync it before success.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the destination cannot be reopened,
    /// revalidated, locked, appended, flushed, or synced. Diagnostics contain
    /// only fixed operation labels and error kinds; they never include paths,
    /// event values, serialized records, or parser source text.
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        #[cfg(unix)]
        {
            unix::record(&self.path, self.identity, event)
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
