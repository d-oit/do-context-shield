//! Versioned audit record envelopes and the SHA-256 hash chain.
//!
//! The chain is **tamper-evident, not tamper-proof**: it detects a modification,
//! deletion, truncation, or reordering by any writer that cannot (or does not)
//! rewrite the whole file, but an attacker who can rewrite the entire file as
//! the same user can rebuild a consistent chain. The chain adds no event
//! content: envelopes carry only sequence/hash metadata around the existing
//! structure-only [`AuditEvent`].
//!
//! # On-disk format (version 2, chained)
//!
//! One JSON object per line (JSONL), field names in this exact order:
//!
//! ```text
//! {"v":2,"sequence":1,"previous_hash":"<64 lowercase hex>","record_hash":"<64 lowercase hex>","event":{...}}
//! ```
//!
//! The first record of a chain uses 64 `0` characters as `previous_hash`.
//! `record_hash` is lowercase hex SHA-256 over `previous_hash || sequence_be8 ||
//! event_bytes`, where `event_bytes` is the exact byte serialization of the
//! `event` value. Verification recomputes those bytes through the same
//! [`serde_json`] value conversion, so the comparison is deterministic: object
//! keys are emitted in sorted order in both directions (the workspace does not
//! enable `serde_json/preserve_order`).
//!
//! # Format versions and migration
//!
//! - **Version 1 (legacy)**: a bare [`AuditEvent`] per line, written by earlier
//!   releases. Legacy files are detected by [`verify`] as
//!   [`VerificationReport::Legacy`] and are **never rewritten, upgraded, or
//!   truncated** by any API in this crate; the sink refuses to append to them
//!   (they have no chain to extend), so an operator migrates explicitly by
//!   starting a new destination file and preserving the old one.
//! - **Version 2 (chained)**: the envelope format above.
//! - A line carrying another `v` number is reported as
//!   [`VerificationReport::UnsupportedVersion`] (fail closed), not guessed at.

use crate::report::{VerificationReport, VerifyCategory};
use do_context_shield_plugin_api::AuditEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// On-disk format version written by this crate.
pub const FORMAT_VERSION: u32 = 2;

/// Length of a lowercase hex SHA-256 digest string.
const HASH_HEX_LEN: usize = 64;

/// Genesis `previous_hash`: 64 zero hex characters.
pub(crate) const GENESIS_PREVIOUS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// A versioned record envelope: chain metadata plus the existing event.
///
/// The envelope introduces no event content; it only adds `sequence`,
/// `previous_hash`, and `record_hash` around the structure-only [`AuditEvent`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// On-disk format version; [`FORMAT_VERSION`] when written by this crate.
    pub v: u32,
    /// 1-based position of this record within its chain.
    pub sequence: u64,
    /// Lowercase hex SHA-256 of the previous record (64 zeros for the first).
    pub previous_hash: String,
    /// Lowercase hex SHA-256 chaining `previous_hash`, `sequence`, and `event`.
    pub record_hash: String,
    /// The structure-only audit event.
    pub event: AuditEvent,
}

impl Envelope {
    /// Encode this envelope for append: canonical JSON plus one newline.
    ///
    /// The `event` bytes hashed here are byte-identical to the bytes the
    /// verifier re-serializes during [`verify`], which keeps `record_hash`
    /// reproducible across writer and reader.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn encode_line(&self) -> Result<Vec<u8>, ()> {
        let mut line = serde_json::to_vec(self).map_err(|_| ())?;
        line.push(b'\n');
        Ok(line)
    }
}

/// The exact serialization of an `event` value.
///
/// Uses a JSON value conversion so the writer hashes the same byte sequence
/// the verifier recomputes, regardless of how [`serde_json`] orders object
/// keys (sorted in this workspace).
pub(crate) fn event_bytes(event: &AuditEvent) -> Result<Vec<u8>, ()> {
    let value = serde_json::to_value(event).map_err(|_| ())?;
    serde_json::to_vec(&value).map_err(|_| ())
}

/// Compute `record_hash` over `previous_hash`, `sequence`, and `event_bytes`.
#[must_use]
pub fn compute_record_hash(previous_hash: &str, sequence: u64, event_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(event_bytes);
    hex(&hasher.finalize())
}

/// Whether `text` is exactly 64 lowercase hexadecimal characters.
#[must_use]
pub fn is_hex_hash(text: &str) -> bool {
    text.len() == HASH_HEX_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Chain tail extracted by a successful [`verify`] scan: the number of
/// records and the last `record_hash`, needed to append the next envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChainTail {
    /// Records in the chain (0 for an empty file).
    pub(crate) records: u64,
    /// `record_hash` of the last record, or the genesis value when empty.
    pub(crate) previous_hash: String,
}

/// Verify the full chain of a complete audit file's bytes.
///
/// Checks, fail-closed in scan order: final newline, per-line JSON shape,
/// format version, sequence continuity from 1, `previous_hash` linkage, and
/// each record's own `record_hash`. The first failure is reported as a safe
/// category plus record index; serialized event data never appears in the
/// report.
///
/// Legacy (version-1) files scan as [`VerificationReport::Legacy`] without
/// chain claims and are never modified. Empty files scan as
/// [`VerificationReport::Empty`].
#[must_use]
pub fn verify(contents: &[u8]) -> VerificationReport {
    match scan(contents) {
        Ok(_) if contents.is_empty() => VerificationReport::Empty,
        Ok(tail) if tail.records == 0 => VerificationReport::Legacy {
            records: count_legacy_records(contents),
        },
        Ok(tail) => VerificationReport::Verified {
            records: tail.records,
        },
        Err(VerificationReport::Failure {
            record_index,
            category: VerifyCategory::UnsupportedVersion,
        }) => VerificationReport::UnsupportedVersion { record_index },
        Err(report) => report,
    }
}

/// Scan a file's bytes and, on success, return its [`ChainTail`].
///
/// A tail with `records == 0` means the file parsed as legacy (bare
/// [`AuditEvent`] lines) or is empty; callers that only accept chained files
/// must treat that as legacy and refuse to append.
pub(crate) fn scan(contents: &[u8]) -> Result<ChainTail, VerificationReport> {
    if contents.is_empty() {
        return Ok(ChainTail {
            records: 0,
            previous_hash: GENESIS_PREVIOUS.to_owned(),
        });
    }
    if contents.last() != Some(&b'\n') {
        return Err(VerificationReport::Failure {
            record_index: 0,
            category: VerifyCategory::Truncated,
        });
    }

    let mut previous_hash = GENESIS_PREVIOUS.to_owned();
    let mut expected_sequence: u64 = 1;
    let mut chain_count: u64 = 0;
    let mut legacy = false;
    // `split_terminator` drops the trailing empty segment after the final
    // newline; any remaining empty segment is a zero-byte line mid-file.
    let mut segments: Vec<&[u8]> = contents.split(|byte| *byte == b'\n').collect();
    if segments.last().is_some_and(|segment| segment.is_empty()) {
        segments.pop();
    }
    for (position, line) in segments.into_iter().enumerate() {
        let record_index = u64::try_from(position).unwrap_or(u64::MAX) + 1;
        if line.is_empty() {
            return Err(VerificationReport::Failure {
                record_index,
                category: VerifyCategory::Truncated,
            });
        }
        if line.starts_with(b"{\"v\":") {
            if legacy {
                // Mixed legacy and chained records: refuse to guess.
                return Err(VerificationReport::Failure {
                    record_index,
                    category: VerifyCategory::NotEnvelope,
                });
            }
            match verify_envelope_line(line, record_index, expected_sequence, &previous_hash) {
                Ok(hash) => {
                    previous_hash = hash;
                    chain_count += 1;
                    expected_sequence = match expected_sequence.checked_add(1) {
                        Some(next) => next,
                        None => {
                            return Err(VerificationReport::Failure {
                                record_index,
                                category: VerifyCategory::SequenceGap,
                            });
                        }
                    };
                }
                Err((category, failed_index)) => {
                    return Err(VerificationReport::Failure {
                        record_index: failed_index,
                        category,
                    });
                }
            }
        } else if chain_count > 0 {
            // A chained file must not fall back to a bare event line; report
            // whether the line is JSON-shaped at all.
            return Err(VerificationReport::Failure {
                record_index,
                category: if line.first() == Some(&b'{') {
                    VerifyCategory::NotEnvelope
                } else {
                    VerifyCategory::Malformed
                },
            });
        } else {
            if serde_json::from_slice::<AuditEvent>(line).is_err() {
                return Err(VerificationReport::Failure {
                    record_index,
                    category: if line.first() == Some(&b'{') {
                        VerifyCategory::NotEnvelope
                    } else {
                        VerifyCategory::Malformed
                    },
                });
            }
            legacy = true;
        }
    }

    Ok(ChainTail {
        records: chain_count,
        previous_hash,
    })
}

/// Count the lines of a legacy file (only called after [`scan`] accepted it).
#[allow(clippy::naive_bytecount)] // one counting pass; no bytecount dependency
fn count_legacy_records(contents: &[u8]) -> u64 {
    // Every line was accepted by `scan`, so each final newline is one record.
    contents
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Verify one chained line; on success return its `record_hash`.
///
/// Returns `(category, record_index)` on the first failure. `record_index` is
/// the scan position, which can exceed `expected_sequence` when earlier
/// records are missing.
fn verify_envelope_line(
    line: &[u8],
    record_index: u64,
    expected_sequence: u64,
    expected_previous: &str,
) -> Result<String, (VerifyCategory, u64)> {
    let envelope: Envelope = serde_json::from_slice(line).map_err(|_| {
        // Distinguish an unknown version number from a malformed envelope.
        if probe_version(line) == Some(FORMAT_VERSION) {
            (VerifyCategory::NotEnvelope, record_index)
        } else {
            (VerifyCategory::UnsupportedVersion, record_index)
        }
    })?;
    if envelope.v != FORMAT_VERSION {
        return Err((VerifyCategory::UnsupportedVersion, record_index));
    }
    if envelope.sequence != expected_sequence {
        return Err((VerifyCategory::SequenceGap, record_index));
    }
    if envelope.previous_hash != expected_previous {
        return Err((VerifyCategory::PreviousHashMismatch, record_index));
    }
    if !is_hex_hash(&envelope.record_hash) {
        return Err((VerifyCategory::RecordHashMismatch, record_index));
    }
    // Recompute the event bytes with the same conversion the writer uses; the
    // comparison is deterministic and never leaves this function.
    let bytes =
        event_bytes(&envelope.event).map_err(|()| (VerifyCategory::Malformed, record_index))?;
    let recomputed = compute_record_hash(&envelope.previous_hash, envelope.sequence, &bytes);
    if recomputed != envelope.record_hash {
        return Err((VerifyCategory::RecordHashMismatch, record_index));
    }
    Ok(recomputed)
}

/// Read the `v` value of a `{"v":...` line without full validation.
fn probe_version(line: &[u8]) -> Option<u32> {
    let probe: serde_json::Value = serde_json::from_slice(line).ok()?;
    probe.get("v")?.as_u64()?.try_into().ok()
}
/// Validate the final record of an existing chain so the next envelope can
/// extend it.
///
/// Whole-file linkage is validated once at open and by [`verify`]; an append
/// re-reads only the tail under the file lock, so the check here is the tail
/// record's shape and its own hash. A malformed tail fails closed rather than
/// writing a record that breaks the chain.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn append_point(last_line: &[u8]) -> Result<ChainTail, VerificationReport> {
    let envelope: Envelope =
        serde_json::from_slice(last_line).map_err(|_| VerificationReport::Failure {
            record_index: 0,
            category: if probe_version(last_line) == Some(FORMAT_VERSION) {
                VerifyCategory::NotEnvelope
            } else {
                VerifyCategory::UnsupportedVersion
            },
        })?;
    if envelope.v != FORMAT_VERSION {
        return Err(VerificationReport::Failure {
            record_index: 0,
            category: VerifyCategory::UnsupportedVersion,
        });
    }
    if !is_hex_hash(&envelope.previous_hash) || !is_hex_hash(&envelope.record_hash) {
        return Err(VerificationReport::Failure {
            record_index: 0,
            category: VerifyCategory::RecordHashMismatch,
        });
    }
    let bytes = event_bytes(&envelope.event).map_err(|()| VerificationReport::Failure {
        record_index: 0,
        category: VerifyCategory::Malformed,
    })?;
    if compute_record_hash(&envelope.previous_hash, envelope.sequence, &bytes)
        != envelope.record_hash
    {
        return Err(VerificationReport::Failure {
            record_index: 0,
            category: VerifyCategory::RecordHashMismatch,
        });
    }
    Ok(ChainTail {
        records: envelope.sequence,
        previous_hash: envelope.record_hash,
    })
}

#[cfg(test)]
mod tests;
