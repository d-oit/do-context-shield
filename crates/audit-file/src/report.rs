//! Safe verification reports: categories, record indexes, and no event bytes.

use std::fmt::{self, Display};

/// A safe verification failure category for one record (or the file).
///
/// Categories are deliberately coarse: they never carry serialized event
/// values, raw JSON, paths, or parser diagnostics, so a `verify-audit` report
/// can be shown to anyone allowed to see the log's existence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyCategory {
    /// The line is not valid JSON, or an envelope whose event cannot be
    /// re-serialized.
    Malformed,
    /// The line is an object but not a conforming version-2 envelope.
    NotEnvelope,
    /// The line names an unknown format version.
    UnsupportedVersion,
    /// `sequence` is not the expected next value (gap, reorder, or reset).
    SequenceGap,
    /// `previous_hash` does not match the previous record's `record_hash`.
    PreviousHashMismatch,
    /// The record's own hash does not cover its content (modification).
    RecordHashMismatch,
    /// The file (or this record) is cut off, or contains a zero-byte line.
    Truncated,
    /// No failure was found.
    Verified,
}

impl VerifyCategory {
    /// Stable lowercase token for CLI/JSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotEnvelope => "not_envelope",
            Self::UnsupportedVersion => "unsupported_version",
            Self::SequenceGap => "sequence_gap",
            Self::PreviousHashMismatch => "previous_hash_mismatch",
            Self::RecordHashMismatch => "record_hash_mismatch",
            Self::Truncated => "truncated",
            Self::Verified => "verified",
        }
    }
}

impl Display for VerifyCategory {
    /// Emit the stable lowercase token; never any record bytes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Result of scanning an audit file (see [`crate::verify`]).
///
/// The report carries only safe metadata: a format marker, a record count, and
/// — on failure — a record index plus a [`VerifyCategory`]. Serialized events
/// never appear in it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationReport {
    /// No records (zero-byte file).
    Empty,
    /// All version-2 records verified as one continuous chain.
    Verified {
        /// Number of records in the chain.
        records: u64,
    },
    /// A legacy version-1 file (bare `AuditEvent` JSONL). Its records were
    /// recognized but **no chain guarantees apply**; this crate never rewrites
    /// or upgrades it — migration is an explicit operator action.
    Legacy {
        /// Number of legacy records recognized.
        records: u64,
    },
    /// The file names an unknown format version; verification fails closed.
    UnsupportedVersion {
        /// Record index (1-based) carrying the unknown version.
        record_index: u64,
    },
    /// The first failure found, at `record_index` (1-based; 0 for a file-level
    /// failure such as a missing final newline). Only the category is safe to
    /// report — never the underlying bytes.
    Failure {
        /// 1-based record index, or 0 for whole-file failures.
        record_index: u64,
        /// Safe failure category.
        category: VerifyCategory,
    },
}

impl VerificationReport {
    /// Whether verification found no integrity failure (legacy files count:
    /// they are recognized, not verified).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(
            self,
            Self::Empty | Self::Verified { .. } | Self::Legacy { .. }
        )
    }

    /// Format marker: `"empty"`, `"v2"`, `"legacy"`, `"unsupported_version"`,
    /// or `"failure"`. Safe for CLI/JSON output; contains no record bytes.
    #[must_use]
    pub fn format(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Verified { .. } => "v2",
            Self::Legacy { .. } => "legacy",
            Self::UnsupportedVersion { .. } => "unsupported_version",
            Self::Failure { .. } => "failure",
        }
    }

    /// Number of records the scan recognized (`None` for failures).
    #[must_use]
    pub fn records(&self) -> Option<u64> {
        match self {
            Self::Verified { records } | Self::Legacy { records } => Some(*records),
            _ => None,
        }
    }

    /// 1-based record index of the failure (0 for whole-file or success
    /// reports).
    #[must_use]
    pub fn record_index(&self) -> u64 {
        match self {
            Self::Failure { record_index, .. } | Self::UnsupportedVersion { record_index } => {
                *record_index
            }
            _ => 0,
        }
    }

    /// Safe failure category token; `None` for success reports.
    #[must_use]
    pub fn category(&self) -> Option<&'static str> {
        match self {
            Self::Failure { category, .. } => Some(category.as_str()),
            Self::UnsupportedVersion { .. } => Some(VerifyCategory::UnsupportedVersion.as_str()),
            _ => None,
        }
    }
}

impl Display for VerificationReport {
    /// Emit only format marker, record count, failing index, and category —
    /// never serialized events or file contents.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "empty audit file"),
            Self::Verified { records } => {
                write!(formatter, "v2 chain verified ({records} records)")
            }
            Self::Legacy { records } => {
                write!(formatter, "legacy v1 file ({records} records, not chained)")
            }
            Self::UnsupportedVersion { record_index } => write!(
                formatter,
                "unsupported format version at record {record_index}"
            ),
            Self::Failure {
                record_index,
                category,
            } => {
                if *record_index == 0 {
                    write!(formatter, "audit file failed verification: {category}")
                } else {
                    write!(
                        formatter,
                        "audit file failed verification at record {record_index}: {category}"
                    )
                }
            }
        }
    }
}
