//! Audit events for the privacy boundary.
//!
//! An audit sink records **structure, never content**: which operation ran,
//! in which session, with which outcome, and how many entities of which kind
//! received which action. Original values, minted tokens, and free-form
//! `purpose` text never appear, so an audit file can be handed to an operator
//! (or a compliance tool) without recreating the exposure the boundary exists
//! to prevent.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Action, DataCategory, ProcessingContext, RecipientClass, ScopeId};

/// The operation an audit event describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    /// `sanitize` produced text (or refused to).
    Sanitize,
    /// `restore` resolved placeholders.
    Restore,
    /// `forget` deleted a session's mappings.
    Forget,
}

/// How an audited operation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The operation completed.
    Ok,
    /// The operation was refused before any transformation (a policy block).
    Blocked,
}

/// The enforcement context of an event, without the free-form `purpose`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditContext {
    /// Trust classification of the recipient.
    pub recipient: RecipientClass,
    /// Highest data category present in the input.
    pub data_category: DataCategory,
    /// Declared jurisdiction, when one was supplied.
    pub jurisdiction: Option<String>,
}

impl From<&ProcessingContext> for AuditContext {
    fn from(context: &ProcessingContext) -> Self {
        Self {
            recipient: context.recipient,
            data_category: context.data_category,
            jurisdiction: context.jurisdiction.clone(),
        }
    }
}

/// How many entities of one kind received one action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCount {
    /// Entity kind, e.g. `email`.
    pub kind: String,
    /// Action the plan assigned to every counted entity of this kind.
    pub action: Action,
    /// Number of entities.
    pub count: u64,
}

/// One audit record. Every field is structure: no value, token, or purpose
/// text is representable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix seconds when the event was created (0 when the clock reads before
    /// the epoch).
    pub time_unix: u64,
    /// Operation that ran.
    pub operation: AuditOperation,
    /// Session scope the operation ran in.
    pub session: String,
    /// Outcome of the operation.
    pub outcome: AuditOutcome,
    /// Enforcement context, when the operation had one (`sanitize` only).
    pub context: Option<AuditContext>,
    /// Per-kind action counts (`sanitize` only; empty otherwise).
    pub actions: Vec<ActionCount>,
    /// Placeholders resolved (`restore` only).
    pub resolved: Option<u64>,
}

impl AuditEvent {
    /// Start an event for `operation` in `session`, stamped with the current
    /// time; the caller fills `context`, `actions`, or `resolved`.
    #[must_use]
    pub fn new(operation: AuditOperation, session: &ScopeId, outcome: AuditOutcome) -> Self {
        Self {
            time_unix: unix_now(),
            operation,
            session: session.0.clone(),
            outcome,
            context: None,
            actions: Vec::new(),
            resolved: None,
        }
    }
}

/// Unix seconds, 0 when the clock reads before the epoch.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Audit failures.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Audit sink failure.
    ///
    /// The text is surfaced to callers; it must not embed raw input or
    /// original values. The pipeline scrubs the values it knows, but the
    /// contract belongs to the plugin.
    #[error("audit error: {0}")]
    Message(String),
}

/// Record boundary operations.
///
/// A configured sink is a hard requirement: when [`AuditSink::record`] fails,
/// the pipeline fails the call instead of returning text, so a silently
/// missing audit trail cannot happen. Implementations receive structure-only
/// [`AuditEvent`]s; they must not add content of their own.
pub trait AuditSink: Send + Sync {
    /// Record one event.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the event cannot be recorded.
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError>;
}
