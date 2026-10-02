//! Audit event construction and scrubbing: structure only, never content.

use do_context_shield_plugin_api::{
    Action, ActionCount, AuditContext, AuditError, AuditEvent, AuditOperation, AuditOutcome,
    PlannedEntity, ScopeId,
};
use std::collections::BTreeMap;

/// A `sanitize` event with the plan's per-kind action counts.
///
/// The plan is complete whenever this is called (validation passed), including
/// on a policy block, so the counts describe the whole decision.
pub(crate) fn sanitize(
    session: &ScopeId,
    outcome: AuditOutcome,
    context: &AuditContext,
    plan: &[PlannedEntity],
) -> AuditEvent {
    let mut event = AuditEvent::new(AuditOperation::Sanitize, session, outcome);
    event.context = Some(context.clone());
    event.actions = action_counts(plan);
    event
}

/// A `restore` event with the number of placeholders that resolved.
pub(crate) fn restore(session: &ScopeId, resolved: u64) -> AuditEvent {
    let mut event = AuditEvent::new(AuditOperation::Restore, session, AuditOutcome::Ok);
    event.resolved = Some(resolved);
    event
}

/// A `forget` event.
pub(crate) fn forget(session: &ScopeId) -> AuditEvent {
    AuditEvent::new(AuditOperation::Forget, session, AuditOutcome::Ok)
}

/// Per-kind action counts, sorted by kind then action so a line is stable.
fn action_counts(plan: &[PlannedEntity]) -> Vec<ActionCount> {
    let mut counts: BTreeMap<(&str, &'static str), (Action, u64)> = BTreeMap::new();
    for planned in plan {
        let entry = counts
            .entry((planned.entity.kind.as_str(), planned.action.as_str()))
            .or_insert((planned.action, 0));
        entry.1 += 1;
    }
    counts
        .into_iter()
        .map(|((kind, _), (action, count))| ActionCount {
            kind: kind.to_owned(),
            action,
            count,
        })
        .collect()
}

/// Replace every occurrence of a sensitive value in an audit error.
pub(crate) fn scrub(error: AuditError, sensitive: &[&str]) -> AuditError {
    match error {
        AuditError::Message(text) => {
            let mut scrubbed = text;
            for value in sensitive {
                if !value.is_empty() {
                    scrubbed = scrubbed.replace(value, "[redacted]");
                }
            }
            AuditError::Message(scrubbed)
        }
    }
}
