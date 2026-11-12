//! Shared detector-span and policy-plan validation.

use crate::PipelineError;
use do_context_shield_plugin_api::{
    Action, DetectorError, Entity, PlannedEntity, PolicyError, is_secret_kind, resolve_overlaps,
};

/// Validate detector output before the judge and policy see it.
///
/// Every entity must carry a non-empty kind that does not contain its matched
/// value, and a confidence in `0..=1`. Every span must be non-empty, fall on
/// UTF-8 character boundaries, stay within the input, and carry the value the
/// input actually holds at that span. [`resolve_overlaps`] applies
/// longest-span-wins, with equal lengths keeping the detector's order.
///
/// # Errors
///
/// Returns [`PipelineError::Detector`] when an entity span, kind, or
/// confidence violates the detector contract.
pub(super) fn validate_spans(
    input: &str,
    entities: &[Entity],
) -> Result<Vec<Entity>, PipelineError> {
    let mut validated = Vec::with_capacity(entities.len());
    for entity in entities {
        if !input.is_char_boundary(entity.start) || !input.is_char_boundary(entity.end) {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} is not on character boundaries",
                entity.start, entity.end
            ))));
        }
        if entity.end > input.len() || entity.start > entity.end {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} is out of bounds for input of length {}",
                entity.start,
                entity.end,
                input.len()
            ))));
        }
        if entity.start == entity.end {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} is empty",
                entity.start, entity.end
            ))));
        }
        if input.get(entity.start..entity.end) != Some(entity.value.as_str()) {
            return Err(PipelineError::Detector(DetectorError::Message(
                "entity value does not match the input at the declared span".to_owned(),
            )));
        }
        if entity.kind.trim().is_empty() {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} carries an empty kind",
                entity.start, entity.end
            ))));
        }
        if entity.kind.contains(&entity.value) {
            return Err(PipelineError::Detector(DetectorError::Message(
                "entity kind contains the matched value".to_owned(),
            )));
        }
        if !(0.0..=1.0).contains(&entity.confidence) {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity confidence {} for kind `{}` is outside 0..=1",
                entity.confidence, entity.kind
            ))));
        }
        validated.push(entity.clone());
    }

    Ok(resolve_overlaps(validated))
}

/// Validate the policy plan against the entity list it was asked to decide.
///
/// The policy contract is exactly one decision per detected entity, for the
/// same kind, span, and value; a plan that drops an entity or rewrites its
/// value would let its raw value pass through undecided. A secret-kind entity
/// must be redacted (or blocked), never kept or pseudonymized into a reversible
/// vault mapping.
///
/// # Errors
///
/// Returns [`PipelineError::Policy`] when the plan length differs from the
/// entity list, a decision substitutes another kind, span, or value, or a
/// secret-kind entity carries a reversible action.
pub(super) fn validate_plan(
    entities: &[Entity],
    plan: &[PlannedEntity],
) -> Result<(), PipelineError> {
    if plan.len() != entities.len() {
        return Err(PipelineError::Policy(PolicyError::Message(format!(
            "policy returned {} decisions for {} entities",
            plan.len(),
            entities.len()
        ))));
    }
    for (planned, entity) in plan.iter().zip(entities) {
        if planned.entity.kind != entity.kind
            || planned.entity.start != entity.start
            || planned.entity.end != entity.end
            || planned.entity.value != entity.value
        {
            return Err(PipelineError::Policy(PolicyError::Message(format!(
                "policy decision does not match the detected entity at {}..{}: kind, span, or value differs",
                entity.start, entity.end
            ))));
        }
        if is_secret_kind(&entity.kind) && !matches!(planned.action, Action::Redact | Action::Block)
        {
            return Err(PipelineError::Policy(PolicyError::Message(format!(
                "secret-kind entity must be redacted: {}",
                entity.kind
            ))));
        }
    }
    Ok(())
}
