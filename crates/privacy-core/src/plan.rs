//! Plan postconditions on the transformer's returned text.

use do_context_shield_plugin_api::{Action, PlannedEntity, TransformError};

/// Validate the transformed text against the plan it was produced from.
///
/// A `Redact` or `Pseudonymize` decision promises that the raw value is gone
/// from the output. Detection is boundary- and width-based, so a second copy
/// of the same value can sit just outside every detectable span — glued to a
/// word character, split across a line break, past a token's declared width.
/// Replacing only the detected span would then emit the original value as
/// "sanitized" text. The process transformer already rejects its own output on
/// this rule; this check applies it centrally, so the promise holds for every
/// transformer, built-in or process.
///
/// A `Keep` on *another* entity carrying the same bytes never exempts the
/// value. A detector that labels one secret as both a secret kind and a
/// non-secret kind makes the default policy redact one span and keep the other
/// (a local recipient keeps every remaining non-secret value), and an
/// exemption on the kept alias would return the raw secret. A plan that both
/// removes and keeps identical bytes is contradictory, so the pipeline fails
/// closed rather than pick a winner.
///
/// # Errors
///
/// Returns [`TransformError::Message`] naming the kind — never the value —
/// when the text still contains the value of an entity the plan removes.
pub(crate) fn validate_transformed_text(
    plan: &[PlannedEntity],
    text: &str,
) -> Result<(), TransformError> {
    for planned in plan {
        let removes_value = matches!(
            planned.action,
            Action::Pseudonymize | Action::Redact | Action::Block
        );
        if removes_value && text.contains(&planned.entity.value) {
            return Err(TransformError::Message(format!(
                "transformed text still contains the value of kind `{}`, which the plan removes",
                planned.entity.kind
            )));
        }
    }
    Ok(())
}
