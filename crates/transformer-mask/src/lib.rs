//! Non-reversible partial-masking transformer.
//!
//! Unlike pseudonymization, nothing is stored: the replacement keeps only the
//! trailing [`VISIBLE_TAIL`] characters of the value, so the output reveals
//! less than the raw value while staying recognizably shaped. Nothing can be
//! restored, and `restore` is a no-op on masked text.

use do_context_shield_plugin_api::{
    Action, PlannedEntity, ScopeId, TransformError, TransformResult, Transformer, Vault,
};

/// Fixed replacement for an entity the policy redacts.
const REDACTED: &str = "__DO_PRIVATE_REDACTED__";

/// How many trailing characters stay visible in a masked value.
const VISIBLE_TAIL: usize = 4;

/// Replaces each pseudonymization target with a partially masked value.
pub struct MaskingTransformer;

impl Transformer for MaskingTransformer {
    fn transform(
        &self,
        input: &str,
        plan: &[PlannedEntity],
        _scope: &ScopeId,
        _vault: &mut dyn Vault,
    ) -> Result<TransformResult, TransformError> {
        let mut ordered = plan.to_vec();
        ordered.sort_by_key(|item| (item.entity.start, item.entity.end));

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0usize;

        for planned in ordered {
            if planned.entity.start < cursor || planned.entity.end > input.len() {
                return Err(TransformError::Message(
                    "overlapping or invalid entity range".to_owned(),
                ));
            }
            let gap = input.get(cursor..planned.entity.start).ok_or_else(|| {
                TransformError::Message("entity range is not on char boundaries".to_owned())
            })?;
            output.push_str(gap);
            let replacement = match planned.action {
                Action::Keep => planned.entity.value.clone(),
                Action::Redact => REDACTED.to_owned(),
                Action::Block => {
                    return Err(TransformError::Message("blocked by policy".to_owned()));
                }
                Action::Pseudonymize => mask(&planned.entity.value),
            };
            output.push_str(&replacement);
            cursor = planned.entity.end;
        }
        let tail = input.get(cursor..).ok_or_else(|| {
            TransformError::Message("entity end is not on char boundaries".to_owned())
        })?;
        output.push_str(tail);

        // Masking stores nothing: there is no mapping to resolve.
        Ok(TransformResult {
            text: output,
            mappings: Vec::new(),
        })
    }
}

/// `*` for every character except the last [`VISIBLE_TAIL`], which stay.
///
/// Values of [`VISIBLE_TAIL`] characters or fewer are masked entirely, so a
/// short value never reveals most of itself. Characters, not bytes, drive the
/// split, so multi-byte values cannot be cut mid-character.
fn mask(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    // Short values have no tail to spare: mask all of them instead of none.
    let masked = if characters.len() > VISIBLE_TAIL {
        characters.len() - VISIBLE_TAIL
    } else {
        characters.len()
    };
    characters
        .iter()
        .enumerate()
        .map(|(index, character)| if index < masked { '*' } else { *character })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use do_context_shield_plugin_api::{Entity, PlannedEntity, is_minted_placeholder_token};
    use do_context_shield_vault_memory::MemoryVault;

    fn planned(value: &str, kind: &str, start: usize, end: usize, action: Action) -> PlannedEntity {
        PlannedEntity {
            entity: Entity {
                kind: kind.to_owned(),
                start,
                end,
                value: value.to_owned(),
                confidence: 1.0,
            },
            action,
        }
    }

    fn transform(input: &str, plan: &[PlannedEntity]) -> Result<TransformResult, TransformError> {
        let mut vault = MemoryVault::default();
        MaskingTransformer.transform(input, plan, &ScopeId("test".to_owned()), &mut vault)
    }

    #[test]
    fn masks_all_but_the_last_four_characters() {
        let result = match transform(
            "mail alice@example.com",
            &[planned(
                "alice@example.com",
                "email",
                5,
                22,
                Action::Pseudonymize,
            )],
        ) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(result.text, "mail *************.com");
        assert!(result.mappings.is_empty(), "{result:?}");
        assert!(!is_minted_placeholder_token("*************.com"));
    }

    #[test]
    fn short_values_are_masked_entirely_or_nearly() {
        for (value, masked) in [
            ("abc", "***"),
            ("abcd", "****"),
            ("abcde", "*bcde"),
            ("123-45-6789", "*******6789"),
        ] {
            let result = match transform(
                value,
                &[planned(
                    value,
                    "phone",
                    0,
                    value.len(),
                    Action::Pseudonymize,
                )],
            ) {
                Ok(result) => result,
                Err(error) => panic!("unexpected error: {error}"),
            };
            assert_eq!(result.text, masked, "{value}");
        }
    }

    #[test]
    fn multibyte_values_are_masked_by_character() {
        // "grüße@x.de" is 10 characters (12 bytes); the last four stay.
        let result = match transform(
            "grüße@x.de",
            &[planned("grüße@x.de", "email", 0, 12, Action::Pseudonymize)],
        ) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(result.text, "******x.de");
    }

    #[test]
    fn redact_and_keep_paths() {
        let kept = match transform(
            "alice@example.com",
            &[planned("alice@example.com", "email", 0, 17, Action::Keep)],
        ) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(kept.text, "alice@example.com");

        let redacted = match transform(
            "key hunter2",
            &[planned("hunter2", "password", 4, 11, Action::Redact)],
        ) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(redacted.text, "key __DO_PRIVATE_REDACTED__");
    }

    #[test]
    fn block_action_fails_closed() {
        let error = match transform(
            "alice@example.com",
            &[planned("alice@example.com", "email", 0, 17, Action::Block)],
        ) {
            Ok(result) => panic!("expected an error, got {result:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("blocked by policy"), "{error}");
    }

    #[test]
    fn overlapping_ranges_are_rejected() {
        let error = match transform(
            "alice@example.com",
            &[
                planned("alice@example.com", "email", 0, 17, Action::Pseudonymize),
                planned("example.com", "domain", 5, 17, Action::Pseudonymize),
            ],
        ) {
            Ok(result) => panic!("expected an error, got {result:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("overlapping"), "{error}");
    }
}
