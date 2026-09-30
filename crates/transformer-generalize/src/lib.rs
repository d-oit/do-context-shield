//! Non-reversible generalizing transformer.
//!
//! Pseudonymization mints one stable, vault-resolvable token per value, so
//! repeated values keep their identity and the transform stays reversible.
//! Generalization gives both up deliberately: every value of a kind collapses
//! into one kind-only token that no vault holds, so nothing can be restored.

use do_context_shield_plugin_api::{
    Action, PlannedEntity, ScopeId, TransformError, TransformResult, Transformer, Vault,
    is_valid_placeholder_kind,
};

/// Fixed replacement for an entity the policy redacts.
const REDACTED: &str = "__DO_PRIVATE_REDACTED__";

/// Replaces each pseudonymization target with a kind-only token.
pub struct GeneralizingTransformer;

impl Transformer for GeneralizingTransformer {
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
                Action::Pseudonymize => kind_token(&planned.entity.kind)?,
            };
            output.push_str(&replacement);
            cursor = planned.entity.end;
        }
        let tail = input.get(cursor..).ok_or_else(|| {
            TransformError::Message("entity end is not on char boundaries".to_owned())
        })?;
        output.push_str(tail);

        // Generalization stores nothing: there is no mapping to resolve, and
        // `restore` therefore leaves the output untouched.
        Ok(TransformResult {
            text: output,
            mappings: Vec::new(),
        })
    }
}

/// `__DO_PRIVATE_<KIND>__` for a kind that can live in a placeholder token.
///
/// # Errors
///
/// Returns [`TransformError::Message`] when the kind cannot be represented in
/// a placeholder token, so a malformed detector label can never emit an
/// unparseable token.
fn kind_token(kind: &str) -> Result<String, TransformError> {
    if !is_valid_placeholder_kind(kind) {
        return Err(TransformError::Message(format!(
            "cannot generalize an entity with an invalid kind `{kind}`"
        )));
    }
    Ok(format!("__DO_PRIVATE_{}__", kind.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use do_context_shield_plugin_api::{
        Entity, PlannedEntity, is_minted_placeholder_token, is_placeholder_token,
    };
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
        GeneralizingTransformer.transform(input, plan, &ScopeId("test".to_owned()), &mut vault)
    }

    #[test]
    fn pseudonymization_targets_become_kind_only_tokens() {
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
        assert_eq!(result.text, "mail __DO_PRIVATE_EMAIL__");
        assert!(result.mappings.is_empty(), "{result:?}");
        // The token has the placeholder shape `restore` scans for, but not the
        // minted shape a vault could resolve.
        assert!(is_placeholder_token("__DO_PRIVATE_EMAIL__"));
        assert!(!is_minted_placeholder_token("__DO_PRIVATE_EMAIL__"));
    }

    #[test]
    fn repeated_values_collapse_into_one_token() {
        // The identity stability pseudonymization guarantees is deliberately
        // given up: two different addresses of one kind share one token.
        let result = match transform(
            "a alice@example.com b bob@example.com",
            &[
                planned("alice@example.com", "email", 2, 19, Action::Pseudonymize),
                planned("bob@example.com", "email", 22, 37, Action::Pseudonymize),
            ],
        ) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(result.text, "a __DO_PRIVATE_EMAIL__ b __DO_PRIVATE_EMAIL__");
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
    fn invalid_kind_fails_closed() {
        let error = match transform(
            "alice@example.com",
            &[planned(
                "alice@example.com",
                "email__x",
                0,
                17,
                Action::Pseudonymize,
            )],
        ) {
            Ok(result) => panic!("expected an error, got {result:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid kind"), "{error}");
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
