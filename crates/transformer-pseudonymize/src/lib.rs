//! Reversible pseudonymizer transformer.

use do_context_shield_plugin_api::{
    Action, PlannedEntity, ScopeId, TransformError, TransformResult, Transformer, Vault,
};

/// Default transformer.
pub struct PseudonymizingTransformer;

impl Transformer for PseudonymizingTransformer {
    fn transform(
        &self,
        input: &str,
        plan: &[PlannedEntity],
        scope: &ScopeId,
        vault: &mut dyn Vault,
    ) -> Result<TransformResult, TransformError> {
        let mut ordered = plan.to_vec();
        ordered.sort_by_key(|item| (item.entity.start, item.entity.end));

        let mut output = String::with_capacity(input.len());
        let mut cursor = 0usize;
        let mut mappings = Vec::new();

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
                Action::Redact => "__DO_PRIVATE_REDACTED__".to_owned(),
                Action::Pseudonymize => {
                    let mapping = vault
                        .get_or_insert(scope, &planned.entity.kind, &planned.entity.value)
                        .map_err(|error| TransformError::Message(error.to_string()))?;
                    mappings.push(mapping.clone());
                    mapping.token
                }
            };
            output.push_str(&replacement);
            cursor = planned.entity.end;
        }
        let tail = input.get(cursor..).ok_or_else(|| {
            TransformError::Message("entity end is not on char boundaries".to_owned())
        })?;
        output.push_str(tail);

        Ok(TransformResult {
            text: output,
            mappings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use do_context_shield_plugin_api::{Action, Entity, PlannedEntity};
    use do_context_shield_vault_memory::MemoryVault;

    fn planned(kind: &str, start: usize, end: usize, action: Action) -> PlannedEntity {
        PlannedEntity {
            entity: Entity {
                kind: kind.to_owned(),
                start,
                end,
                value: String::new(),
                confidence: 1.0,
            },
            action,
        }
    }

    fn transform(input: &str, plan: &[PlannedEntity]) -> Result<TransformResult, TransformError> {
        PseudonymizingTransformer.transform(
            input,
            plan,
            &ScopeId("test".to_owned()),
            &mut MemoryVault::default(),
        )
    }

    #[test]
    fn overlapping_ranges_are_rejected() {
        let plan = vec![
            planned("email", 0, 10, Action::Pseudonymize),
            planned("person", 5, 8, Action::Pseudonymize),
        ];
        match transform("0123456789abcdef", &plan) {
            Ok(_) => panic!("expected overlap error"),
            Err(error) => assert!(error.to_string().contains("overlapping")),
        }
    }

    #[test]
    fn non_boundary_ranges_are_rejected() {
        let plan = vec![planned("person", 1, 3, Action::Pseudonymize)];
        match transform("grüße", &plan) {
            Ok(_) => panic!("expected boundary error"),
            Err(error) => assert!(error.to_string().contains("char boundaries")),
        }
    }

    #[test]
    fn keep_and_redact_paths() {
        let plan = vec![
            planned("note", 0, 4, Action::Keep),
            planned("api_key", 5, 11, Action::Redact),
        ];
        // Values are passed through for Keep; Redact emits the fixed token.
        let mut keep_plan = plan;
        keep_plan[0].entity.value = "keep".to_owned();
        let result = match transform("keep secret", &keep_plan) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(result.text, "keep __DO_PRIVATE_REDACTED__");
        assert!(result.mappings.is_empty());
    }
}
