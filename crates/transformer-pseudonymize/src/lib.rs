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
            output.push_str(&input[cursor..planned.entity.start]);
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
        output.push_str(&input[cursor..]);

        Ok(TransformResult {
            text: output,
            mappings,
        })
    }
}
