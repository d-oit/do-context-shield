//! Conservative default privacy policy.

use do_context_shield_plugin_api::{Action, Entity, PlannedEntity, Policy, PolicyError};

/// Conservative default policy.
#[derive(Default)]
pub struct DefaultPolicy;

impl Policy for DefaultPolicy {
    fn plan(&self, entities: &[Entity]) -> Result<Vec<PlannedEntity>, PolicyError> {
        entities
            .iter()
            .cloned()
            .map(|entity| {
                let kind = entity.kind.as_str();
                let action = if kind.contains("key")
                    || kind.contains("secret")
                    || kind == "password"
                    || kind == "github_token"
                {
                    Action::Redact
                } else {
                    Action::Pseudonymize
                };
                Ok(PlannedEntity { entity, action })
            })
            .collect()
    }
}
