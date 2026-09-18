//! Conservative default privacy policy.
//!
//! Actions come from the entity kind plus an optional semantic judge decision:
//! secret-like kinds always redact; a `secret` label always redacts;
//! `test`/`business` labels at or above 0.90 keep the value; everything else
//! (including `personal`, abstention, low confidence, and a missing judgment)
//! pseudonymizes. A judge can therefore never turn a secret into a keep or a
//! pseudonym.

use do_context_shield_plugin_api::{
    Action, Entity, Judgment, PlannedEntity, Policy, PolicyError, SemanticLabel, is_secret_kind,
};

/// Minimum judge confidence required to trust a `test` or `business` label.
const KEEP_CONFIDENCE: f32 = 0.90;

/// Conservative default policy.
#[derive(Default)]
pub struct DefaultPolicy;

impl Policy for DefaultPolicy {
    fn plan(
        &self,
        entities: &[Entity],
        judgments: &[Judgment],
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        entities
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, entity)| {
                let decision = judgments.iter().find(|judgment| judgment.index() == index);
                let action = decide(&entity.kind, decision);
                Ok(PlannedEntity { entity, action })
            })
            .collect()
    }
}

/// Decide one action from the entity kind and an optional judge decision.
fn decide(kind: &str, decision: Option<&Judgment>) -> Action {
    if is_secret_kind(kind) {
        return Action::Redact;
    }
    match decision {
        Some(Judgment::Labeled {
            label: SemanticLabel::Secret,
            ..
        }) => Action::Redact,
        Some(Judgment::Labeled {
            label: SemanticLabel::Test | SemanticLabel::Business,
            confidence,
            ..
        }) if *confidence >= KEEP_CONFIDENCE => Action::Keep,
        Some(Judgment::Labeled { .. } | Judgment::Abstain { .. }) | None => Action::Pseudonymize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(kind: &str) -> Entity {
        Entity {
            kind: kind.to_owned(),
            start: 0,
            end: 1,
            value: "x".to_owned(),
            confidence: 1.0,
        }
    }

    fn action(kind: &str, judgments: &[Judgment]) -> Action {
        let entities = [entity(kind)];
        match DefaultPolicy.plan(&entities, judgments) {
            Ok(planned) => planned[0].action.clone(),
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn labeled(index: usize, label: SemanticLabel, confidence: f32) -> Judgment {
        Judgment::Labeled {
            index,
            label,
            confidence,
        }
    }

    #[test]
    fn secret_kind_without_judgments_redacts() {
        assert_eq!(action("api_key", &[]), Action::Redact);
    }

    #[test]
    fn high_confidence_test_label_keeps() {
        assert_eq!(
            action("email", &[labeled(0, SemanticLabel::Test, 0.95)]),
            Action::Keep
        );
    }

    #[test]
    fn low_confidence_test_label_pseudonymizes() {
        assert_eq!(
            action("email", &[labeled(0, SemanticLabel::Test, 0.5)]),
            Action::Pseudonymize
        );
    }

    #[test]
    fn high_confidence_business_label_keeps() {
        assert_eq!(
            action("email", &[labeled(0, SemanticLabel::Business, 0.95)]),
            Action::Keep
        );
    }

    #[test]
    fn secret_label_redacts_a_plain_kind() {
        assert_eq!(
            action("email", &[labeled(0, SemanticLabel::Secret, 0.99)]),
            Action::Redact
        );
    }

    #[test]
    fn test_label_cannot_keep_a_secret_kind() {
        assert_eq!(
            action("api_key", &[labeled(0, SemanticLabel::Test, 0.95)]),
            Action::Redact
        );
    }

    #[test]
    fn entities_without_a_judgment_pseudonymize() {
        let entities = [entity("email"), entity("phone")];
        let planned = match DefaultPolicy.plan(&entities, &[labeled(0, SemanticLabel::Test, 0.95)])
        {
            Ok(planned) => planned,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(planned[0].action, Action::Keep);
        assert_eq!(planned[1].action, Action::Pseudonymize);
    }
}
