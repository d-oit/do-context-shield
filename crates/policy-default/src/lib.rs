//! Conservative default privacy policy.
//!
//! Actions come from the entity kind, an optional semantic judge decision, and
//! the [`ProcessingContext`]:
//!
//! - secret-like kinds and `secret` labels always redact;
//! - special-category data addressed to external or unknown recipients is blocked;
//! - unknown recipients block every non-secret entity that is not `non_personal`;
//! - `test`/`business` labels at or above 0.90 keep the value;
//! - a local recipient keeps non-secret values;
//! - everything else (including `personal`, abstention, low confidence, and a
//!   missing judgment) pseudonymizes.
//!
//! A judge can therefore never turn a secret into a keep or a pseudonym.

use do_context_shield_plugin_api::{
    Action, DataCategory, Entity, Judgment, PlannedEntity, Policy, PolicyError, ProcessingContext,
    RecipientClass, SemanticLabel, is_secret_kind,
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
        context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        entities
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, entity)| {
                let decision = judgments.iter().find(|judgment| judgment.index() == index);
                let action = decide(&entity.kind, decision, context);
                Ok(PlannedEntity { entity, action })
            })
            .collect()
    }
}

/// Decide one action from the entity kind, an optional judge decision, and the
/// enforcement context.
fn decide(kind: &str, decision: Option<&Judgment>, context: &ProcessingContext) -> Action {
    // Secrets are always redacted regardless of context.
    if is_secret_kind(kind) {
        return Action::Redact;
    }
    if let Some(Judgment::Labeled {
        label: SemanticLabel::Secret,
        ..
    }) = decision
    {
        return Action::Redact;
    }

    // Special-category data never reaches an external or unknown recipient.
    if context.data_category == DataCategory::SpecialCategory
        && matches!(
            context.recipient,
            RecipientClass::External | RecipientClass::Unknown
        )
    {
        return Action::Block;
    }

    // An unknown recipient blocks every non-secret entity that is not
    // explicitly non-personal.
    if context.recipient == RecipientClass::Unknown
        && context.data_category != DataCategory::NonPersonal
    {
        return Action::Block;
    }

    // High-confidence test/business labels keep the value.
    if let Some(Judgment::Labeled {
        label: SemanticLabel::Test | SemanticLabel::Business,
        confidence,
        ..
    }) = decision
        && *confidence >= KEEP_CONFIDENCE
    {
        return Action::Keep;
    }

    // A local recipient keeps every remaining value.
    if context.recipient == RecipientClass::Local {
        return Action::Keep;
    }

    // Everything else pseudonymizes.
    Action::Pseudonymize
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
        action_with(kind, judgments, &ProcessingContext::default())
    }

    fn action_with(kind: &str, judgments: &[Judgment], context: &ProcessingContext) -> Action {
        let entities = [entity(kind)];
        match DefaultPolicy.plan(&entities, judgments, context) {
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
        let planned = match DefaultPolicy.plan(
            &entities,
            &[labeled(0, SemanticLabel::Test, 0.95)],
            &ProcessingContext::default(),
        ) {
            Ok(planned) => planned,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(planned[0].action, Action::Keep);
        assert_eq!(planned[1].action, Action::Pseudonymize);
    }

    #[test]
    fn special_category_to_external_blocks() {
        let context = ProcessingContext {
            data_category: DataCategory::SpecialCategory,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Block);
    }

    #[test]
    fn unknown_recipient_blocks_personal() {
        let context = ProcessingContext {
            recipient: RecipientClass::Unknown,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Block);
    }

    #[test]
    fn unknown_recipient_still_redacts_secrets() {
        let context = ProcessingContext {
            recipient: RecipientClass::Unknown,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("api_key", &[], &context), Action::Redact);
    }

    #[test]
    fn local_recipient_keeps_personal() {
        let context = ProcessingContext {
            recipient: RecipientClass::Local,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Keep);
        assert_eq!(action_with("api_key", &[], &context), Action::Redact);
    }

    #[test]
    fn trusted_recipient_pseudonymizes_personal() {
        let context = ProcessingContext {
            recipient: RecipientClass::Trusted,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Pseudonymize);
    }

    #[test]
    fn special_category_to_local_keeps() {
        let context = ProcessingContext {
            recipient: RecipientClass::Local,
            data_category: DataCategory::SpecialCategory,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Keep);
    }
}
