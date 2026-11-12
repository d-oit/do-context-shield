//! Conservative default privacy policy.
//!
//! Actions come from the entity kind, an optional semantic judge decision, and
//! the [`ProcessingContext`]:
//!
//! - secret-like kinds and `secret` labels always redact;
//! - special-category data addressed to external or unknown recipients is
//!   blocked, and a trusted recipient blocks it while `jurisdiction` is unset
//!   or malformed;
//! - unknown recipients block every non-secret entity that is not `non_personal`;
//! - `test`/`business` labels at or above 0.90 keep the value;
//! - a local recipient keeps non-secret values;
//! - everything else (including `personal`, abstention, low confidence, and a
//!   missing judgment) pseudonymizes.
//!
//! A judge can therefore never turn a secret into a keep or a pseudonym.

use do_context_shield_plugin_api::{
    Action, DataCategory, DecisionReason, Entity, Judgment, PlannedEntity, Policy, PolicyError,
    ProcessingContext, ReasonCode, RecipientClass, SemanticLabel, is_secret_kind,
    is_valid_jurisdiction,
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
        Ok(entities
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, entity)| {
                let decision = judgments.iter().find(|judgment| judgment.index() == index);
                PlannedEntity {
                    action: decide(&entity, decision, context).action,
                    entity,
                }
            })
            .collect())
    }

    fn explain(
        &self,
        plan: &[PlannedEntity],
        judgments: &[Judgment],
        context: &ProcessingContext,
    ) -> Result<Vec<DecisionReason>, PolicyError> {
        Ok(plan
            .iter()
            .enumerate()
            .map(|(index, planned)| {
                let decision = judgments.iter().find(|judgment| judgment.index() == index);
                decide(&planned.entity, decision, context)
            })
            .collect())
    }
}

/// Decide one action and its value-free explanation from policy inputs.
fn decide(
    entity: &Entity,
    decision: Option<&Judgment>,
    context: &ProcessingContext,
) -> DecisionReason {
    let result = |action, reason_code| DecisionReason {
        kind: entity.kind.clone(),
        start: entity.start,
        end: entity.end,
        action,
        reason_code,
        matched_rule: None,
        used_default: true,
    };
    if is_secret_kind(&entity.kind) {
        return result(Action::Redact, ReasonCode::SecretKind);
    }
    if matches!(
        decision,
        Some(Judgment::Labeled {
            label: SemanticLabel::Secret,
            ..
        })
    ) {
        return result(Action::Redact, ReasonCode::JudgeSecret);
    }

    if context.data_category == DataCategory::SpecialCategory {
        if matches!(
            context.recipient,
            RecipientClass::External | RecipientClass::Unknown
        ) {
            return result(Action::Block, ReasonCode::SpecialCategoryBlocked);
        }
        if context.recipient == RecipientClass::Trusted
            && !context
                .jurisdiction
                .as_deref()
                .is_some_and(is_valid_jurisdiction)
        {
            return result(Action::Block, ReasonCode::JurisdictionRequiredBlocked);
        }
    }

    if context.recipient == RecipientClass::Unknown
        && context.data_category != DataCategory::NonPersonal
    {
        return result(Action::Block, ReasonCode::UnknownRecipientBlocked);
    }
    if let Some(Judgment::Labeled {
        label: SemanticLabel::Test | SemanticLabel::Business,
        confidence,
        ..
    }) = decision
        && *confidence >= KEEP_CONFIDENCE
    {
        return result(Action::Keep, ReasonCode::JudgeKeep);
    }
    if context.recipient == RecipientClass::Local {
        return result(Action::Keep, ReasonCode::LocalRecipientKeep);
    }
    result(Action::Pseudonymize, ReasonCode::DefaultPseudonymize)
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
            Ok(planned) => planned[0].action,
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
    fn unknown_recipient_keeps_non_personal() {
        // The unknown-recipient block covers personal data only: explicitly
        // non-personal entities fall through to the normal rules.
        let context = ProcessingContext {
            recipient: RecipientClass::Unknown,
            data_category: DataCategory::NonPersonal,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Pseudonymize);
        assert_eq!(action_with("api_key", &[], &context), Action::Redact);
        assert_eq!(
            action_with("email", &[labeled(0, SemanticLabel::Test, 0.95)], &context),
            Action::Keep
        );
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

    #[test]
    fn special_category_to_trusted_without_jurisdiction_blocks() {
        // Unknown jurisdiction fails closed: trusted is the one non-local
        // recipient the plain recipient rules let through, so the absent
        // jurisdiction decides against the transfer.
        let context = ProcessingContext {
            recipient: RecipientClass::Trusted,
            data_category: DataCategory::SpecialCategory,
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Block);
    }

    #[test]
    fn malformed_jurisdiction_to_trusted_blocks() {
        // A malformed code is not a declared jurisdiction: the trusted
        // special-category transfer blocks exactly as if the field were unset,
        // so a direct library caller cannot bypass the check by constructing
        // the context itself.
        for value in ["", "Germany", "DEU", "de-DE", "D1", "é"] {
            let context = ProcessingContext {
                recipient: RecipientClass::Trusted,
                data_category: DataCategory::SpecialCategory,
                jurisdiction: Some(value.to_owned()),
                ..ProcessingContext::default()
            };
            assert_eq!(
                action_with("email", &[], &context),
                Action::Block,
                "jurisdiction `{value}` must not count as declared"
            );
        }
    }

    #[test]
    fn special_category_to_trusted_with_a_jurisdiction_pseudonymizes() {
        // A declared jurisdiction keeps the previous behavior: only external
        // and unknown recipients block special-category data outright.
        let context = ProcessingContext {
            recipient: RecipientClass::Trusted,
            data_category: DataCategory::SpecialCategory,
            jurisdiction: Some("DE".to_owned()),
            ..ProcessingContext::default()
        };
        assert_eq!(action_with("email", &[], &context), Action::Pseudonymize);
    }
    #[test]
    fn explanations_share_decision_logic_and_report_stable_reasons() {
        let entities = [entity("api_key"), entity("email")];
        let context = ProcessingContext::default();
        let judgments: [Judgment; 0] = [];
        let plan = match DefaultPolicy.plan(&entities, &judgments, &context) {
            Ok(plan) => plan,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let reasons = match DefaultPolicy.explain(&plan, &judgments, &context) {
            Ok(reasons) => reasons,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(
            plan.iter().map(|item| item.action).collect::<Vec<_>>(),
            reasons.iter().map(|item| item.action).collect::<Vec<_>>()
        );
        assert_eq!(reasons[0].reason_code, ReasonCode::SecretKind);
        assert_eq!(reasons[1].reason_code, ReasonCode::DefaultPseudonymize);
        assert!(reasons.iter().all(|reason| reason.used_default));
        assert!(reasons.iter().all(|reason| reason.matched_rule.is_none()));
    }
}
