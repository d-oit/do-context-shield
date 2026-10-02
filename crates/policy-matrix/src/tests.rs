//! Unit tests for `MatrixPolicy`.

use super::*;
use std::collections::HashSet;

fn entity(kind: &str) -> Entity {
    Entity {
        kind: kind.to_owned(),
        start: 0,
        end: 1,
        value: "test_val".to_owned(),
        confidence: 1.0,
    }
}

/// Plan one entity of `kind` and return its action, failing the test on error.
fn action(policy: &MatrixPolicy, kind: &str, context: &ProcessingContext) -> Action {
    actions(policy, &[kind], &[], context)[0]
}

fn actions(
    policy: &MatrixPolicy,
    kinds: &[&str],
    judgments: &[Judgment],
    context: &ProcessingContext,
) -> Vec<Action> {
    let entities: Vec<Entity> = kinds.iter().map(|kind| entity(kind)).collect();
    match policy.plan(&entities, judgments, context) {
        Ok(planned) => planned.into_iter().map(|planned| planned.action).collect(),
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn context(
    purpose: Option<&str>,
    recipient: RecipientClass,
    jurisdiction: Option<&str>,
    data_category: DataCategory,
) -> ProcessingContext {
    ProcessingContext {
        purpose: purpose.map(str::to_owned),
        recipient,
        jurisdiction: jurisdiction.map(str::to_owned),
        data_category,
    }
}

#[test]
fn secrets_always_redact_even_if_purpose_rule_says_keep() {
    let config = MatrixConfig {
        purpose_rules: vec![PurposeRule {
            purpose: "emergency_debug".to_owned(),
            data_category: None,
            recipients: vec![RecipientClass::Local, RecipientClass::Trusted],
            action: RuleAction::Keep,
        }],
        ..MatrixConfig::default()
    };
    let policy = MatrixPolicy::new(config);
    let ctx = context(
        Some("emergency_debug"),
        RecipientClass::Local,
        Some("DE"),
        DataCategory::Personal,
    );

    let planned = actions(&policy, &["generic_secret", "api_key", "jwt"], &[], &ctx);
    assert_eq!(
        planned,
        vec![Action::Redact; 3],
        "secret kinds must redact under a purpose keep rule"
    );
}

#[test]
fn secrets_with_judge_label_always_redact() {
    let config = MatrixConfig {
        purpose_rules: vec![PurposeRule {
            purpose: "bypass".to_owned(),
            data_category: None,
            recipients: vec![],
            action: RuleAction::Keep,
        }],
        ..MatrixConfig::default()
    };
    let policy = MatrixPolicy::new(config);
    let ctx = context(
        Some("bypass"),
        RecipientClass::Local,
        None,
        DataCategory::Personal,
    );
    let judgments = vec![Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Secret,
        confidence: 0.99,
    }];
    assert_eq!(
        actions(&policy, &["email"], &judgments, &ctx),
        vec![Action::Redact],
        "a Secret label must redact even under a purpose keep rule"
    );
}

#[test]
fn adequacy_permits_declared_origin_and_configured_destinations() {
    let mut adequate = HashSet::new();
    adequate.insert("FR".to_owned());
    adequate.insert("gb".to_owned()); // normalized to uppercase
    let config = MatrixConfig {
        origin: Some("DE".to_owned()),
        adequate_jurisdictions: adequate,
        enforce_adequacy_for_trusted: true,
        purpose_rules: vec![],
    };
    let policy = MatrixPolicy::new(config);

    // Trusted, special category, adequate destination (lower-case: normalized)
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                Some("fr"),
                DataCategory::SpecialCategory
            ),
        ),
        Action::Pseudonymize
    );

    // Domestic destination (the declared origin) is not a cross-border transfer
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                Some("de"),
                DataCategory::SpecialCategory
            ),
        ),
        Action::Pseudonymize
    );

    // Inadequate destination blocks
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                Some("US"),
                DataCategory::SpecialCategory
            ),
        ),
        Action::Block
    );

    // Malformed destination shape blocks
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                Some("USA"),
                DataCategory::SpecialCategory
            ),
        ),
        Action::Block
    );

    // Unset destination blocks
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                None,
                DataCategory::SpecialCategory
            ),
        ),
        Action::Block
    );
}

#[test]
fn undeclared_origin_blocks_special_category_to_trusted() {
    // Adequacy is a pair decision: even a destination listed as adequate is
    // refused while the origin is undeclared, so an incomplete matrix cannot
    // silently loosen the transfer.
    let mut adequate = HashSet::new();
    adequate.insert("FR".to_owned());
    let config = MatrixConfig {
        adequate_jurisdictions: adequate,
        ..MatrixConfig::default()
    };
    let policy = MatrixPolicy::new(config);
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                Some("FR"),
                DataCategory::SpecialCategory
            ),
        ),
        Action::Block
    );
}

#[test]
fn fail_closed_default_enforces_adequacy() {
    // A default (unconfigured) matrix must be no looser than the built-in
    // default policy: special category to a trusted recipient blocks even with
    // a valid jurisdiction, because the adequacy set is empty.
    let policy = MatrixPolicy::new(MatrixConfig::default());
    assert!(policy.config.enforce_adequacy_for_trusted);
    assert_eq!(
        action(
            &policy,
            "health_record",
            &context(
                None,
                RecipientClass::Trusted,
                Some("DE"),
                DataCategory::SpecialCategory
            ),
        ),
        Action::Block
    );
}

#[test]
fn purpose_rules_evaluated_in_declaration_order() {
    let config = MatrixConfig {
        origin: Some("DE".to_owned()),
        purpose_rules: vec![
            PurposeRule {
                purpose: "analytics".to_owned(),
                data_category: Some(DataCategory::Personal),
                recipients: vec![RecipientClass::Trusted],
                action: RuleAction::Keep,
            },
            PurposeRule {
                purpose: "analytics".to_owned(),
                data_category: None,
                recipients: vec![],
                action: RuleAction::Block,
            },
            PurposeRule {
                purpose: "unapproved".to_owned(),
                data_category: None,
                recipients: vec![],
                action: RuleAction::Block,
            },
        ],
        ..MatrixConfig::default()
    };
    let policy = MatrixPolicy::new(config);

    // Analytics + Personal + Trusted hits the first rule
    assert_eq!(
        action(
            &policy,
            "user_name",
            &context(
                Some("analytics"),
                RecipientClass::Trusted,
                Some("DE"),
                DataCategory::Personal
            ),
        ),
        Action::Keep
    );

    // Analytics + External misses rule one, hits rule two
    assert_eq!(
        action(
            &policy,
            "user_name",
            &context(
                Some("analytics"),
                RecipientClass::External,
                Some("DE"),
                DataCategory::Personal
            ),
        ),
        Action::Block
    );

    // Unapproved purpose blocks regardless of recipient
    assert_eq!(
        action(
            &policy,
            "user_name",
            &context(
                Some("unapproved"),
                RecipientClass::Local,
                None,
                DataCategory::NonPersonal
            ),
        ),
        Action::Block
    );
}

#[test]
fn unknown_recipient_blocks_personal_data() {
    let policy = MatrixPolicy::default();
    assert_eq!(
        action(
            &policy,
            "user_name",
            &context(None, RecipientClass::Unknown, None, DataCategory::Personal),
        ),
        Action::Block
    );
}

#[test]
fn high_confidence_test_label_keeps() {
    let policy = MatrixPolicy::default();
    let ctx = context(
        None,
        RecipientClass::Trusted,
        Some("DE"),
        DataCategory::Personal,
    );
    let judgments = vec![Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Test,
        confidence: 0.95,
    }];
    assert_eq!(
        actions(&policy, &["email"], &judgments, &ctx),
        vec![Action::Keep]
    );
}

#[test]
fn local_recipient_keeps_remaining_values() {
    let policy = MatrixPolicy::default();
    assert_eq!(
        action(
            &policy,
            "email",
            &context(None, RecipientClass::Local, None, DataCategory::Personal),
        ),
        Action::Keep
    );
}
