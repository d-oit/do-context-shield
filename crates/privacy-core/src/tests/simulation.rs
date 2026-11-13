//! Contract tests for value-free policy simulation.

use super::*;
use do_context_shield_plugin_api::{DecisionReason, ReasonCode};

#[test]
fn simulation_reports_redaction_and_block_without_disclosing_values() {
    let planner = PolicyPlanner::new(Box::new(RegexDetector), Box::new(DefaultPolicy));
    let secret = format!("password={}", "x".repeat(16));
    let decisions = match planner.explain(&secret, &ProcessingContext::default()) {
        Ok(decisions) => decisions,
        Err(error) => panic!("unexpected simulation error: {error}"),
    };
    assert_eq!(decisions[0].action, Action::Redact);
    assert_eq!(decisions[0].reason_code, ReasonCode::SecretKind);
    assert!(!format!("{decisions:?}").contains(&secret));

    let context = ProcessingContext {
        recipient: do_context_shield_plugin_api::RecipientClass::Unknown,
        ..ProcessingContext::default()
    };
    let decisions = match planner.explain("alice@example.com", &context) {
        Ok(decisions) => decisions,
        Err(error) => panic!("unexpected simulation error: {error}"),
    };
    assert_eq!(decisions[0].action, Action::Block);
    assert_eq!(
        decisions[0].reason_code,
        ReasonCode::UnknownRecipientBlocked
    );
}

struct MissingReasonPolicy;

impl Policy for MissingReasonPolicy {
    fn plan(
        &self,
        entities: &[Entity],
        _judgments: &[Judgment],
        _context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        Ok(entities
            .iter()
            .cloned()
            .map(|entity| PlannedEntity {
                entity,
                action: Action::Keep,
            })
            .collect())
    }

    fn explain(
        &self,
        _plan: &[PlannedEntity],
        _judgments: &[Judgment],
        _context: &ProcessingContext,
    ) -> Result<Vec<DecisionReason>, PolicyError> {
        Ok(Vec::new())
    }
}

#[test]
fn simulation_rejects_policy_explanations_without_one_result_per_entity() {
    let planner = PolicyPlanner::new(Box::new(RegexDetector), Box::new(MissingReasonPolicy));
    let error = match planner.explain("alice@example.com", &ProcessingContext::default()) {
        Ok(_) => panic!("missing policy explanation must fail closed"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("different number of explanations")
    );
}

struct EchoErrorDetector;

impl Detector for EchoErrorDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        Err(DetectorError::Message(format!("failure for {input}")))
    }
}

#[test]
fn simulation_scrubs_input_from_stage_errors() {
    let planner = PolicyPlanner::new(Box::new(EchoErrorDetector), Box::new(DefaultPolicy));
    let secret = "alice@example.com";
    let error = match planner.explain(secret, &ProcessingContext::default()) {
        Ok(_) => panic!("detector failure must be returned"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains(secret));
}

struct ValueDerivedKindDetector;

impl Detector for ValueDerivedKindDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        Ok(vec![Entity {
            kind: "alice".to_owned(),
            start: 0,
            end: input.len(),
            value: input.to_owned(),
            confidence: 1.0,
        }])
    }
}

#[test]
fn simulation_rejects_value_derived_entity_kinds() {
    let planner = PolicyPlanner::new(Box::new(ValueDerivedKindDetector), Box::new(DefaultPolicy));
    let secret = "alice@example.com";
    let error = match planner.explain(secret, &ProcessingContext::default()) {
        Ok(_) => panic!("a value-derived kind must not be returned as explanation metadata"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains(secret));
    assert!(!error.to_string().contains("alice"));
}

struct GenericPolicy;

impl Policy for GenericPolicy {
    fn plan(
        &self,
        entities: &[Entity],
        _judgments: &[Judgment],
        _context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        Ok(entities
            .iter()
            .cloned()
            .map(|entity| PlannedEntity {
                entity,
                action: Action::Keep,
            })
            .collect())
    }
}

#[test]
fn custom_policy_gets_only_generic_reason_metadata() {
    let planner = PolicyPlanner::new(Box::new(RegexDetector), Box::new(GenericPolicy));
    let decisions = match planner.explain("alice@example.com", &ProcessingContext::default()) {
        Ok(decisions) => decisions,
        Err(error) => panic!("unexpected simulation error: {error}"),
    };
    assert_eq!(decisions[0].reason_code, ReasonCode::CustomPolicyPlan);
    assert_eq!(decisions[0].matched_rule, None);
    assert!(!decisions[0].used_default);
}

struct ContextErrorPolicy;

impl Policy for ContextErrorPolicy {
    fn plan(
        &self,
        _entities: &[Entity],
        _judgments: &[Judgment],
        context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        Err(PolicyError::Message(format!(
            "failure for {:?} {:?}",
            context.purpose, context.jurisdiction
        )))
    }
}

#[test]
fn simulation_scrubs_purpose_and_jurisdiction_from_policy_errors() {
    let planner = PolicyPlanner::new(Box::new(RegexDetector), Box::new(ContextErrorPolicy));
    let context = ProcessingContext {
        purpose: Some("sensitive-purpose".to_owned()),
        jurisdiction: Some("XY".to_owned()),
        ..ProcessingContext::default()
    };
    let error = match planner.explain("alice@example.com", &context) {
        Ok(_) => panic!("policy failure must be returned"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains("sensitive-purpose"));
    assert!(!error.to_string().contains("XY"));
}
