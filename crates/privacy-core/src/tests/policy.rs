//! Policy plan enforcement: one decision per entity, same span, secrets redacted.

use super::*;

struct FixedActionPolicy(Action);

impl Policy for FixedActionPolicy {
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
                action: self.0.clone(),
            })
            .collect())
    }
}

/// A policy that answers every call with one fixed plan, whatever it was given.
struct FixedPlanPolicy(Vec<PlannedEntity>);

impl Policy for FixedPlanPolicy {
    fn plan(
        &self,
        _entities: &[Entity],
        _judgments: &[Judgment],
        _context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        Ok(self.0.clone())
    }
}

/// Pipeline with `policy` over the real regex detector.
fn with_policy(policy: impl Policy + 'static) -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(policy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    )
}

#[test]
fn block_action_fails_pipeline() {
    let mut pipeline = with_policy(FixedActionPolicy(Action::Block));
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Policy(_)), "{error:?}");
    assert!(error.to_string().contains("blocked by policy"), "{error}");
}

#[test]
fn short_plan_fails_closed() {
    // A dropped decision would leave the entity undecided and its raw value in
    // the sanitized output.
    let mut pipeline = with_policy(FixedPlanPolicy(Vec::new()));
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Policy(_)), "{error:?}");
    assert!(
        error.to_string().contains("0 decisions for 1 entities"),
        "{error}"
    );
}

#[test]
fn substituted_decision_fails_closed() {
    // The plan must describe the entity the policy was given, not another span.
    let mut pipeline = with_policy(FixedPlanPolicy(vec![PlannedEntity {
        entity: entity("email", 5, 17, "example.com"),
        action: Action::Pseudonymize,
    }]));
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Policy(_)), "{error:?}");
    assert!(error.to_string().contains("does not match"), "{error}");
}

#[test]
fn reversible_action_on_secret_fails_closed() {
    // Synthetic fixture built programmatically so no secret-like literal is
    // committed. Keep would emit the credential raw; pseudonymize would store
    // it in a reversible vault mapping.
    let api_key = format!("sk-test-{}", "0123456789abcdef");
    for action in [Action::Keep, Action::Pseudonymize] {
        let mut pipeline = with_policy(FixedActionPolicy(action));
        let error = sanitize_err(&mut pipeline, &api_key);
        assert!(matches!(error, PipelineError::Policy(_)), "{error:?}");
        assert!(
            error.to_string().contains("must be redacted: api_key"),
            "{error}"
        );
    }
}
