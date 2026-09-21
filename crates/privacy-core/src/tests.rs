use super::*;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{Judgment, Mapping, PlannedEntity, SemanticLabel};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;

fn context() -> ProcessingContext {
    ProcessingContext::default()
}

fn pipeline() -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    )
}

#[test]
fn sanitize_preserves_repeated_identity() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let result = match pipeline.sanitize(
        &scope,
        "mail alice@example.com then alice@example.com",
        &context(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(result.text.matches("__DO_PRIVATE_EMAIL_1__").count(), 2);
    assert!(!result.text.contains("alice@example.com"));
}

#[test]
fn restore_is_scope_limited() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let other = ScopeId("other".to_owned());
    let result = match pipeline.sanitize(&scope, "alice@example.com", &context()) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let restored = match pipeline.restore(&scope, &result.text) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let blocked = match pipeline.restore(&other, &result.text) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(restored, "alice@example.com");
    assert_eq!(blocked, result.text);
}

#[test]
fn restore_skips_malformed_placeholders_and_keeps_scanning() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let result = match pipeline.sanitize(&scope, "alice@example.com", &context()) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let adversarial = format!("__DO_PRIVATE_ junk __DO_PRIVATE_ {}", result.text);
    let restored = match pipeline.restore(&scope, &adversarial) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(restored.contains("alice@example.com"));
    assert!(restored.contains("__DO_PRIVATE_ junk __DO_PRIVATE_ "));
}

#[test]
fn restore_leaves_redacted_and_truncated_tokens_untouched() {
    let pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    for input in [
        "__DO_PRIVATE_REDACTED__",
        "prefix __DO_PRIVATE_",
        "__DO_PRIVATE___",
    ] {
        match pipeline.restore(&scope, input) {
            Ok(output) => assert_eq!(output, input),
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}

struct FixedJudge(Judgment);

impl SemanticJudge for FixedJudge {
    fn judge(&self, _input: &str, _entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        Ok(vec![self.0])
    }
}

struct PairJudge(Judgment, Judgment);

impl SemanticJudge for PairJudge {
    fn judge(&self, _input: &str, _entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        Ok(vec![self.0, self.1])
    }
}

struct BrokenJudge;

impl SemanticJudge for BrokenJudge {
    fn judge(&self, _input: &str, _entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        Err(JudgeError::Message("boom".to_owned()))
    }
}

fn judged(judge: impl SemanticJudge + 'static) -> PrivacyPipeline {
    pipeline().with_judge(Box::new(judge))
}

fn sanitize_ok(pipeline: &mut PrivacyPipeline, input: &str) -> SanitizeResult {
    match pipeline.sanitize(&ScopeId("test".to_owned()), input, &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn sanitize_err(pipeline: &mut PrivacyPipeline, input: &str) -> PipelineError {
    match pipeline.sanitize(&ScopeId("test".to_owned()), input, &context()) {
        Ok(result) => panic!("expected an error, got {result:?}"),
        Err(error) => error,
    }
}

#[test]
fn judge_labels_flow_into_policy() {
    let mut pipeline = judged(FixedJudge(Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Test,
        confidence: 0.95,
    }));
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert_eq!(result.text, "alice@example.com");
    assert_eq!(result.entities.len(), 1);
}

#[test]
fn abstaining_judge_falls_back_to_the_kind_rules() {
    let mut pipeline = judged(FixedJudge(Judgment::Abstain { index: 0 }));
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert!(result.text.contains("__DO_PRIVATE_EMAIL_1__"), "{result:?}");
}

#[test]
fn low_confidence_judgment_is_not_trusted() {
    let mut pipeline = judged(FixedJudge(Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Test,
        confidence: 0.5,
    }));
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert!(result.text.contains("__DO_PRIVATE_EMAIL_1__"), "{result:?}");
}

#[test]
fn secret_kind_is_redacted_even_when_judge_says_test() {
    let mut pipeline = judged(FixedJudge(Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Test,
        confidence: 0.95,
    }));
    let fixture = format!("sk-test-{}", "0123456789abcdef");
    let result = sanitize_ok(&mut pipeline, &fixture);
    assert!(
        result.text.contains("__DO_PRIVATE_REDACTED__"),
        "{result:?}"
    );
}

#[test]
fn judge_failure_fails_closed() {
    let mut pipeline = judged(BrokenJudge);
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Judge(_)), "{error:?}");
}

#[test]
fn out_of_range_judgment_fails_closed() {
    let mut pipeline = judged(FixedJudge(Judgment::Labeled {
        index: 7,
        label: SemanticLabel::Personal,
        confidence: 0.9,
    }));
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(
        matches!(
            error,
            PipelineError::Judge(JudgeError::IndexOutOfRange { index: 7, .. })
        ),
        "{error:?}"
    );
}

#[test]
fn duplicate_judgment_fails_closed() {
    let mut pipeline = judged(PairJudge(
        Judgment::Abstain { index: 0 },
        Judgment::Abstain { index: 0 },
    ));
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(
        matches!(
            error,
            PipelineError::Judge(JudgeError::DuplicateIndex { index: 0 })
        ),
        "{error:?}"
    );
}

struct FixedDetector(Vec<Entity>);

impl Detector for FixedDetector {
    fn detect(&self, _input: &str) -> Result<Vec<Entity>, DetectorError> {
        Ok(self.0.clone())
    }
}

fn entity(kind: &str, start: usize, end: usize, value: &str) -> Entity {
    Entity {
        kind: kind.to_owned(),
        start,
        end,
        value: value.to_owned(),
        confidence: 1.0,
    }
}

fn with_detector(entities: Vec<Entity>) -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(FixedDetector(entities)),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    )
}

#[test]
fn bad_utf8_boundary_fails_closed() {
    // "grüße": byte 3 is inside the two-byte `ü`.
    let mut pipeline = with_detector(vec![entity("person", 3, 7, "e")]);
    let error = sanitize_err(&mut pipeline, "grüße");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(
        error.to_string().contains("character boundaries"),
        "{error}"
    );
}

#[test]
fn tampered_value_fails_closed() {
    let mut pipeline = with_detector(vec![entity("email", 0, 5, "bob@x")]);
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("does not match"), "{error}");
}

#[test]
fn out_of_bounds_span_fails_closed() {
    let mut past_end = with_detector(vec![entity("email", 0, 18, "alice@example.com")]);
    let error = sanitize_err(&mut past_end, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");

    let mut reversed = with_detector(vec![entity("email", 5, 2, "x")]);
    let error = sanitize_err(&mut reversed, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("out of bounds"), "{error}");
}

#[test]
fn empty_kind_fails_closed() {
    // A malformed model label can canonicalize to an empty kind; the pipeline
    // rejects it instead of letting an untyped entity reach policy decisions.
    let mut pipeline = with_detector(vec![entity("  ", 0, 5, "alice")]);
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("empty kind"), "{error}");
}

#[test]
fn confidence_out_of_range_fails_closed() {
    let mut too_high = with_detector(vec![Entity {
        confidence: 1.5,
        ..entity("email", 0, 5, "alice")
    }]);
    let error = sanitize_err(&mut too_high, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("outside 0..=1"), "{error}");

    // NaN compares false against every bound, so it must be rejected too.
    let mut not_a_number = with_detector(vec![Entity {
        confidence: f32::NAN,
        ..entity("email", 0, 5, "alice")
    }]);
    let error = sanitize_err(&mut not_a_number, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
}

struct LeakingDetector;

impl Detector for LeakingDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        Err(DetectorError::Message(format!("cannot parse `{input}`")))
    }
}

#[test]
fn leaking_detector_error_is_scrubbed() {
    let mut pipeline = PrivacyPipeline::new(
        Box::new(LeakingDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    let text = error.to_string();
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
}

struct LeakingJudge;

impl SemanticJudge for LeakingJudge {
    fn judge(&self, _input: &str, entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        let value = entities
            .first()
            .map_or("nothing", |entity| entity.value.as_str());
        Err(JudgeError::Message(format!("cannot classify `{value}`")))
    }
}

#[test]
fn leaking_judge_error_is_scrubbed() {
    // The judge echoes a detected value, not the whole input, so only the
    // entity-value scrub can hide it.
    let mut pipeline = pipeline().with_judge(Box::new(LeakingJudge));
    let error = sanitize_err(&mut pipeline, "contact alice@example.com");
    let text = error.to_string();
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
}

struct LeakingVault;

impl Vault for LeakingVault {
    fn get_or_insert(
        &mut self,
        _scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        Err(VaultError::Message(format!(
            "cannot store `{original}` as {kind}"
        )))
    }

    fn resolve(&self, _scope: &ScopeId, _token: &str) -> Result<Option<Mapping>, VaultError> {
        Ok(None)
    }
}

#[test]
fn leaking_vault_error_is_scrubbed() {
    let mut pipeline = PrivacyPipeline::new(
        Box::new(FixedDetector(vec![entity(
            "email",
            8,
            25,
            "alice@example.com",
        )])),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(LeakingVault),
    );
    let error = sanitize_err(&mut pipeline, "contact alice@example.com");
    let text = error.to_string();
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
}

#[test]
fn overlapping_spans_resolved_to_longest() {
    let mut pipeline = with_detector(vec![
        entity("person", 0, 5, "alice"),
        entity("email", 0, 17, "alice@example.com"),
    ]);
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert_eq!(result.entities.len(), 1, "{result:?}");
    assert_eq!(result.entities[0].kind, "email");
    assert!(result.text.contains("__DO_PRIVATE_EMAIL_1__"), "{result:?}");
    assert!(!result.text.contains("PERSON"), "{result:?}");
}

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

#[test]
fn block_action_fails_pipeline() {
    for action in [Action::Block, Action::Review] {
        let mut pipeline = PrivacyPipeline::new(
            Box::new(RegexDetector),
            Box::new(FixedActionPolicy(action)),
            Box::new(PseudonymizingTransformer),
            Box::new(MemoryVault::default()),
        );
        let error = sanitize_err(&mut pipeline, "alice@example.com");
        assert!(matches!(error, PipelineError::Policy(_)), "{error:?}");
        assert!(error.to_string().contains("blocked by policy"), "{error}");
    }
}

#[test]
fn forget_removes_session_mappings() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let other = ScopeId("other".to_owned());
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    let other_result = match pipeline.sanitize(&other, "bob@example.com", &context()) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };

    match pipeline.forget(&scope) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    match pipeline.restore(&scope, &result.text) {
        Ok(restored) => assert_eq!(restored, result.text),
        Err(error) => panic!("unexpected error: {error}"),
    }
    match pipeline.restore(&other, &other_result.text) {
        Ok(restored) => assert_eq!(restored, "bob@example.com"),
        Err(error) => panic!("unexpected error: {error}"),
    }
}
