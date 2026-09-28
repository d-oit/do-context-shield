use super::*;

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
    assert!(
        result.text.starts_with("__DO_PRIVATE_EMAIL_1_"),
        "{result:?}"
    );
}

#[test]
fn low_confidence_judgment_is_not_trusted() {
    let mut pipeline = judged(FixedJudge(Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Test,
        confidence: 0.5,
    }));
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert!(
        result.text.starts_with("__DO_PRIVATE_EMAIL_1_"),
        "{result:?}"
    );
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
