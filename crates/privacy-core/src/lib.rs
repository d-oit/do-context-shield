//! Privacy pipeline independent of any LLM provider or agent runtime.

use do_context_shield_plugin_api::{
    Detector, DetectorError, Entity, JudgeError, Policy, PolicyError, ScopeId, SemanticJudge,
    TransformError, TransformResult, Transformer, Vault, VaultError, is_placeholder_token,
    validate_judgments,
};
use serde::{Deserialize, Serialize};

/// Pipeline errors.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// Detector error.
    #[error(transparent)]
    Detector(#[from] DetectorError),
    /// Policy error.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Transformation error.
    #[error(transparent)]
    Transform(#[from] TransformError),
    /// Vault error.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// Judge error.
    #[error(transparent)]
    Judge(#[from] JudgeError),
}

/// Detected entity as disclosed outside the pipeline: kind, byte span, and confidence.
///
/// The matched text is deliberately absent so pipeline results, CLI output, and
/// MCP tool responses cannot echo raw values back into an agent context.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntitySummary {
    /// Stable kind name, e.g. `email` or `iban`.
    pub kind: String,
    /// Byte offset of the entity start.
    pub start: usize,
    /// Byte offset immediately after the entity.
    pub end: usize,
    /// Detector confidence in the range 0..=1.
    pub confidence: f32,
}

impl From<&Entity> for EntitySummary {
    fn from(entity: &Entity) -> Self {
        Self {
            kind: entity.kind.clone(),
            start: entity.start,
            end: entity.end,
            confidence: entity.confidence,
        }
    }
}

/// Result of sanitization.
#[derive(Debug)]
pub struct SanitizeResult {
    /// Sanitized text.
    pub text: String,
    /// Detected entities as raw-value-free summaries.
    pub entities: Vec<EntitySummary>,
}

/// Composable privacy pipeline.
pub struct PrivacyPipeline {
    detector: Box<dyn Detector>,
    judge: Option<Box<dyn SemanticJudge>>,
    policy: Box<dyn Policy>,
    transformer: Box<dyn Transformer>,
    vault: Box<dyn Vault>,
}

impl PrivacyPipeline {
    /// Create a pipeline from replaceable plugins.
    #[must_use]
    pub fn new(
        detector: Box<dyn Detector>,
        policy: Box<dyn Policy>,
        transformer: Box<dyn Transformer>,
        vault: Box<dyn Vault>,
    ) -> Self {
        Self {
            detector,
            judge: None,
            policy,
            transformer,
            vault,
        }
    }

    /// Attach an optional semantic judge between detection and policy.
    #[must_use]
    pub fn with_judge(mut self, judge: Box<dyn SemanticJudge>) -> Self {
        self.judge = Some(judge);
        self
    }

    /// Detect and sanitize text in a session scope.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when detection, planning, transformation, or storage fails.
    pub fn sanitize(
        &mut self,
        scope: &ScopeId,
        input: &str,
    ) -> Result<SanitizeResult, PipelineError> {
        let entities = self.detector.detect(input)?;
        let judgments = match &self.judge {
            Some(judge) => {
                let judgments = judge.judge(input, &entities)?;
                validate_judgments(entities.len(), &judgments)?;
                judgments
            }
            None => Vec::new(),
        };
        let plan = self.policy.plan(&entities, &judgments)?;
        let TransformResult { text, .. } =
            self.transformer
                .transform(input, &plan, scope, self.vault.as_mut())?;
        Ok(SanitizeResult {
            text,
            entities: entities.iter().map(EntitySummary::from).collect(),
        })
    }

    /// Restore known placeholders in text.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when vault resolution fails.
    pub fn restore(&self, scope: &ScopeId, input: &str) -> Result<String, PipelineError> {
        const PREFIX: &str = "__DO_PRIVATE_";
        let mut output = input.to_owned();
        let mut positions = Vec::new();
        let mut index = 0usize;
        while let Some(relative) = output[index..].find(PREFIX) {
            let start = index + relative;
            let after_prefix = start + PREFIX.len();
            let Some(rest) = output.get(after_prefix..) else {
                break;
            };
            let Some(end_relative) = rest.find("__") else {
                // No closing delimiter for this occurrence; skip past it.
                index = after_prefix;
                continue;
            };
            let end = after_prefix + end_relative + 2;
            // Byte indices land on ASCII boundaries, so slicing is safe.
            if is_placeholder_token(&output[start..end]) {
                positions.push((start, end));
                index = end;
            } else {
                // Malformed placeholder: advance by one so a nested valid
                // token (e.g. `__DO_PRIVATE_ __DO_PRIVATE_EMAIL_1__`)
                // is still found on rescan.
                index = start + 1;
            }
        }

        for (start, end) in positions.into_iter().rev() {
            let token = &output[start..end];
            if let Some(mapping) = self.vault.resolve(scope, token)? {
                output.replace_range(start..end, &mapping.original);
            }
        }
        Ok(output)
    }

    /// Get the detector's current findings without transforming.
    ///
    /// Findings carry kind, byte span, and confidence; the matched text is
    /// never returned.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when detection fails.
    pub fn inspect(&self, input: &str) -> Result<Vec<EntitySummary>, PipelineError> {
        Ok(self
            .detector
            .detect(input)?
            .iter()
            .map(EntitySummary::from)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use do_context_shield_detector_regex::RegexDetector;
    use do_context_shield_plugin_api::{Judgment, SemanticLabel};
    use do_context_shield_policy_default::DefaultPolicy;
    use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
    use do_context_shield_vault_memory::MemoryVault;

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
        let result =
            match pipeline.sanitize(&scope, "mail alice@example.com then alice@example.com") {
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
        let result = match pipeline.sanitize(&scope, "alice@example.com") {
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
        let result = match pipeline.sanitize(&scope, "alice@example.com") {
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
        match pipeline.sanitize(&ScopeId("test".to_owned()), input) {
            Ok(result) => result,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn sanitize_err(pipeline: &mut PrivacyPipeline, input: &str) -> PipelineError {
        match pipeline.sanitize(&ScopeId("test".to_owned()), input) {
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
}
