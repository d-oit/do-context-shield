//! Privacy pipeline independent of any LLM provider or agent runtime.

use do_context_shield_plugin_api::{
    Detector, DetectorError, Entity, Policy, PolicyError, ScopeId, TransformError, TransformResult,
    Transformer, Vault, VaultError,
};

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
}

/// Result of sanitization.
#[derive(Debug)]
pub struct SanitizeResult {
    /// Sanitized text.
    pub text: String,
    /// Detected entities.
    pub entities: Vec<Entity>,
    /// Stored reversible mappings.
    pub mappings: Vec<do_context_shield_plugin_api::Mapping>,
}

/// Composable privacy pipeline.
pub struct PrivacyPipeline {
    detector: Box<dyn Detector>,
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
            policy,
            transformer,
            vault,
        }
    }

    /// Detect and sanitize text in a session scope.
    pub fn sanitize(
        &mut self,
        scope: &ScopeId,
        input: &str,
    ) -> Result<SanitizeResult, PipelineError> {
        let entities = self.detector.detect(input)?;
        let plan = self.policy.plan(&entities)?;
        let TransformResult { text, mappings } =
            self.transformer
                .transform(input, &plan, scope, self.vault.as_mut())?;
        Ok(SanitizeResult {
            text,
            entities,
            mappings,
        })
    }

    /// Restore known placeholders in text.
    pub fn restore(&self, scope: &ScopeId, input: &str) -> Result<String, PipelineError> {
        let mut output = input.to_owned();
        let mut positions = Vec::new();
        let mut index = 0usize;
        while let Some(relative) = output[index..].find("__DO_PRIVATE_") {
            let start = index + relative;
            if start + 2 >= output.len() {
                break;
            }
            let Some(end_relative) = output[start + 2..].find("__") else {
                break;
            };
            let end = start + 2 + end_relative + 2;
            positions.push((start, end));
            index = end;
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
    pub fn inspect(&self, input: &str) -> Result<Vec<Entity>, PipelineError> {
        Ok(self.detector.detect(input)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use do_context_shield_detector_regex::RegexDetector;
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
}
