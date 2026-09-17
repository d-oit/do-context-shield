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
            if is_token_shape(&output[start..end]) {
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
    /// # Errors
    ///
    /// Returns [`PipelineError`] when detection fails.
    pub fn inspect(&self, input: &str) -> Result<Vec<Entity>, PipelineError> {
        Ok(self.detector.detect(input)?)
    }
}

/// Check a candidate placeholder has the `__DO_PRIVATE_<KIND>_<N>__` shape
/// (or the fixed redacted token) before vault resolution.
fn is_token_shape(token: &str) -> bool {
    let Some(inner) = token
        .strip_prefix("__DO_PRIVATE_")
        .and_then(|rest| rest.strip_suffix("__"))
    else {
        return false;
    };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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
}
