//! Privacy pipeline independent of any LLM provider or agent runtime.

use do_context_shield_plugin_api::{
    Action, Detector, DetectorError, Entity, JudgeError, Policy, PolicyError, ProcessingContext,
    ScopeId, SemanticJudge, TransformError, TransformResult, Transformer, Vault, VaultError,
    is_placeholder_token, validate_judgments,
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

    /// Detect and sanitize text in a session scope under an enforcement context.
    ///
    /// Detector output is validated (character boundaries, bounds, value
    /// match, overlaps) before the judge and policy see it. A plan containing
    /// [`Action::Block`] or [`Action::Review`] fails the call instead of
    /// producing text.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when detection, validation, planning,
    /// transformation, or storage fails.
    pub fn sanitize(
        &mut self,
        scope: &ScopeId,
        input: &str,
        context: &ProcessingContext,
    ) -> Result<SanitizeResult, PipelineError> {
        let entities = validate_spans(input, &self.detector.detect(input)?)?;
        let judgments = match &self.judge {
            Some(judge) => {
                let judgments = judge.judge(input, &entities)?;
                validate_judgments(entities.len(), &judgments)?;
                judgments
            }
            None => Vec::new(),
        };
        let plan = self.policy.plan(&entities, &judgments, context)?;
        if plan
            .iter()
            .any(|planned| matches!(planned.action, Action::Block | Action::Review))
        {
            return Err(PipelineError::Policy(PolicyError::Message(
                "input blocked by policy".to_owned(),
            )));
        }
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

    /// Delete every mapping stored for a session scope.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Vault`] when the vault cannot delete the scope.
    pub fn forget(&mut self, scope: &ScopeId) -> Result<(), PipelineError> {
        self.vault.delete_scope(scope)?;
        Ok(())
    }

    /// Drop expired vault mappings. Vaults without a lifetime policy no-op, so
    /// a long-running caller can invoke this on every request.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Vault`] when cleanup fails.
    pub fn expire_vault(&mut self) -> Result<(), PipelineError> {
        self.vault.expire()?;
        Ok(())
    }
}

/// Validate detector output before the judge and policy see it.
///
/// Every entity must carry a non-empty kind and a confidence in `0..=1`, and
/// every span must fall on UTF-8 character boundaries, stay within the input,
/// and carry the value the input actually holds at that span. Overlaps are
/// resolved longest-span-wins: entities are ordered by start (widest first)
/// and any entity overlapping an already-kept one is dropped, so the
/// transformer never sees overlapping ranges.
fn validate_spans(input: &str, entities: &[Entity]) -> Result<Vec<Entity>, PipelineError> {
    let mut validated = Vec::with_capacity(entities.len());
    for entity in entities {
        if !input.is_char_boundary(entity.start) || !input.is_char_boundary(entity.end) {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} is not on character boundaries",
                entity.start, entity.end
            ))));
        }
        if entity.end > input.len() || entity.start > entity.end {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} is out of bounds for input of length {}",
                entity.start,
                entity.end,
                input.len()
            ))));
        }
        if input.get(entity.start..entity.end) != Some(entity.value.as_str()) {
            return Err(PipelineError::Detector(DetectorError::Message(
                "entity value does not match the input at the declared span".to_owned(),
            )));
        }
        if entity.kind.trim().is_empty() {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity span {}..{} carries an empty kind",
                entity.start, entity.end
            ))));
        }
        if !(0.0..=1.0).contains(&entity.confidence) {
            return Err(PipelineError::Detector(DetectorError::Message(format!(
                "entity confidence {} for kind `{}` is outside 0..=1",
                entity.confidence, entity.kind
            ))));
        }
        validated.push(entity.clone());
    }

    validated.sort_by_key(|entity| (entity.start, std::cmp::Reverse(entity.end)));
    let mut deduped: Vec<Entity> = Vec::with_capacity(validated.len());
    for entity in validated {
        if deduped
            .iter()
            .any(|kept| entity.start < kept.end && kept.start < entity.end)
        {
            continue;
        }
        deduped.push(entity);
    }
    deduped.sort_by_key(|entity| (entity.start, entity.end));
    Ok(deduped)
}

#[cfg(test)]
mod tests;
