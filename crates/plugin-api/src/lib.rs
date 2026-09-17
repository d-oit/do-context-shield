//! Stable plugin contracts for `do-context-shield`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A logical session for reversible mappings.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ScopeId(pub String);

/// A detected entity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Stable kind name, e.g. `email` or `iban`.
    pub kind: String,
    /// Byte offset of the entity start.
    pub start: usize,
    /// Byte offset immediately after the entity.
    pub end: usize,
    /// Original matched text.
    pub value: String,
    /// Detector confidence in the range 0..=1.
    pub confidence: f32,
}

/// Action selected by a policy plugin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Leave the value unchanged.
    Keep,
    /// Replace it with a reversible pseudonym.
    Pseudonymize,
    /// Remove the value irreversibly.
    Redact,
}

/// Entity plus policy decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlannedEntity {
    /// Detected entity.
    pub entity: Entity,
    /// Transformation action.
    pub action: Action,
}

/// Result returned by a transformation plugin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformResult {
    /// Sanitized text.
    pub text: String,
    /// Reversible mappings generated during transformation.
    pub mappings: Vec<Mapping>,
}

/// A reversible mapping held by a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    /// Entity kind.
    pub kind: String,
    /// Original value.
    pub original: String,
    /// Replacement token.
    pub token: String,
}

/// Detector failures.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Detector configuration or runtime error.
    #[error("detector error: {0}")]
    Message(String),
}

/// Policy failures.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy configuration or runtime error.
    #[error("policy error: {0}")]
    Message(String),
}

/// Transformer failures.
#[derive(Debug, Error)]
pub enum TransformError {
    /// Transformation failure.
    #[error("transform error: {0}")]
    Message(String),
}

/// Vault failures.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Vault operation failure.
    #[error("vault error: {0}")]
    Message(String),
}

/// Detect sensitive entities in text.
pub trait Detector: Send + Sync {
    /// Return detected entities.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] when detection fails.
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError>;
}

/// Decide what should happen to each detected entity.
pub trait Policy: Send + Sync {
    /// Build transformation decisions.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when planning fails.
    fn plan(&self, entities: &[Entity]) -> Result<Vec<PlannedEntity>, PolicyError>;
}

/// Transform planned entities.
pub trait Transformer: Send + Sync {
    /// Produce sanitized text and any mappings that should be persisted.
    ///
    /// # Errors
    ///
    /// Returns [`TransformError`] when transformation fails.
    fn transform(
        &self,
        input: &str,
        plan: &[PlannedEntity],
        scope: &ScopeId,
        vault: &mut dyn Vault,
    ) -> Result<TransformResult, TransformError>;
}

/// Local reversible mapping store.
pub trait Vault: Send + Sync {
    /// Return an existing token or create and store a new mapping.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the mapping cannot be stored.
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError>;

    /// Resolve a token within a scope.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when resolution fails.
    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError>;
}

/// Whether `token` has the `__DO_PRIVATE_<INNER>__` placeholder shape that
/// the pipeline's `restore` resolves through a vault.
///
/// `<INNER>` must be non-empty and ASCII alphanumeric or `_`, so
/// `__DO_PRIVATE_EMAIL_1__` and `__DO_PRIVATE_REDACTED__` qualify.
#[must_use]
pub fn is_placeholder_token(token: &str) -> bool {
    let Some(inner) = token
        .strip_prefix("__DO_PRIVATE_")
        .and_then(|rest| rest.strip_suffix("__"))
    else {
        return false;
    };
    !inner.is_empty() && inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
