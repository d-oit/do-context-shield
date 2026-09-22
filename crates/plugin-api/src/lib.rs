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
    /// Reject the entire input; the pipeline returns an error, not sanitized text.
    Block,
    /// Flag for human review; the pipeline treats this as [`Action::Block`] until
    /// a review flow exists.
    Review,
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

mod context;

pub use context::{DataCategory, ProcessingContext, RecipientClass};

/// Detector failures.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Detector configuration or runtime error.
    ///
    /// The text is surfaced to callers; it must not embed raw input or
    /// original values. The pipeline scrubs the values it knows, but the
    /// contract belongs to the plugin.
    #[error("detector error: {0}")]
    Message(String),
}

/// Policy failures.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy configuration or runtime error.
    ///
    /// The text is surfaced to callers; it must not embed raw input or
    /// original values. The pipeline scrubs the values it knows, but the
    /// contract belongs to the plugin.
    #[error("policy error: {0}")]
    Message(String),
}

/// Transformer failures.
#[derive(Debug, Error)]
pub enum TransformError {
    /// Transformation failure.
    ///
    /// The text is surfaced to callers; it must not embed raw input or
    /// original values. The pipeline scrubs the values it knows, but the
    /// contract belongs to the plugin.
    #[error("transform error: {0}")]
    Message(String),
}

/// Vault failures.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Vault operation failure.
    ///
    /// The text is surfaced to callers; it must not embed raw input or
    /// original values. The pipeline scrubs the values it knows, but the
    /// contract belongs to the plugin.
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
    /// `judgments` is empty when no semantic judge is configured; every index
    /// has already been validated against `entities`. `context` carries the
    /// enforcement context (recipient trust, data category, purpose, and
    /// jurisdiction) the policy may consult.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when planning fails.
    fn plan(
        &self,
        entities: &[Entity],
        judgments: &[Judgment],
        context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError>;
}

/// Classify detected candidates semantically without producing text or spans.
///
/// A judge may abstain per candidate; it can never invent spans, rewrite text,
/// or weaken secret redaction (the policy redacts secret-like kinds first).
pub trait SemanticJudge: Send + Sync {
    /// Return one decision per candidate the judge is willing to label.
    ///
    /// # Errors
    ///
    /// Returns [`JudgeError`] when judging fails; the pipeline then fails the
    /// call instead of passing text through.
    fn judge(&self, input: &str, entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError>;
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

    /// Delete every mapping and counter for a session scope.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the deletion cannot be completed. Vaults
    /// that cannot delete state keep the default no-op, so a caller that never
    /// deletes a scope is unaffected.
    fn delete_scope(&mut self, _scope: &ScopeId) -> Result<(), VaultError> {
        Ok(())
    }

    /// Remove expired mappings.
    ///
    /// Called by the pipeline or a background tick. Vaults without a lifetime
    /// policy keep the default no-op.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when cleanup cannot be completed.
    fn expire(&mut self) -> Result<(), VaultError> {
        Ok(())
    }
}

/// Whether `token` has the `__DO_PRIVATE_<INNER>__` placeholder shape that
/// the pipeline's `restore` resolves through a vault.
///
/// `<INNER>` must be non-empty and ASCII alphanumeric or `_`, so
/// `__DO_PRIVATE_EMAIL_1_9F3A2C7B5D1E4F08__` and `__DO_PRIVATE_REDACTED__`
/// qualify.
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

/// Mint a fresh placeholder token for one mapping.
///
/// The token carries an unguessable 64-bit suffix, so tokens cannot be
/// enumerated from other tokens of the same scope and a fabricated
/// `__DO_PRIVATE_*__` string — in a model reply, say — does not resolve to a
/// stored value. Stability is the vault's job: the same `(scope, kind,
/// original)` mapping keeps returning the token minted on its first insert.
///
/// # Errors
///
/// Returns [`VaultError`] when the system entropy source is unavailable; the
/// vault must fail the insert rather than mint a predictable token.
pub fn mint_placeholder(kind: &str, counter: u64) -> Result<String, VaultError> {
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|error| {
        VaultError::Message(format!(
            "cannot obtain entropy for a placeholder token ({error})"
        ))
    })?;
    let entropy = u64::from_be_bytes(suffix);
    Ok(format!(
        "__DO_PRIVATE_{}_{counter}_{entropy:016X}__",
        kind.to_ascii_uppercase()
    ))
}

/// Whether `kind` names a credential that must be redacted, never pseudonymized.
#[must_use]
pub fn is_secret_kind(kind: &str) -> bool {
    kind.contains("key")
        || kind.contains("secret")
        || kind == "password"
        || kind == "github_token"
        || kind == "slack_token"
        || kind == "jwt"
}

/// Semantic role assigned by a judge to one detected candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SemanticLabel {
    /// Private individual data.
    Personal,
    /// A service or role address behind a business function, e.g. `support@`.
    Business,
    /// A documentation, fixture, or reserved-domain value, e.g. `example.com`.
    Test,
    /// A credential or secret-like value.
    Secret,
}

impl SemanticLabel {
    /// Lowercase name used by the process protocol.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Business => "business",
            Self::Test => "test",
            Self::Secret => "secret",
        }
    }

    /// Parse a process-protocol label name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "personal" => Some(Self::Personal),
            "business" => Some(Self::Business),
            "test" => Some(Self::Test),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// One judge decision for one detected candidate.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum Judgment {
    /// The judge selected `label` for the candidate at `index`.
    Labeled {
        /// Position of the candidate in the entity list handed to the judge.
        index: usize,
        /// Selected semantic label.
        label: SemanticLabel,
        /// Judge confidence for the label, in `0..=1`.
        confidence: f32,
    },
    /// The judge declined to classify the candidate at `index`.
    Abstain {
        /// Position of the candidate in the entity list handed to the judge.
        index: usize,
    },
}

impl Judgment {
    /// Candidate index this judgment refers to.
    #[must_use]
    pub fn index(&self) -> usize {
        match self {
            Self::Labeled { index, .. } | Self::Abstain { index } => *index,
        }
    }
}

/// Judge failures.
#[derive(Debug, Error)]
pub enum JudgeError {
    /// Judge configuration or runtime error.
    ///
    /// The text is surfaced to callers; it must not embed raw input or
    /// original values. The pipeline scrubs the values it knows, but the
    /// contract belongs to the plugin.
    #[error("judge error: {0}")]
    Message(String),
    /// A judgment referenced a candidate index outside the candidate list.
    #[error("judge index {index} is out of range for {len} candidates")]
    IndexOutOfRange {
        /// Reported index.
        index: usize,
        /// Number of candidates the judge was given.
        len: usize,
    },
    /// A judgment repeated a candidate index.
    #[error("judge repeated candidate index {index}")]
    DuplicateIndex {
        /// Repeated index.
        index: usize,
    },
    /// A judgment carried a confidence outside `0..=1`.
    #[error("judge confidence {confidence} for index {index} is outside 0..=1")]
    ConfidenceOutOfRange {
        /// Reported index.
        index: usize,
        /// Reported confidence.
        confidence: f32,
    },
}

/// Validate a judge's output against the candidate list it was given.
///
/// Candidates without a judgment are abstentions and are allowed; indices must
/// be in range and unique, and a label's confidence must be in `0..=1`.
///
/// # Errors
///
/// Returns [`JudgeError::IndexOutOfRange`], [`JudgeError::DuplicateIndex`], or
/// [`JudgeError::ConfidenceOutOfRange`] for a malformed response.
pub fn validate_judgments(len: usize, judgments: &[Judgment]) -> Result<(), JudgeError> {
    for (position, judgment) in judgments.iter().enumerate() {
        let index = judgment.index();
        if index >= len {
            return Err(JudgeError::IndexOutOfRange { index, len });
        }
        if judgments[..position]
            .iter()
            .any(|earlier| earlier.index() == index)
        {
            return Err(JudgeError::DuplicateIndex { index });
        }
        if let Judgment::Labeled {
            index, confidence, ..
        } = judgment
            && !(0.0..=1.0).contains(confidence)
        {
            return Err(JudgeError::ConfidenceOutOfRange {
                index: *index,
                confidence: *confidence,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_placeholder_token, is_secret_kind, mint_placeholder};

    #[test]
    fn minted_tokens_are_shaped_and_unguessable() {
        let first = match mint_placeholder("full_name", 1) {
            Ok(token) => token,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(is_placeholder_token(&first), "{first}");
        assert!(first.starts_with("__DO_PRIVATE_FULL_NAME_1_"), "{first}");
        let second = match mint_placeholder("full_name", 1) {
            Ok(token) => token,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_ne!(first, second, "each mapping mints its own entropy");
    }

    #[test]
    fn credential_kinds_are_secrets() {
        for kind in [
            "api_key",
            "aws_access_key",
            "generic_secret",
            "github_token",
            "google_api_key",
            "jwt",
            "password",
            "private_key",
            "slack_token",
        ] {
            assert!(is_secret_kind(kind), "{kind}");
        }
    }

    #[test]
    fn personal_kinds_are_not_secrets() {
        for kind in [
            "date_of_birth",
            "email",
            "passport",
            "phone",
            "us_bank_routing",
            "us_drivers_license",
        ] {
            assert!(!is_secret_kind(kind), "{kind}");
        }
    }
}
