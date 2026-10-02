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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Leave the value unchanged.
    Keep,
    /// Replace it with a reversible pseudonym.
    Pseudonymize,
    /// Remove the value irreversibly.
    Redact,
    /// Reject the entire input; the pipeline returns an error, not sanitized text.
    Block,
}

impl Action {
    /// Lowercase name used by the process protocol and the audit log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keep => "keep",
            Self::Pseudonymize => "pseudonymize",
            Self::Redact => "redact",
            Self::Block => "block",
        }
    }
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

mod audit;
mod context;
mod placeholder;
mod secret;
mod spans;
mod traits;

pub use audit::{
    ActionCount, AuditContext, AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink,
};
pub use context::{DataCategory, ProcessingContext, RecipientClass, is_valid_jurisdiction};
pub use placeholder::{
    is_minted_placeholder_token, is_placeholder_token, is_valid_placeholder_kind, mint_placeholder,
};
pub use secret::is_secret_kind;
pub use spans::resolve_overlaps;
pub use traits::{
    Detector, JudgeError, Judgment, Policy, SemanticJudge, SemanticLabel, Transformer, Vault,
    validate_judgments,
};

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

#[cfg(test)]
mod tests {
    use super::{
        is_minted_placeholder_token, is_placeholder_token, is_valid_placeholder_kind,
        mint_placeholder,
    };

    #[test]
    fn minted_tokens_are_shaped_and_unguessable() {
        let first = match mint_placeholder("full_name", 1) {
            Ok(token) => token,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(is_placeholder_token(&first), "{first}");
        assert!(is_minted_placeholder_token(&first), "{first}");
        assert!(first.starts_with("__DO_PRIVATE_FULL_NAME_1_"), "{first}");
        let second = match mint_placeholder("full_name", 1) {
            Ok(token) => token,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_ne!(first, second, "each mapping mints its own entropy");
    }

    #[test]
    fn invalid_kinds_cannot_be_minted() {
        for kind in ["email__x", "email-address", "ü-email", "_email", "email_"] {
            assert!(
                mint_placeholder(kind, 1).is_err(),
                "kind `{kind}` must not produce an unrestorable token"
            );
        }
        assert!(!is_placeholder_token("__DO_PRIVATE_EMAIL__X__"));
        assert!(is_placeholder_token("__DO_PRIVATE_REDACTED__"));
        assert!(!is_minted_placeholder_token("__DO_PRIVATE_EMAIL_1__"));
    }

    #[test]
    fn placeholder_kinds_are_validated_for_shape() {
        for kind in ["email", "full_name", "card_cvv", "apiKey2"] {
            assert!(is_valid_placeholder_kind(kind), "{kind}");
        }
        for kind in [
            "",
            "email__x",
            "_email",
            "email_",
            "email-address",
            "ü-email",
        ] {
            assert!(!is_valid_placeholder_kind(kind), "{kind}");
        }
    }
}
