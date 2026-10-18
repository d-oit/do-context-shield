//! Stage contracts and their shared validation.
//!
//! A detector, policy, judge, transformer, and vault each sit behind one of
//! these traits; the pipeline validates every stage's output before the next
//! stage sees it.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DetectorError, Entity, Mapping, PlannedEntity, PolicyError, ProcessingContext, ScopeId,
    TransformError, TransformResult, VaultError,
};

/// Detect sensitive entities in text.
///
/// A detector may report overlapping candidates; [`resolve_overlaps`](crate::resolve_overlaps)
/// applies the shared longest-span-wins rule, and the pipeline re-validates the
/// result before the judge and policy see it.
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

    /// Return or create one mapping per `(kind, original)` item, in order.
    ///
    /// The default implementation calls [`Vault::get_or_insert`] once per
    /// item, so every vault keeps working unchanged. An override exists to
    /// avoid one authoritative write per item (see `vault-json`), and MUST
    /// treat the whole list as one snapshot of the vault: items repeated
    /// within the call resolve to the same mapping, and a deletion performed
    /// between two calls (including by another process) must be visible to the
    /// second one, so state is re-read per call and never cached across calls.
    ///
    /// A batch that fails may leave the vault without any of the call's
    /// mappings: the trait makes no atomicity promise, but an override should
    /// prefer persisting once at the end over partial writes.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when any mapping cannot be stored.
    fn get_or_insert_many(
        &mut self,
        scope: &ScopeId,
        items: &[(&str, &str)],
    ) -> Result<Vec<Mapping>, VaultError> {
        let mut mappings = Vec::with_capacity(items.len());
        for (kind, original) in items {
            mappings.push(self.get_or_insert(scope, kind, original)?);
        }
        Ok(mappings)
    }

    /// Resolve a token within a scope.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when resolution fails.
    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError>;

    /// Resolve many tokens within a scope, in the order given.
    ///
    /// The default implementation calls [`Vault::resolve`] once per token, so
    /// every vault keeps working unchanged. An override exists to avoid one
    /// authoritative read per token (see `vault-json`), and MUST resolve the
    /// whole list against one snapshot of the vault: callers treat the result
    /// as the state at the time of the call. Cross-call caching is forbidden —
    /// a deletion performed between two calls (including by another process)
    /// must be visible to the second one, which is why the snapshot must be
    /// re-read per call rather than remembered.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when resolution fails.
    fn resolve_many(
        &self,
        scope: &ScopeId,
        tokens: &[&str],
    ) -> Result<Vec<Option<Mapping>>, VaultError> {
        tokens
            .iter()
            .map(|token| self.resolve(scope, token))
            .collect()
    }

    /// Delete every mapping and counter for a session scope.
    ///
    /// `forget` is a revocation, so a vault must either remove the scope's
    /// mappings and counters or report that it cannot. A vault that keeps
    /// state it never deletes inherits this default, which fails instead of
    /// silently acknowledging a deletion that did not happen — a false
    /// success would leave resolvable originals behind.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the deletion cannot be completed; every
    /// vault without deletion support always fails.
    fn delete_scope(&mut self, _scope: &ScopeId) -> Result<(), VaultError> {
        Err(VaultError::Message(
            "vault does not support scope deletion".to_owned(),
        ))
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
    use super::{JudgeError, Judgment, SemanticLabel, validate_judgments};
    use crate::{Mapping, ScopeId, Vault, VaultError};

    /// Vault that implements only the required methods, so the trait defaults
    /// under test are the ones that run.
    struct Stub;

    impl Vault for Stub {
        fn get_or_insert(
            &mut self,
            _scope: &ScopeId,
            kind: &str,
            original: &str,
        ) -> Result<Mapping, VaultError> {
            Ok(Mapping {
                kind: kind.to_owned(),
                original: original.to_owned(),
                token: format!("tok-{original}"),
            })
        }

        fn resolve(&self, _scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
            Ok(token.strip_prefix("tok-").map(|original| Mapping {
                kind: "email".to_owned(),
                original: original.to_owned(),
                token: token.to_owned(),
            }))
        }
    }

    fn scope() -> ScopeId {
        ScopeId("s".to_owned())
    }

    #[test]
    fn default_batch_insert_keeps_length_and_order() {
        let mut vault = Stub;
        let items = [("email", "a@example.com"), ("phone", "555")];
        match vault.get_or_insert_many(&scope(), &items) {
            Ok(mappings) => {
                assert_eq!(mappings.len(), 2);
                assert_eq!(mappings[0].original, "a@example.com");
                assert_eq!(mappings[1].original, "555");
                assert_eq!(mappings[1].kind, "phone");
            }
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn default_batch_resolve_is_per_token_and_ordered() {
        let vault = Stub;
        match vault.resolve_many(&scope(), &["tok-a@example.com", "unknown"]) {
            Ok(resolved) => {
                assert_eq!(resolved.len(), 2);
                assert_eq!(
                    resolved[0]
                        .as_ref()
                        .map(|mapping| mapping.original.as_str()),
                    Some("a@example.com")
                );
                assert!(resolved[1].is_none());
            }
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn default_scope_deletion_fails_instead_of_acknowledging() {
        let mut vault = Stub;
        assert!(vault.delete_scope(&scope()).is_err());
    }

    #[test]
    fn semantic_labels_render_their_protocol_names() {
        assert_eq!(SemanticLabel::Personal.as_str(), "personal");
        assert_eq!(SemanticLabel::Business.as_str(), "business");
        assert_eq!(SemanticLabel::Test.as_str(), "test");
        assert_eq!(SemanticLabel::Secret.as_str(), "secret");
    }

    #[test]
    fn judgment_index_reports_the_candidate_position() {
        let labeled = Judgment::Labeled {
            index: 3,
            label: SemanticLabel::Personal,
            confidence: 0.5,
        };
        assert_eq!(labeled.index(), 3);
        assert_eq!(Judgment::Abstain { index: 5 }.index(), 5);
    }

    #[test]
    fn valid_judgments_pass_including_abstentions() {
        let judgments = [
            Judgment::Labeled {
                index: 0,
                label: SemanticLabel::Business,
                confidence: 1.0,
            },
            Judgment::Abstain { index: 1 },
        ];
        assert!(validate_judgments(2, &judgments).is_ok());
    }

    #[test]
    fn index_equal_to_candidate_count_is_out_of_range() {
        let judgments = [Judgment::Abstain { index: 2 }];
        assert!(matches!(
            validate_judgments(2, &judgments),
            Err(JudgeError::IndexOutOfRange { index: 2, len: 2 })
        ));
    }

    #[test]
    fn duplicate_index_is_rejected() {
        let judgments = [
            Judgment::Abstain { index: 0 },
            Judgment::Abstain { index: 0 },
        ];
        assert!(matches!(
            validate_judgments(2, &judgments),
            Err(JudgeError::DuplicateIndex { index: 0 })
        ));
    }

    #[test]
    fn confidence_outside_unit_interval_is_rejected() {
        for confidence in [1.5_f32, -0.1] {
            let judgments = [Judgment::Labeled {
                index: 0,
                label: SemanticLabel::Test,
                confidence,
            }];
            assert!(
                matches!(
                    validate_judgments(1, &judgments),
                    Err(JudgeError::ConfidenceOutOfRange { index: 0, .. })
                ),
                "confidence {confidence} must be rejected"
            );
        }
    }
}
