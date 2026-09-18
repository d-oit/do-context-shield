//! Deterministic local judge: labels candidates from their kind and value.
//!
//! The rules are value-shape heuristics, not a model: email domains are
//! compared against reserved documentation domains, email local parts against
//! a role-address list, and non-email identifiers fall back to their kind.
//! Candidates the rules do not cover abstain, so the policy keeps its
//! kind-based default. Secret-like kinds abstain by design; the policy redacts
//! them before any label is consulted.

use do_context_shield_plugin_api::{
    Entity, JudgeError, Judgment, SemanticJudge, SemanticLabel, is_secret_kind,
};

/// Confidence attached to every heuristic label.
const CONFIDENCE: f32 = 0.95;

/// Reserved documentation domains (RFC 2606 / RFC 6761).
const RESERVED_DOMAINS: [&str; 3] = ["example.com", "example.org", "example.net"];

/// Reserved documentation suffixes (RFC 2606 / RFC 6761).
const RESERVED_SUFFIXES: [&str; 3] = [".invalid", ".test", ".example"];

/// Local parts that name a business function rather than a person.
const ROLE_LOCAL_PARTS: [&str; 10] = [
    "support", "billing", "sales", "info", "admin", "noreply", "no-reply", "security", "help",
    "contact",
];

/// Deterministic local judge.
#[derive(Default)]
pub struct HeuristicJudge;

impl SemanticJudge for HeuristicJudge {
    /// Classify each candidate; unclassified kinds are left to abstain.
    ///
    /// # Errors
    ///
    /// Never fails: the heuristics are total and local.
    fn judge(&self, _input: &str, entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        Ok(entities
            .iter()
            .enumerate()
            .filter_map(|(index, entity)| {
                classify(&entity.kind, &entity.value).map(|label| Judgment::Labeled {
                    index,
                    label,
                    confidence: CONFIDENCE,
                })
            })
            .collect())
    }
}

/// Classify one candidate, or `None` to abstain.
fn classify(kind: &str, value: &str) -> Option<SemanticLabel> {
    if is_secret_kind(kind) {
        return None;
    }
    if let Some((local, domain)) = value.rsplit_once('@') {
        return Some(classify_email(local, domain));
    }
    if matches!(kind, "email" | "phone" | "iban") {
        return Some(SemanticLabel::Personal);
    }
    None
}

/// Classify an email-shaped candidate by its domain, then its local part.
///
/// The domain rule runs first: `billing@example.com` is a `test` value even
/// though `billing` is also a role address.
fn classify_email(local: &str, domain: &str) -> SemanticLabel {
    let domain = domain.trim_end_matches('.');
    if RESERVED_DOMAINS
        .iter()
        .any(|reserved| domain.eq_ignore_ascii_case(reserved))
        || RESERVED_SUFFIXES
            .iter()
            .any(|suffix| has_ascii_suffix(domain, suffix))
        || domain.eq_ignore_ascii_case("localhost")
    {
        return SemanticLabel::Test;
    }
    if ROLE_LOCAL_PARTS
        .iter()
        .any(|role| local.eq_ignore_ascii_case(role))
    {
        return SemanticLabel::Business;
    }
    SemanticLabel::Personal
}

/// Whether `domain` ends with the ASCII `suffix` (case-insensitively).
fn has_ascii_suffix(domain: &str, suffix: &str) -> bool {
    domain.len() > suffix.len()
        && domain
            .get(domain.len() - suffix.len()..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(kind: &str, value: &str) -> Entity {
        Entity {
            kind: kind.to_owned(),
            start: 0,
            end: value.len(),
            value: value.to_owned(),
            confidence: 1.0,
        }
    }

    fn label(kind: &str, value: &str) -> Option<SemanticLabel> {
        let entities = [entity(kind, value)];
        match HeuristicJudge.judge("", &entities) {
            Ok(judgments) => match judgments.as_slice() {
                [] => None,
                [
                    Judgment::Labeled {
                        index: 0, label, ..
                    },
                ] => Some(*label),
                other => panic!("expected at most one judgment, got {other:?}"),
            },
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn personal_address_is_personal() {
        assert_eq!(
            label("email", "alice@acme.com"),
            Some(SemanticLabel::Personal)
        );
    }

    #[test]
    fn role_address_is_business() {
        assert_eq!(
            label("email", "support@acme.com"),
            Some(SemanticLabel::Business)
        );
    }

    #[test]
    fn reserved_domain_wins_over_role_local_part() {
        assert_eq!(
            label("email", "billing@example.com"),
            Some(SemanticLabel::Test)
        );
    }

    #[test]
    fn reserved_domain_is_test() {
        assert_eq!(
            label("email", "alice@example.com"),
            Some(SemanticLabel::Test)
        );
    }

    #[test]
    fn reserved_suffix_is_test() {
        assert_eq!(
            label("email", "alice@host.invalid"),
            Some(SemanticLabel::Test)
        );
    }

    #[test]
    fn localhost_is_test() {
        assert_eq!(
            label("email", "support@localhost"),
            Some(SemanticLabel::Test)
        );
    }

    #[test]
    fn phone_kind_is_personal() {
        assert_eq!(label("phone", "+1 555 0100"), Some(SemanticLabel::Personal));
    }

    #[test]
    fn secret_kind_abstains() {
        assert_eq!(label("api_key", "sk-test-0123456789abcdef"), None);
    }

    #[test]
    fn unknown_kind_abstains() {
        assert_eq!(label("person", "Alice"), None);
    }
}
