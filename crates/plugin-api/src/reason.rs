//! Value-free metadata explaining policy decisions.

use crate::Action;
use serde::{Deserialize, Serialize, Serializer};

/// Stable machine-readable reason for a policy decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// A secret-like entity kind was redacted.
    SecretKind,
    /// A semantic judge classified the entity as secret.
    JudgeSecret,
    /// Special-category transfer was blocked by recipient context.
    SpecialCategoryBlocked,
    /// An unknown recipient was blocked for non-public data.
    UnknownRecipientBlocked,
    /// The declared jurisdiction did not satisfy the adequacy requirement.
    JurisdictionAdequacyBlocked,
    /// A required jurisdiction declaration was missing or malformed.
    JurisdictionRequiredBlocked,
    /// A configured purpose rule decided the action.
    PurposeRuleMatch,
    /// A high-confidence test or business judgment selected keep.
    JudgeKeep,
    /// A local recipient selected keep.
    LocalRecipientKeep,
    /// The policy's fallback selected pseudonymization.
    DefaultPseudonymize,
    /// The policy does not expose more specific rule metadata.
    CustomPolicyPlan,
}

impl ReasonCode {
    /// Stable snake-case representation used by JSON and text output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecretKind => "secret_kind",
            Self::JudgeSecret => "judge_secret",
            Self::SpecialCategoryBlocked => "special_category_blocked",
            Self::UnknownRecipientBlocked => "unknown_recipient_blocked",
            Self::JurisdictionAdequacyBlocked => "jurisdiction_adequacy_blocked",
            Self::JurisdictionRequiredBlocked => "jurisdiction_required_blocked",
            Self::PurposeRuleMatch => "purpose_rule_match",
            Self::JudgeKeep => "judge_keep",
            Self::LocalRecipientKeep => "local_recipient_keep",
            Self::DefaultPseudonymize => "default_pseudonymize",
            Self::CustomPolicyPlan => "custom_policy_plan",
        }
    }
}

/// A value-free explanation for one policy decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DecisionReason {
    /// Stable entity kind; matched text is never included.
    pub kind: String,
    /// Byte offset where the detected entity starts.
    pub start: usize,
    /// Byte offset immediately after the detected entity.
    pub end: usize,
    /// Action selected by the policy.
    #[serde(serialize_with = "serialize_action")]
    pub action: Action,
    /// Stable reason code; never contains purpose or jurisdiction values.
    pub reason_code: ReasonCode,
    /// Zero-based index of a matched configured rule, when available.
    pub matched_rule: Option<usize>,
    /// Whether the selected policy's fallback/default hierarchy was used.
    pub used_default: bool,
}

/// Serialize actions with their stable lowercase wire representation.
///
/// # Errors
///
/// Returns the serializer's error if it cannot encode the action string.
/// Serde's `serialize_with` contract requires a reference to the field.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_action<S>(action: &Action, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(action.as_str())
}

#[cfg(test)]
mod tests {
    use super::ReasonCode;

    #[test]
    fn reason_codes_have_stable_wire_names() {
        for (code, name) in [
            (ReasonCode::SecretKind, "secret_kind"),
            (ReasonCode::JudgeSecret, "judge_secret"),
            (
                ReasonCode::SpecialCategoryBlocked,
                "special_category_blocked",
            ),
            (
                ReasonCode::UnknownRecipientBlocked,
                "unknown_recipient_blocked",
            ),
            (
                ReasonCode::JurisdictionRequiredBlocked,
                "jurisdiction_required_blocked",
            ),
            (
                ReasonCode::JurisdictionAdequacyBlocked,
                "jurisdiction_adequacy_blocked",
            ),
            (ReasonCode::PurposeRuleMatch, "purpose_rule_match"),
            (ReasonCode::JudgeKeep, "judge_keep"),
            (ReasonCode::LocalRecipientKeep, "local_recipient_keep"),
            (ReasonCode::DefaultPseudonymize, "default_pseudonymize"),
            (ReasonCode::CustomPolicyPlan, "custom_policy_plan"),
        ] {
            assert_eq!(code.as_str(), name);
        }
    }
    #[test]
    fn decision_reason_serializes_value_free_stable_fields() {
        let decision = super::DecisionReason {
            kind: "api_key".to_owned(),
            start: 0,
            end: 12,
            action: crate::Action::Redact,
            reason_code: ReasonCode::SecretKind,
            matched_rule: None,
            used_default: true,
        };
        let value = match serde_json::to_value(decision) {
            Ok(value) => value,
            Err(error) => panic!("unexpected serialization error: {error}"),
        };
        assert_eq!(value["action"], "redact");
        assert_eq!(value["reason_code"], "secret_kind");
        assert_eq!(value["used_default"], true);
        assert_eq!(value.as_object().map(serde_json::Map::len), Some(7));
    }
}
