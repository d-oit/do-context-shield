//! Opt-in jurisdiction-adequacy and purpose-mapping policy plugin.
//!
//! # Invariants
//!
//! - **Secret protection**: Secret entities (`is_secret_kind` or `SemanticLabel::Secret`)
//!   always redact, regardless of purpose mapping, adequacy, recipient, or confidence.
//! - **Unknown recipient**: Refuses non-personal data transfers immediately with `Action::Block`.
//! - **Adequacy verification**: `SpecialCategory` data to a trusted recipient requires a
//!   declared origin and an adequate destination (the origin itself, or a member of the
//!   configured adequate set); an unset or malformed jurisdiction, or a destination outside
//!   the pair, fails closed with `Action::Block`.
//! - **Purpose rules**: Matched in sequence for non-secret entities.

use do_context_shield_plugin_api::{
    Action, DataCategory, DecisionReason, Entity, Judgment, PlannedEntity, Policy, PolicyError,
    ProcessingContext, ReasonCode, RecipientClass, SemanticLabel, is_secret_kind,
    is_valid_jurisdiction,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Minimum judge confidence required to trust a `test` or `business` label.
const KEEP_CONFIDENCE: f32 = 0.90;

/// Action specification in a purpose rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Keep the value unchanged.
    Keep,
    /// Pseudonymize the value.
    Pseudonymize,
    /// Block the input.
    Block,
}

impl From<RuleAction> for Action {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Keep => Self::Keep,
            RuleAction::Pseudonymize => Self::Pseudonymize,
            RuleAction::Block => Self::Block,
        }
    }
}

/// A single purpose-conditional rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeRule {
    /// Purpose string to match (case-sensitive or exact match against `context.purpose`).
    pub purpose: String,
    /// Optional data category filter. If `None`, matches any category.
    #[serde(default)]
    pub data_category: Option<DataCategory>,
    /// Optional list of recipient classes. If `None` or empty, matches any recipient class.
    #[serde(default)]
    pub recipients: Vec<RecipientClass>,
    /// Resulting action for matching non-secret entities.
    pub action: RuleAction,
}

impl PurposeRule {
    /// Check whether this rule matches the given context.
    #[must_use]
    pub fn matches(&self, context: &ProcessingContext) -> bool {
        if context.purpose.as_deref() != Some(&self.purpose) {
            return false;
        }
        if let Some(cat) = self.data_category {
            if cat != context.data_category {
                return false;
            }
        }
        if !self.recipients.is_empty() && !self.recipients.contains(&context.recipient) {
            return false;
        }
        true
    }
}

/// Configuration for the policy matrix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixConfig {
    /// Governing jurisdiction of the operator's transfers (ISO 3166-1 alpha-2).
    /// Adequacy is a pair decision: without a declared origin, no destination is
    /// adequate and special-category data to a trusted recipient fails closed.
    #[serde(default)]
    pub origin: Option<String>,
    /// Destinations deemed adequate for cross-border transfer from `origin`.
    #[serde(default)]
    pub adequate_jurisdictions: HashSet<String>,
    /// Whether trusted recipients require an adequate jurisdiction for `SpecialCategory` data.
    /// Defaults to true.
    #[serde(default = "default_true")]
    pub enforce_adequacy_for_trusted: bool,
    /// Sequential purpose-conditional rules.
    #[serde(default)]
    pub purpose_rules: Vec<PurposeRule>,
}

fn default_true() -> bool {
    true
}

/// The fail-closed default: an empty adequacy set with enforcement on, so an
/// unconfigured matrix is never looser than the built-in default policy.
impl Default for MatrixConfig {
    fn default() -> Self {
        Self {
            origin: None,
            adequate_jurisdictions: HashSet::new(),
            enforce_adequacy_for_trusted: true,
            purpose_rules: Vec::new(),
        }
    }
}

impl MatrixConfig {
    /// Normalize country codes to uppercase for comparison.
    #[must_use]
    pub fn normalized(mut self) -> Self {
        if let Some(origin) = self.origin.take() {
            self.origin = Some(origin.to_ascii_uppercase());
        }
        self.adequate_jurisdictions = self
            .adequate_jurisdictions
            .into_iter()
            .map(|code| code.to_ascii_uppercase())
            .collect();
        self
    }
}

/// Opt-in jurisdiction and purpose policy.
#[derive(Clone, Debug, Default)]
pub struct MatrixPolicy {
    config: MatrixConfig,
}

impl MatrixPolicy {
    /// Create a new policy with the given configuration.
    #[must_use]
    pub fn new(config: MatrixConfig) -> Self {
        Self {
            config: config.normalized(),
        }
    }
}

impl Policy for MatrixPolicy {
    fn plan(
        &self,
        entities: &[Entity],
        judgments: &[Judgment],
        context: &ProcessingContext,
    ) -> Result<Vec<PlannedEntity>, PolicyError> {
        Ok(entities
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, entity)| {
                let decision = judgments.iter().find(|judgment| judgment.index() == index);
                PlannedEntity {
                    action: self.decide(&entity, decision, context).action,
                    entity,
                }
            })
            .collect())
    }

    fn explain(
        &self,
        plan: &[PlannedEntity],
        judgments: &[Judgment],
        context: &ProcessingContext,
    ) -> Result<Vec<DecisionReason>, PolicyError> {
        Ok(plan
            .iter()
            .enumerate()
            .map(|(index, planned)| {
                let decision = judgments.iter().find(|judgment| judgment.index() == index);
                self.decide(&planned.entity, decision, context)
            })
            .collect())
    }
}

impl MatrixPolicy {
    fn decide(
        &self,
        entity: &Entity,
        decision: Option<&Judgment>,
        context: &ProcessingContext,
    ) -> DecisionReason {
        let result = |action, reason_code, matched_rule, used_default| DecisionReason {
            kind: entity.kind.clone(),
            start: entity.start,
            end: entity.end,
            action,
            reason_code,
            matched_rule,
            used_default,
        };
        if is_secret_kind(&entity.kind) {
            return result(Action::Redact, ReasonCode::SecretKind, None, true);
        }
        if matches!(
            decision,
            Some(Judgment::Labeled {
                label: SemanticLabel::Secret,
                ..
            })
        ) {
            return result(Action::Redact, ReasonCode::JudgeSecret, None, true);
        }

        if context.recipient == RecipientClass::Unknown
            && context.data_category != DataCategory::NonPersonal
        {
            return result(
                Action::Block,
                ReasonCode::UnknownRecipientBlocked,
                None,
                true,
            );
        }
        if context.data_category == DataCategory::SpecialCategory {
            match context.recipient {
                RecipientClass::External | RecipientClass::Unknown => {
                    return result(
                        Action::Block,
                        ReasonCode::SpecialCategoryBlocked,
                        None,
                        true,
                    );
                }
                RecipientClass::Trusted if self.config.enforce_adequacy_for_trusted => {
                    let adequate = context
                        .jurisdiction
                        .as_deref()
                        .filter(|destination| is_valid_jurisdiction(destination))
                        .map(str::to_ascii_uppercase)
                        .is_some_and(|destination| {
                            self.config.origin.as_deref().is_some_and(|origin| {
                                origin == destination
                                    || self.config.adequate_jurisdictions.contains(&destination)
                            })
                        });
                    if !adequate {
                        return result(
                            Action::Block,
                            ReasonCode::JurisdictionAdequacyBlocked,
                            None,
                            true,
                        );
                    }
                }
                RecipientClass::Local | RecipientClass::Trusted => {}
            }
        }

        for (index, rule) in self.config.purpose_rules.iter().enumerate() {
            if rule.matches(context) {
                return result(
                    rule.action.into(),
                    ReasonCode::PurposeRuleMatch,
                    Some(index),
                    false,
                );
            }
        }
        if let Some(Judgment::Labeled {
            label: SemanticLabel::Test | SemanticLabel::Business,
            confidence,
            ..
        }) = decision
            && *confidence >= KEEP_CONFIDENCE
        {
            return result(Action::Keep, ReasonCode::JudgeKeep, None, true);
        }
        if context.recipient == RecipientClass::Local {
            return result(Action::Keep, ReasonCode::LocalRecipientKeep, None, true);
        }
        result(
            Action::Pseudonymize,
            ReasonCode::DefaultPseudonymize,
            None,
            true,
        )
    }
}

#[cfg(test)]
mod tests;
