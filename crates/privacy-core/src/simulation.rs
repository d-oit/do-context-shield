//! Value-free policy simulation using detection and policy validation only.

use crate::{
    PipelineError, scrub_detector, scrub_judge, scrub_policy, sensitive_values, validate_plan,
    validate_spans,
};
use do_context_shield_plugin_api::{
    Action, Detector, DetectorError, Policy, PolicyError, ProcessingContext, SemanticJudge,
    is_valid_placeholder_kind, validate_judgments,
};
use serde::{Serialize, Serializer};

/// Value-free explanation of one entity's policy decision.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExplainedEntity {
    /// Stable entity kind; matched text is never included.
    pub kind: String,
    /// Byte offset where the detected entity starts.
    pub start: usize,
    /// Byte offset immediately after the detected entity.
    pub end: usize,
    /// Action selected by the policy, serialized using its stable wire name.
    #[serde(serialize_with = "serialize_action")]
    pub action: Action,
    /// Stable snake-case policy reason code.
    pub reason_code: do_context_shield_plugin_api::ReasonCode,
    /// Zero-based configured rule index, when the policy exposes one.
    pub matched_rule: Option<usize>,
    /// Whether the policy's default hierarchy supplied this decision.
    pub used_default: bool,
}

/// Detector, optional judge, and policy for a simulation with no write stages.
pub struct PolicyPlanner {
    detector: Box<dyn Detector>,
    judge: Option<Box<dyn SemanticJudge>>,
    policy: Box<dyn Policy>,
}

impl PolicyPlanner {
    /// Create a planner using the selected detector and policy.
    #[must_use]
    pub fn new(detector: Box<dyn Detector>, policy: Box<dyn Policy>) -> Self {
        Self {
            detector,
            judge: None,
            policy,
        }
    }

    /// Attach an optional semantic judge.
    #[must_use]
    pub fn with_judge(mut self, judge: Box<dyn SemanticJudge>) -> Self {
        self.judge = Some(judge);
        self
    }

    /// Detect entities and report policy decisions without transforming text.
    ///
    /// Block actions are reported as simulation results rather than returned as
    /// errors. This planner has no transformer, vault, or audit sink.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when detection, judging, policy planning, shared
    /// boundary validation, or value-free kind validation fails.
    pub fn explain(
        &self,
        input: &str,
        context: &ProcessingContext,
    ) -> Result<Vec<ExplainedEntity>, PipelineError> {
        let detected = self
            .detector
            .detect(input)
            .map_err(|error| scrub_detector(error, &[input]))?;
        let entities = validate_spans(input, &detected)?;
        let sensitive = sensitive_values(input, &entities);
        for entity in &entities {
            if !is_valid_placeholder_kind(&entity.kind)
                || sensitive
                    .iter()
                    .any(|value| value_contains_kind(value, &entity.kind))
            {
                return Err(PipelineError::Detector(DetectorError::Message(
                    "entity kind is not safe to disclose in a value-free explanation".to_owned(),
                )));
            }
        }
        let judgments = match &self.judge {
            Some(judge) => {
                let judgments = judge
                    .judge(input, &entities)
                    .map_err(|error| scrub_judge(error, &sensitive))?;
                validate_judgments(entities.len(), &judgments)?;
                judgments
            }
            None => Vec::new(),
        };
        let mut policy_sensitive = sensitive.clone();
        policy_sensitive.extend(context.purpose.as_deref());
        policy_sensitive.extend(context.jurisdiction.as_deref());
        let plan = self
            .policy
            .plan(&entities, &judgments, context)
            .map_err(|error| scrub_policy(error, &policy_sensitive))?;
        validate_plan(&entities, &plan)?;
        let reasons = self
            .policy
            .explain(&plan, &judgments, context)
            .map_err(|error| scrub_policy(error, &policy_sensitive))?;
        if reasons.len() != entities.len() {
            return Err(PolicyError::Message(
                "policy returned a different number of explanations than entities".to_owned(),
            )
            .into());
        }
        for ((entity, planned), reason) in entities.iter().zip(&plan).zip(&reasons) {
            if entity.kind != reason.kind
                || entity.start != reason.start
                || entity.end != reason.end
                || planned.action != reason.action
            {
                return Err(PolicyError::Message(
                    "policy explanation does not match the validated policy decision".to_owned(),
                )
                .into());
            }
        }
        Ok(reasons
            .into_iter()
            .map(|reason| ExplainedEntity {
                kind: reason.kind,
                start: reason.start,
                end: reason.end,
                action: reason.action,
                reason_code: reason.reason_code,
                matched_rule: reason.matched_rule,
                used_default: reason.used_default,
            })
            .collect())
    }
}

fn value_contains_kind(value: &str, kind: &str) -> bool {
    let kind_bytes = kind.as_bytes();
    !kind_bytes.is_empty()
        && value.as_bytes().windows(kind_bytes.len()).any(|candidate| {
            candidate
                .iter()
                .zip(kind_bytes)
                .all(|(value_byte, kind_byte)| value_byte.eq_ignore_ascii_case(kind_byte))
        })
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
