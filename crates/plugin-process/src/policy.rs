//! `Policy` over the newline-delimited JSON protocol.
//!
//! Request: `{"method":"plan","entities":[{"kind","start","end","value","confidence"}]}`.
//! Response: `{"plan":[{"index":0,"action":"keep|pseudonymize|redact"}]}`.

use crate::ProcessConfig;
use crate::protocol;
use do_context_shield_plugin_api::{Action, Entity, PlannedEntity, Policy, PolicyError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Guidance returned when no policy command is configured.
const NO_COMMAND: &str = "process policy unavailable (no command configured); pass `--policy-command <program> [args...]`";

/// Policy that delegates to a local executable over the NDJSON protocol.
pub struct ProcessPolicy {
    config: ProcessConfig,
}

impl ProcessPolicy {
    /// Build a policy from an explicit config.
    #[must_use]
    pub fn new(config: ProcessConfig) -> Self {
        Self { config }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Build a policy from an adapter selection.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when no usable command is configured, so a
    /// missing `--policy-command` fails at startup instead of on the first call.
    pub fn from_selection(command: Option<&str>, timeout: Duration) -> Result<Self, PolicyError> {
        let command = command
            .filter(|command| !command.trim().is_empty())
            .ok_or_else(|| PolicyError::Message(NO_COMMAND.to_owned()))?;
        Ok(Self::new(
            ProcessConfig::with_command(command.to_owned()).with_timeout(timeout),
        ))
    }
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self::new(ProcessConfig::default())
    }
}

impl Policy for ProcessPolicy {
    /// Ask the configured child for one action per entity.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when no command is configured, the child cannot
    /// be started, no response arrives within the configured timeout, or the
    /// response violates the protocol contract.
    fn plan(&self, entities: &[Entity]) -> Result<Vec<PlannedEntity>, PolicyError> {
        let Some((program, args)) = protocol::split_command(self.config.command.as_deref()) else {
            return Err(PolicyError::Message(NO_COMMAND.to_owned()));
        };
        let wire_entities = entities
            .iter()
            .map(|entity| WireEntity {
                kind: entity.kind.as_str(),
                start: entity.start,
                end: entity.end,
                value: entity.value.as_str(),
                confidence: entity.confidence,
            })
            .collect();
        let request = protocol::encode(
            "policy",
            &Request {
                method: "plan",
                entities: wire_entities,
            },
        )
        .map_err(PolicyError::Message)?;
        let line = protocol::run_child("policy", program, &args, request, self.config.timeout)
            .map_err(PolicyError::Message)?;
        let response: Response = protocol::decode("policy", &line).map_err(PolicyError::Message)?;
        validate_plan(entities, &response.plan)
    }
}

/// Request written as one JSON line on the child's stdin.
#[derive(Serialize)]
struct Request<'a> {
    method: &'static str,
    entities: Vec<WireEntity<'a>>,
}

/// One detected entity as sent to the child.
#[derive(Serialize)]
struct WireEntity<'a> {
    kind: &'a str,
    start: usize,
    end: usize,
    value: &'a str,
    confidence: f32,
}

/// Response read as one JSON line from the child's stdout.
#[derive(Deserialize)]
struct Response {
    plan: Vec<WireDecision>,
}

/// One action as reported by the child, before validation.
#[derive(Deserialize)]
struct WireDecision {
    index: usize,
    action: String,
}

/// Pair the reported actions with the entities they refer to.
///
/// Every entity must be covered exactly once: a missing, duplicated, or
/// out-of-range index and an unknown action all fail closed, so a policy can
/// never leave an entity undecided. (In-range indices without duplicates can
/// only cover every entity, so a shorter or longer response surfaces as a
/// missing decision, a duplicate, or an out-of-range index.)
fn validate_plan(
    entities: &[Entity],
    decisions: &[WireDecision],
) -> Result<Vec<PlannedEntity>, PolicyError> {
    let mut actions: Vec<Option<Action>> = vec![None; entities.len()];
    for decision in decisions {
        let Some(slot) = actions.get_mut(decision.index) else {
            return Err(PolicyError::Message(format!(
                "process policy returned the out-of-range index {}",
                decision.index
            )));
        };
        if slot.is_some() {
            return Err(PolicyError::Message(format!(
                "process policy returned the duplicate index {}",
                decision.index
            )));
        }
        let Some(action) = parse_action(&decision.action) else {
            return Err(PolicyError::Message(format!(
                "process policy returned the unknown action `{}` for index {}",
                decision.action, decision.index
            )));
        };
        *slot = Some(action);
    }
    let mut plan = Vec::with_capacity(entities.len());
    for (entity, action) in entities.iter().zip(actions) {
        let Some(action) = action else {
            return Err(PolicyError::Message(format!(
                "process policy returned no decision for index {}",
                plan.len()
            )));
        };
        plan.push(PlannedEntity {
            entity: entity.clone(),
            action,
        });
    }
    Ok(plan)
}

/// Parse the wire action name.
fn parse_action(action: &str) -> Option<Action> {
    match action {
        "keep" => Some(Action::Keep),
        "pseudonymize" => Some(Action::Pseudonymize),
        "redact" => Some(Action::Redact),
        _ => None,
    }
}
