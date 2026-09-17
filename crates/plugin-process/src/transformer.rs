//! `Transformer` over the newline-delimited JSON protocol.
//!
//! Request:
//! `{"method":"transform","scope":"...","input":"...","plan":[{"index","kind","start","end","value","action"}]}`.
//! Response: `{"text":"...","mappings":[{"kind","original","token"}]}`.
//!
//! The child may rewrite the text, but every placeholder it emits must resolve
//! through the pipeline's vault back to the claimed kind and value, and every
//! planned `keep` value must survive while every other planned value must be
//! replaced. A transform that violates this fails closed instead of producing
//! output whose placeholders `restore` cannot reverse.

use crate::ProcessConfig;
use crate::protocol;
use do_context_shield_plugin_api::{
    Action, Mapping, PlannedEntity, ScopeId, TransformError, TransformResult, Transformer, Vault,
    is_placeholder_token,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

/// Guidance returned when no transformer command is configured.
const NO_COMMAND: &str = "process transformer unavailable (no command configured); pass `--transformer-command <program> [args...]`";

/// Transformer that delegates to a local executable over the NDJSON protocol.
pub struct ProcessTransformer {
    config: ProcessConfig,
}

impl ProcessTransformer {
    /// Build a transformer from an explicit config.
    #[must_use]
    pub fn new(config: ProcessConfig) -> Self {
        Self { config }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Build a transformer from an adapter selection.
    ///
    /// # Errors
    ///
    /// Returns [`TransformError`] when no usable command is configured, so a
    /// missing `--transformer-command` fails at startup instead of on the first call.
    pub fn from_selection(
        command: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, TransformError> {
        let command = command
            .filter(|command| !command.trim().is_empty())
            .ok_or_else(|| TransformError::Message(NO_COMMAND.to_owned()))?;
        Ok(Self::new(
            ProcessConfig::with_command(command.to_owned()).with_timeout(timeout),
        ))
    }
}

impl Default for ProcessTransformer {
    fn default() -> Self {
        Self::new(ProcessConfig::default())
    }
}

impl Transformer for ProcessTransformer {
    /// Ask the configured child for sanitized text and verify its mappings.
    ///
    /// # Errors
    ///
    /// Returns [`TransformError`] when no command is configured, the child
    /// cannot be started, no response arrives within the configured timeout, or
    /// the response violates the protocol contract.
    fn transform(
        &self,
        input: &str,
        plan: &[PlannedEntity],
        scope: &ScopeId,
        vault: &mut dyn Vault,
    ) -> Result<TransformResult, TransformError> {
        let Some((program, args)) = protocol::split_command(self.config.command.as_deref()) else {
            return Err(TransformError::Message(NO_COMMAND.to_owned()));
        };
        let wire_plan = plan
            .iter()
            .enumerate()
            .map(|(index, planned)| WirePlanEntry {
                index,
                kind: planned.entity.kind.as_str(),
                start: planned.entity.start,
                end: planned.entity.end,
                value: planned.entity.value.as_str(),
                action: action_name(&planned.action),
            })
            .collect();
        let request = protocol::encode(
            "transformer",
            &Request {
                method: "transform",
                scope: &scope.0,
                input,
                plan: wire_plan,
            },
        )
        .map_err(TransformError::Message)?;
        let line = protocol::run_child("transformer", program, &args, request, self.config.timeout)
            .map_err(TransformError::Message)?;
        let response: Response =
            protocol::decode("transformer", &line).map_err(TransformError::Message)?;
        validate(plan, scope, response, vault)
    }
}

/// Request written as one JSON line on the child's stdin.
#[derive(Serialize)]
struct Request<'a> {
    method: &'static str,
    scope: &'a str,
    input: &'a str,
    plan: Vec<WirePlanEntry<'a>>,
}

/// One planned entity as sent to the child.
#[derive(Serialize)]
struct WirePlanEntry<'a> {
    index: usize,
    kind: &'a str,
    start: usize,
    end: usize,
    value: &'a str,
    action: &'static str,
}

/// Response read as one JSON line from the child's stdout.
#[derive(Deserialize)]
struct Response {
    text: String,
    #[serde(default)]
    mappings: Vec<WireMapping>,
}

/// One mapping as reported by the child, before validation.
#[derive(Deserialize)]
struct WireMapping {
    kind: String,
    original: String,
    token: String,
}

/// Wire name of a transformation action.
fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Keep => "keep",
        Action::Pseudonymize => "pseudonymize",
        Action::Redact => "redact",
    }
}

/// Check the child's text and mappings against the plan and the vault.
///
/// Messages name kinds, indices, and placeholder tokens; never an original value.
fn validate(
    plan: &[PlannedEntity],
    scope: &ScopeId,
    response: Response,
    vault: &mut dyn Vault,
) -> Result<TransformResult, TransformError> {
    let mut pseudonymized: HashSet<(&str, &str)> = HashSet::new();
    let mut kept: HashSet<&str> = HashSet::new();
    for planned in plan {
        match planned.action {
            Action::Pseudonymize => {
                pseudonymized.insert((planned.entity.kind.as_str(), planned.entity.value.as_str()));
            }
            Action::Redact => {}
            Action::Keep => {
                kept.insert(planned.entity.value.as_str());
            }
        }
    }

    let mut tokens: HashSet<&str> = HashSet::new();
    let mut covered: HashSet<(&str, &str)> = HashSet::new();
    let mut mappings = Vec::with_capacity(response.mappings.len());
    for mapping in &response.mappings {
        if !is_placeholder_token(&mapping.token) {
            return Err(TransformError::Message(format!(
                "process transformer returned the malformed placeholder `{}`",
                mapping.token
            )));
        }
        if !tokens.insert(mapping.token.as_str()) {
            return Err(TransformError::Message(format!(
                "process transformer returned the duplicate token `{}`",
                mapping.token
            )));
        }
        if !covered.insert((mapping.kind.as_str(), mapping.original.as_str())) {
            return Err(TransformError::Message(format!(
                "process transformer returned duplicate mappings for kind `{}`",
                mapping.kind
            )));
        }
        if !pseudonymized.contains(&(mapping.kind.as_str(), mapping.original.as_str())) {
            return Err(TransformError::Message(format!(
                "process transformer mapped a value that was not planned for pseudonymization (kind `{}`)",
                mapping.kind
            )));
        }
        if !response.text.contains(&mapping.token) {
            return Err(TransformError::Message(format!(
                "process transformer returned text without its token `{}`",
                mapping.token
            )));
        }
        match vault.resolve(scope, &mapping.token) {
            Ok(Some(stored))
                if stored.kind == mapping.kind && stored.original == mapping.original => {}
            Ok(_) => {
                return Err(TransformError::Message(format!(
                    "process transformer emitted the token `{}`, which the configured vault cannot resolve",
                    mapping.token
                )));
            }
            Err(error) => {
                return Err(TransformError::Message(format!(
                    "process transformer vault lookup failed: {error}"
                )));
            }
        }
        mappings.push(Mapping {
            kind: mapping.kind.clone(),
            original: mapping.original.clone(),
            token: mapping.token.clone(),
        });
    }

    for (kind, value) in &pseudonymized {
        if !covered.contains(&(*kind, *value)) {
            return Err(TransformError::Message(format!(
                "process transformer returned no mapping for the pseudonymized kind `{kind}`"
            )));
        }
    }

    for planned in plan {
        let present = response.text.contains(&planned.entity.value);
        match planned.action {
            Action::Keep => {
                if !present {
                    return Err(TransformError::Message(format!(
                        "process transformer returned text without the value of kind `{}` that was planned to be kept",
                        planned.entity.kind
                    )));
                }
            }
            Action::Pseudonymize | Action::Redact => {
                if present && !kept.contains(planned.entity.value.as_str()) {
                    return Err(TransformError::Message(format!(
                        "process transformer returned text that still contains the value of kind `{}`",
                        planned.entity.kind
                    )));
                }
            }
        }
    }

    Ok(TransformResult {
        text: response.text,
        mappings,
    })
}
