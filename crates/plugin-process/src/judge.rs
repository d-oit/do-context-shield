//! `SemanticJudge` over the newline-delimited JSON protocol.
//!
//! Request: `{"method":"judge","input":"…","entities":[{"kind","start","end","value","confidence"}]}`.
//! Response: `{"judgments":[{"index":0,"label":"business","confidence":0.95},{"index":1,"label":null}]}`.
//!
//! A null or omitted `label` is an abstention, as is a candidate the child did
//! not mention at all. `confidence` is ignored for abstentions.

use crate::ProcessConfig;
use crate::protocol;
use crate::wire::WireEntity;
use do_context_shield_plugin_api::{
    Entity, JudgeError, Judgment, SemanticJudge, SemanticLabel, validate_judgments,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Guidance returned when no judge command is configured.
const NO_COMMAND: &str =
    "process judge unavailable (no command configured); pass `--judge-command <program> [args...]`";

/// Judge that delegates to a local executable over the NDJSON protocol.
pub struct ProcessJudge {
    config: ProcessConfig,
}

impl ProcessJudge {
    /// Build a judge from an explicit config.
    #[must_use]
    pub fn new(config: ProcessConfig) -> Self {
        Self { config }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Build a judge from an adapter selection.
    ///
    /// # Errors
    ///
    /// Returns [`JudgeError`] when no usable command is configured, so a
    /// missing `--judge-command` fails at startup instead of on the first call.
    pub fn from_selection(command: Option<&str>, timeout: Duration) -> Result<Self, JudgeError> {
        let command = command
            .filter(|command| !command.trim().is_empty())
            .ok_or_else(|| JudgeError::Message(NO_COMMAND.to_owned()))?;
        Ok(Self::new(
            ProcessConfig::with_command(command.to_owned()).with_timeout(timeout),
        ))
    }
}

impl Default for ProcessJudge {
    fn default() -> Self {
        Self::new(ProcessConfig::default())
    }
}

impl SemanticJudge for ProcessJudge {
    /// Ask the configured child to label the candidates it is willing to judge.
    ///
    /// # Errors
    ///
    /// Returns [`JudgeError`] when no command is configured, the child cannot
    /// be started, no response arrives within the configured timeout, or the
    /// response violates the protocol contract (out-of-range or duplicate
    /// index, confidence outside `0..=1`, unknown label, missing index).
    fn judge(&self, input: &str, entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        let Some((program, args)) = protocol::split_command(self.config.command.as_deref()) else {
            return Err(JudgeError::Message(NO_COMMAND.to_owned()));
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
            "judge",
            &Request {
                method: "judge",
                input,
                entities: wire_entities,
            },
        )
        .map_err(JudgeError::Message)?;
        let line = protocol::run_child("judge", program, &args, request, self.config.timeout)
            .map_err(JudgeError::Message)?;
        let response: Response = protocol::decode("judge", &line).map_err(JudgeError::Message)?;
        let judgments = convert_judgments(&response.judgments)?;
        validate_judgments(entities.len(), &judgments)?;
        Ok(judgments)
    }
}

/// Request written as one JSON line on the child's stdin.
#[derive(Serialize)]
struct Request<'a> {
    method: &'static str,
    input: &'a str,
    entities: Vec<WireEntity<'a>>,
}

/// Response read as one JSON line from the child's stdout.
#[derive(Deserialize)]
struct Response {
    judgments: Vec<WireJudgment>,
}

/// One judgment as reported by the child, before validation.
#[derive(Deserialize)]
struct WireJudgment {
    index: usize,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    confidence: f32,
}

/// Convert wire judgments to pipeline judgments.
///
/// A null or omitted `label` is an abstention; an unknown label name is
/// rejected. Per-candidate coverage is not required: candidates without a
/// judgment are treated as abstentions by the policy.
fn convert_judgments(wire: &[WireJudgment]) -> Result<Vec<Judgment>, JudgeError> {
    wire.iter()
        .map(|reported| match reported.label.as_deref() {
            Some(name) => {
                let label = SemanticLabel::parse(name).ok_or_else(|| {
                    JudgeError::Message(format!(
                        "process judge returned the unknown label `{name}` for index {}",
                        reported.index
                    ))
                })?;
                Ok(Judgment::Labeled {
                    index: reported.index,
                    label,
                    confidence: reported.confidence,
                })
            }
            None => Ok(Judgment::Abstain {
                index: reported.index,
            }),
        })
        .collect()
}
