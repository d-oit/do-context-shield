//! `Detector` over the newline-delimited JSON protocol.
//!
//! Request: `{"method":"detect","input":"..."}`. Response:
//! `{"entities":[{"kind","start","end","value?","confidence?"}]}`.

use crate::ProcessConfig;
use crate::protocol;
use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Guidance returned when no detector command is configured.
const NO_COMMAND: &str = "process detector unavailable (no command configured); pass `--detector-command <program> [args...]`";

/// Detector that delegates to a local executable over the NDJSON protocol.
pub struct ProcessDetector {
    config: ProcessConfig,
}

impl ProcessDetector {
    /// Build a detector from an explicit config.
    #[must_use]
    pub fn new(config: ProcessConfig) -> Self {
        Self { config }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Build a detector from an adapter selection.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] when no usable command is configured, so a
    /// missing `--detector-command` fails at startup instead of on the first call.
    pub fn from_selection(command: Option<&str>, timeout: Duration) -> Result<Self, DetectorError> {
        let command = command
            .filter(|command| !command.trim().is_empty())
            .ok_or_else(|| DetectorError::Message(NO_COMMAND.to_owned()))?;
        Ok(Self::new(
            ProcessConfig::with_command(command.to_owned()).with_timeout(timeout),
        ))
    }
}

impl Default for ProcessDetector {
    fn default() -> Self {
        Self::new(ProcessConfig::default())
    }
}

impl Detector for ProcessDetector {
    /// Run the configured child once and return its validated entities.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] when no command is configured, the child
    /// cannot be started, no response arrives within the configured timeout, or
    /// the response violates the protocol contract.
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        let Some((program, args)) = protocol::split_command(self.config.command.as_deref()) else {
            return Err(DetectorError::Message(NO_COMMAND.to_owned()));
        };
        let request = protocol::encode(
            "detector",
            &Request {
                method: "detect",
                input,
            },
        )
        .map_err(DetectorError::Message)?;
        let line = protocol::run_child("detector", program, &args, request, self.config.timeout)
            .map_err(DetectorError::Message)?;
        let response: Response =
            protocol::decode("detector", &line).map_err(DetectorError::Message)?;
        Ok(dedupe_overlaps(validate_entities(
            input,
            &response.entities,
        )?))
    }
}

/// Request written as one JSON line on the child's stdin.
#[derive(Serialize)]
struct Request<'a> {
    method: &'static str,
    input: &'a str,
}

/// Response read as one JSON line from the child's stdout.
#[derive(Deserialize)]
struct Response {
    entities: Vec<WireEntity>,
}

/// One entity as reported by the child, before validation.
#[derive(Deserialize)]
struct WireEntity {
    kind: String,
    start: usize,
    end: usize,
    #[serde(default)]
    value: Option<String>,
    #[serde(default = "certain")]
    confidence: f32,
}

/// Default confidence for a child that does not report one.
fn certain() -> f32 {
    1.0
}

/// Validate reported entities against the exact input and convert them to
/// pipeline entities.
///
/// Unlike a model backend, a process plugin is a programming contract, so
/// violations fail loudly instead of being dropped silently. Messages name the
/// kind and span only, never a reported value.
fn validate_entities(input: &str, wire: &[WireEntity]) -> Result<Vec<Entity>, DetectorError> {
    let mut entities = Vec::with_capacity(wire.len());
    for reported in wire {
        let kind = reported.kind.trim().to_ascii_lowercase().replace(' ', "_");
        if kind.is_empty() {
            return Err(DetectorError::Message(format!(
                "process detector returned an empty kind at span {}..{}",
                reported.start, reported.end
            )));
        }
        if reported.start >= reported.end {
            return Err(invalid_span(&kind, reported.start, reported.end));
        }
        let Some(value) = input.get(reported.start..reported.end) else {
            return Err(invalid_span(&kind, reported.start, reported.end));
        };
        if let Some(reported_value) = reported.value.as_deref() {
            if reported_value != value {
                return Err(DetectorError::Message(format!(
                    "process detector value does not match input at span {}..{} for kind `{kind}`",
                    reported.start, reported.end
                )));
            }
        }
        if !(0.0..=1.0).contains(&reported.confidence) {
            return Err(DetectorError::Message(format!(
                "process detector returned confidence {} for kind `{kind}` outside 0..=1",
                reported.confidence
            )));
        }
        entities.push(Entity {
            kind,
            start: reported.start,
            end: reported.end,
            value: value.to_owned(),
            confidence: reported.confidence,
        });
    }
    Ok(entities)
}

/// Error for a span that is not a valid range of the input.
fn invalid_span(kind: &str, start: usize, end: usize) -> DetectorError {
    DetectorError::Message(format!(
        "process detector returned an invalid span {start}..{end} for kind `{kind}`"
    ))
}

/// Resolve overlapping entities longest-span-wins, keeping the first reported
/// entity for identical spans (mirroring `detector-regex` and `detector-gliner2`).
fn dedupe_overlaps(mut entities: Vec<Entity>) -> Vec<Entity> {
    entities.sort_by_key(|entity| (entity.start, usize::MAX - entity.end));
    let mut deduped = Vec::with_capacity(entities.len());
    for entity in entities {
        if deduped
            .iter()
            .any(|saved: &Entity| entity.start < saved.end && saved.start < entity.end)
        {
            continue;
        }
        deduped.push(entity);
    }
    deduped.sort_by_key(|entity: &Entity| (entity.start, entity.end));
    deduped
}
