//! Process detector plugin: local executables over a newline-delimited JSON
//! protocol.
//!
//! A configured local program (Python, `Presidio`, `spaCy`, a Rust model, or
//! any other executable) replaces a compiled-in detector without touching
//! `do-context-shield-core`. One child process is started per
//! [`Detector::detect`] call: the request is written as a single JSON line to
//! stdin, exactly one response line is read from stdout, and the child is
//! terminated as soon as its answer has been read. A long-lived server mode is
//! not part of this version.
//!
//! Request:
//!
//! ```json
//! {"method":"detect","input":"email alice@example.com"}
//! ```
//!
//! Response:
//!
//! ```json
//! {"entities":[{"kind":"email","start":6,"end":23,"value":"alice@example.com","confidence":0.99}]}
//! ```
//!
//! `start` and `end` are byte offsets into the exact input. `value` is optional
//! but must equal `input[start..end]`; `confidence` is optional and defaults to
//! `1.0`. Kind labels are trimmed, lowercased, and have spaces replaced by
//! underscores, so `API Key` becomes `api_key`.
//!
//! Fail-closed: a missing command, a spawn failure, an empty or oversized
//! response, malformed JSON, an invalid span, a value mismatch, an
//! out-of-range confidence, or a non-zero exit all produce a [`DetectorError`]
//! instead of a silently reduced entity list. The child's stderr is discarded
//! and never logged, so a failing detector cannot print sensitive input into
//! agent logs.
//!
//! The command line is split on whitespace; quoting and shell expansion are not
//! supported. Point the command at a wrapper script for anything more elaborate.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// Default process-detector timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Maximum accepted size of one response line in bytes.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// How long a child that already closed its answer pipe may take to report its
/// exit status before it is killed as a lingering process.
const EXIT_GRACE: Duration = Duration::from_millis(100);

/// Poll interval used while waiting for that exit status.
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Configuration for [`ProcessDetector`].
#[derive(Clone, Debug)]
pub struct ProcessDetectorConfig {
    /// Local executable plus arguments, whitespace-separated. `None` means unconfigured.
    pub command: Option<String>,
    /// Maximum time to wait for one detection response.
    pub timeout: Duration,
}

impl Default for ProcessDetectorConfig {
    fn default() -> Self {
        Self {
            command: None,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl ProcessDetectorConfig {
    /// Build a config from an explicit command line and the default timeout.
    #[must_use]
    pub fn with_command(command: String) -> Self {
        Self {
            command: Some(command),
            ..Self::default()
        }
    }
}

/// Detector that delegates to a local executable over the NDJSON protocol.
pub struct ProcessDetector {
    config: ProcessDetectorConfig,
}

impl ProcessDetector {
    /// Build a detector from an explicit config.
    #[must_use]
    pub fn new(config: ProcessDetectorConfig) -> Self {
        Self { config }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &ProcessDetectorConfig {
        &self.config
    }
}

impl Default for ProcessDetector {
    fn default() -> Self {
        Self::new(ProcessDetectorConfig::default())
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
        let Some((program, args)) = self.config.command.as_deref().and_then(|command| {
            let mut tokens = command.split_whitespace();
            let program = tokens.next()?;
            Some((program, tokens.collect::<Vec<&str>>()))
        }) else {
            return Err(DetectorError::Message(
                "process detector unavailable (no command configured); pass `--detector-command <program> [args...]`"
                    .to_owned(),
            ));
        };
        let request = serde_json::to_vec(&Request {
            method: "detect",
            input,
        })
        .map_err(|error| {
            DetectorError::Message(format!(
                "process detector request could not be encoded: {error}"
            ))
        })?;
        let line = run_child(program, &args, request, self.config.timeout)?;
        let response_line = line.trim();
        if response_line.is_empty() {
            return Err(DetectorError::Message(
                "process detector returned an empty response".to_owned(),
            ));
        }
        let response: Response = serde_json::from_str(response_line).map_err(|error| {
            DetectorError::Message(format!("process detector returned invalid JSON: {error}"))
        })?;
        Ok(dedupe_overlaps(validate_entities(
            input,
            &response.entities,
        )?))
    }
}

/// Run the child once: write the request line, read one response line, and
/// leave no process behind.
fn run_child(
    program: &str,
    args: &[&str],
    request: Vec<u8>,
    timeout: Duration,
) -> Result<String, DetectorError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Discarded by design: a failing detector must not print context into
        // agent logs, so child stderr never reaches error messages or terminals.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            DetectorError::Message(format!(
                "process detector failed to start `{program}`: {error}"
            ))
        })?;

    let Some(mut stdin) = child.stdin.take() else {
        terminate(&mut child);
        return Err(DetectorError::Message(
            "process detector stdio was not captured".to_owned(),
        ));
    };
    let Some(stdout) = child.stdout.take() else {
        terminate(&mut child);
        return Err(DetectorError::Message(
            "process detector stdio was not captured".to_owned(),
        ));
    };

    // Both directions run on detached threads: joining a thread blocked on a
    // pipe that a lingering grandchild still holds open would defeat the
    // timeout. The threads end when their pipes close.
    let _ = thread::spawn(move || {
        let _ = stdin.write_all(&request);
        let _ = stdin.write_all(b"\n");
    });
    let (line_tx, line_rx) = mpsc::channel();
    let _ = thread::spawn(move || {
        let mut line = String::new();
        let read = BufReader::new(stdout.take(MAX_RESPONSE_BYTES + 1)).read_line(&mut line);
        let _ = line_tx.send(read.map(|_| line));
    });

    match line_rx.recv_timeout(timeout) {
        Ok(Ok(line)) => {
            if line.len() as u64 > MAX_RESPONSE_BYTES {
                terminate(&mut child);
                return Err(DetectorError::Message(format!(
                    "process detector response exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            match settle(&mut child)? {
                Some(status) if !status.success() => Err(DetectorError::Message(format!(
                    "process detector exited with status {status} (stderr discarded to avoid leaking sensitive input)"
                ))),
                _ => Ok(line),
            }
        }
        Ok(Err(error)) => {
            terminate(&mut child);
            Err(DetectorError::Message(format!(
                "process detector response could not be read: {error}"
            )))
        }
        Err(RecvTimeoutError::Timeout) => {
            terminate(&mut child);
            Err(DetectorError::Message(format!(
                "process detector timed out after {} ms",
                timeout.as_millis()
            )))
        }
        Err(RecvTimeoutError::Disconnected) => {
            terminate(&mut child);
            Err(DetectorError::Message(
                "process detector response channel closed unexpectedly".to_owned(),
            ))
        }
    }
}

/// Kill and reap the child so no process outlives its answer.
fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Wait for the child's exit status, allowing a child that has just closed its
/// answer pipe to finish exiting. A child can close its pipes microseconds
/// before the kernel reports its status, so without this grace a non-zero exit
/// would be misreported as an empty response. A child that keeps running is
/// terminated and reports `None`.
fn settle(child: &mut Child) -> Result<Option<ExitStatus>, DetectorError> {
    let deadline = Instant::now() + EXIT_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
            Ok(None) => {
                terminate(child);
                return Ok(None);
            }
            Err(error) => {
                terminate(child);
                return Err(DetectorError::Message(format!(
                    "process detector status could not be read: {error}"
                )));
            }
        }
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
