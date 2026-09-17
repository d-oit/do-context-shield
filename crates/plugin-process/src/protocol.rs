//! Shared child-process driver for the newline-delimited JSON protocol.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum accepted size of one response line in bytes.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// How long a child that already closed its answer pipe may take to report its
/// exit status before it is killed as a lingering process.
const EXIT_GRACE: Duration = Duration::from_millis(100);

/// Poll interval used while waiting for that exit status.
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Split a configured command line into program and arguments.
///
/// Returns `None` when the command is missing or blank.
pub(crate) fn split_command(command: Option<&str>) -> Option<(&str, Vec<&str>)> {
    command.and_then(|command| {
        let mut tokens = command.split_whitespace();
        let program = tokens.next()?;
        Some((program, tokens.collect::<Vec<&str>>()))
    })
}

/// Encode a request as one JSON line (without the trailing newline).
pub(crate) fn encode<T: Serialize>(label: &str, request: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(request)
        .map_err(|error| format!("process {label} request could not be encoded: {error}"))
}

/// Decode one response line, rejecting empty and malformed answers.
pub(crate) fn decode<T: DeserializeOwned>(label: &str, line: &str) -> Result<T, String> {
    let response_line = line.trim();
    if response_line.is_empty() {
        return Err(format!("process {label} returned an empty response"));
    }
    serde_json::from_str(response_line)
        .map_err(|error| format!("process {label} returned invalid JSON: {error}"))
}

/// Run one child: write the request line, read exactly one response line, and
/// leave no process behind.
///
/// # Errors
///
/// Returns a message (never input text, never child output) when the child
/// cannot be started, does not answer within `timeout`, answers with an
/// oversized line, exits non-zero, or fails at the pipe level.
pub(crate) fn run_child(
    label: &str,
    program: &str,
    args: &[&str],
    request: Vec<u8>,
    timeout: Duration,
) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Discarded by design: a failing plugin must not print context into
        // agent logs, so child stderr never reaches error messages or terminals.
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("process {label} failed to start `{program}`: {error}"))?;

    let Some(mut stdin) = child.stdin.take() else {
        terminate(&mut child);
        return Err(format!("process {label} stdio was not captured"));
    };
    let Some(stdout) = child.stdout.take() else {
        terminate(&mut child);
        return Err(format!("process {label} stdio was not captured"));
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
                return Err(format!(
                    "process {label} response exceeds {MAX_RESPONSE_BYTES} bytes"
                ));
            }
            match settle(label, &mut child)? {
                Some(status) if !status.success() => Err(format!(
                    "process {label} exited with status {status} (stderr discarded to avoid leaking sensitive input)"
                )),
                _ => Ok(line),
            }
        }
        Ok(Err(error)) => {
            terminate(&mut child);
            Err(format!(
                "process {label} response could not be read: {error}"
            ))
        }
        Err(RecvTimeoutError::Timeout) => {
            terminate(&mut child);
            Err(format!(
                "process {label} timed out after {} ms",
                timeout.as_millis()
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            terminate(&mut child);
            Err(format!(
                "process {label} response channel closed unexpectedly"
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
fn settle(label: &str, child: &mut Child) -> Result<Option<ExitStatus>, String> {
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
                return Err(format!("process {label} status could not be read: {error}"));
            }
        }
    }
}
