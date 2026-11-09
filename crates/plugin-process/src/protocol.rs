//! Shared child-process driver for the newline-delimited JSON protocol.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Maximum accepted size of one response line in bytes.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// How long a child that already closed its answer pipe may take to report its
/// exit status before it is killed as a lingering process.
const EXIT_GRACE: Duration = Duration::from_millis(100);

/// How long to wait for a terminated process tree to disappear before giving
/// up on reaping it. Bounds the whole call: `timeout + EXIT_GRACE + TREE_WAIT`.
const TREE_WAIT: Duration = Duration::from_millis(500);

/// Poll interval used while waiting for an exit status or a thread.
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

/// Platform-specific process-tree containment for one child.
///
/// Unix launches the child as its own process-group leader and kills the whole
/// group; Windows assigns it to a Job Object configured to terminate every
/// member when the host closes the job. Direct `kill`/`wait` remains the
/// fallback when containment could not be established (for example a Windows
/// host that already holds the process in a non-breakaway job): a descendant
/// may then outlive the direct child, which is reported rather than hidden.
struct Containment {
    #[cfg(unix)]
    pid: Option<i32>,
    #[cfg(windows)]
    job: Option<win32job::Job>,
}

impl Containment {
    /// Set up containment for a freshly spawned child.
    fn new(child: &Child) -> Self {
        #[cfg(unix)]
        {
            Self {
                pid: i32::try_from(child.id()).ok(),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            let mut info = win32job::ExtendedLimitInfo::new();
            info.limit_kill_on_job_close();
            let job = win32job::Job::create_with_limit_info(&info).ok();
            let job = match job {
                Some(job) if job.assign_process(child.as_raw_handle() as isize).is_ok() => {
                    Some(job)
                }
                _ => None,
            };
            Self { job }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Self {}
        }
    }

    /// Terminate the whole tree, then reap the direct child within a bound.
    fn terminate(&mut self, child: &mut Child) {
        #[cfg(unix)]
        {
            if let Some(pid) = self.pid.and_then(rustix::process::Pid::from_raw) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
        }
        #[cfg(windows)]
        {
            // Closing the last job handle terminates every assigned process.
            if let Some(job) = self.job.take() {
                drop(job);
            }
        }
        let _ = child.kill();
        reap_bounded(child);
    }
}

/// Poll for the child's exit status without an unbounded `wait`.
fn reap_bounded(child: &mut Child) {
    let deadline = Instant::now() + TREE_WAIT;
    loop {
        match child.try_wait() {
            Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
            // Exited, unkillable, or already gone: never block the caller on
            // it. The kernel reaps a leftover zombie when this process exits.
            _ => return,
        }
    }
}

/// Join a helper thread only while it finishes within `deadline`.
///
/// A reader blocked on a pipe still held by a surviving descendant would
/// otherwise defeat the timeout; such a thread is detached instead of awaited.
fn join_bounded(handle: JoinHandle<()>, deadline: Instant) {
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            drop(handle);
            return;
        }
        thread::sleep(EXIT_POLL_INTERVAL);
    }
    let _ = handle.join();
}

/// Run one child: write the request line, read exactly one response line, and
/// leave no process behind.
///
/// # Errors
///
/// Returns a message (never input text, never child output) when the child
/// cannot be started, does not answer within `timeout`, answers with an
/// oversized line, exits non-zero, could not receive the request, or fails at
/// the pipe level.
pub(crate) fn run_child(
    label: &str,
    program: &str,
    args: &[&str],
    request: Vec<u8>,
    timeout: Duration,
) -> Result<String, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Discarded by design: a failing plugin must not print context into
        // agent logs, so child stderr never reaches error messages or terminals.
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // The child leads its own process group, so a timeout can signal every
        // descendant instead of only the direct executable.
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("process {label} failed to start `{program}`: {error}"))?;
    let mut containment = Containment::new(&child);

    let Some(mut stdin) = child.stdin.take() else {
        containment.terminate(&mut child);
        return Err(format!("process {label} stdio was not captured"));
    };
    let Some(stdout) = child.stdout.take() else {
        containment.terminate(&mut child);
        return Err(format!("process {label} stdio was not captured"));
    };

    // Both directions run on helper threads so a pipe holder (a descendant
    // that inherited stdin/stdout) cannot block the caller past the timeout.
    // The writer reports a broken pipe instead of swallowing it, and closing
    // its handle signals EOF to the child. Keep stdout open through `settle`:
    // closing it after the first line can make a child fail while writing an
    // extra line, before the host terminates it.
    let (write_tx, write_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        let result = stdin
            .write_all(&request)
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush());
        let _ = write_tx.send(result);
    });
    let (line_tx, line_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut stdout = BufReader::new(stdout.take(MAX_RESPONSE_BYTES + 1));
        let mut line = String::new();
        let read = stdout.read_line(&mut line);
        let _ = line_tx.send((read.map(|_| line), stdout));
    });

    let outcome = line_rx.recv_timeout(timeout);
    let outcome = match outcome {
        Ok((Ok(line), _stdout)) => {
            if line.len() as u64 > MAX_RESPONSE_BYTES {
                containment.terminate(&mut child);
                finish_threads(writer, reader, &write_rx);
                return Err(format!(
                    "process {label} response exceeds {MAX_RESPONSE_BYTES} bytes"
                ));
            }
            match settle(label, &mut child, &mut containment)? {
                Some(status) if !status.success() => {
                    finish_threads(writer, reader, &write_rx);
                    return Err(format!(
                        "process {label} exited with status {status} (stderr discarded to avoid leaking sensitive input)"
                    ));
                }
                _ => Ok(line),
            }
        }
        Ok((Err(error), _stdout)) => {
            containment.terminate(&mut child);
            Err(format!(
                "process {label} response could not be read: {error}"
            ))
        }
        Err(RecvTimeoutError::Timeout) => {
            containment.terminate(&mut child);
            Err(format!(
                "process {label} timed out after {} ms",
                timeout.as_millis()
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            containment.terminate(&mut child);
            Err(format!(
                "process {label} response channel closed unexpectedly"
            ))
        }
    };

    let write_error = finish_threads(writer, reader, &write_rx);
    match outcome {
        Ok(line) if line.trim().is_empty() => match write_error {
            Some(error) => Err(format!(
                "process {label} request could not be delivered: {error}"
            )),
            None => Ok(line),
        },
        other => other,
    }
}

/// Reap both helper threads within a bound and return a write failure, if any.
fn finish_threads(
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
    write_results: &mpsc::Receiver<std::io::Result<()>>,
) -> Option<std::io::Error> {
    let deadline = Instant::now() + TREE_WAIT;
    join_bounded(writer, deadline);
    join_bounded(reader, deadline);
    // The writer sends its outcome before it exits, so a finished thread has
    // already queued it.
    match write_results.try_recv() {
        Ok(Err(error)) => Some(error),
        _ => None,
    }
}

/// Wait for the child's exit status, allowing a child that has just closed its
/// answer pipe to finish exiting. A child can close its pipes microseconds
/// before the kernel reports its status, so without this grace a non-zero exit
/// would be misreported as an empty response. A child that keeps running is
/// terminated and reports `None`.
fn settle(
    label: &str,
    child: &mut Child,
    containment: &mut Containment,
) -> Result<Option<ExitStatus>, String> {
    let deadline = Instant::now() + EXIT_GRACE;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL_INTERVAL),
            Ok(None) => {
                containment.terminate(child);
                return Ok(None);
            }
            Err(error) => {
                containment.terminate(child);
                return Err(format!("process {label} status could not be read: {error}"));
            }
        }
    }
}
