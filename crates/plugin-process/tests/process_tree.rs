//! Process-tree lifetime: a timeout terminates descendants, not only the
//! direct executable, and does not wait on a pipe they inherited.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use do_context_shield_plugin_api::Detector;
use do_context_shield_plugin_process::{ProcessConfig, ProcessDetector};

fn tree_command(pid_file: &Path) -> String {
    format!(
        "sh {} {}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tree.sh"),
        pid_file.display()
    )
}

/// Whether `kill -0 <pid>` still reports the process (zombies of a dead
/// grandchild are reparented and reaped, so this is a real liveness probe).
#[cfg(unix)]
fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(unix)]
fn assert_gone(pid: u32, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "{label}: descendant {pid} survived the timeout"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn wait_for_pid_file(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the fixture never reported its grandchild pid"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
#[test]
fn timeout_kills_the_whole_process_tree() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let pid_file: PathBuf = dir.path().join("grandchild.pid");
    let detector = ProcessDetector::new(
        ProcessConfig::with_command(tree_command(&pid_file))
            .with_timeout(Duration::from_millis(800)),
    );

    let started = Instant::now();
    let message = match detector.detect("alice@example.com") {
        Ok(entities) => panic!("expected a timeout error, got {entities:?}"),
        Err(error) => error.to_string(),
    };
    let elapsed = started.elapsed();
    assert!(message.contains("timed out"), "got: {message}");
    // Bounded: the response wait, the exit grace, and the tree wait only.
    assert!(
        elapsed < Duration::from_secs(3),
        "timeout did not stay bounded, elapsed {elapsed:?}"
    );

    let grandchild = wait_for_pid_file(&pid_file);
    assert_gone(grandchild, "timeout");
}

#[cfg(windows)]
fn alive(pid: u32) -> bool {
    // `tasklist` reports a running process; a terminated job member is gone.
    let filter = format!("PID eq {pid}");
    Command::new("tasklist")
        .args(["/FI", &filter, "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(windows)]
#[test]
fn timeout_kills_the_whole_process_tree() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let pid_file: PathBuf = dir.path().join("grandchild.pid");
    let detector = ProcessDetector::new(
        ProcessConfig::with_command(tree_command(&pid_file))
            .with_timeout(Duration::from_millis(800)),
    );

    let started = Instant::now();
    let message = match detector.detect("alice@example.com") {
        Ok(entities) => panic!("expected a timeout error, got {entities:?}"),
        Err(error) => error.to_string(),
    };
    let elapsed = started.elapsed();
    assert!(message.contains("timed out"), "got: {message}");
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout did not stay bounded, elapsed {elapsed:?}"
    );

    let grandchild = wait_for_pid_file(&pid_file);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(grandchild) {
        assert!(
            Instant::now() < deadline,
            "descendant {grandchild} survived the timeout"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn wait_for_pid_file(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the fixture never reported its grandchild pid"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
