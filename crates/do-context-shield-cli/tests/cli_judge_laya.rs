//! Black-box tests for the Laya judge sidecar example
//! (`examples/laya-judge.py --stub`).
//!
//! Every test spawns the compiled binary and the sidecar exactly like a shell
//! pipeline would. The sidecar runs with its offline `--stub` agent, so these
//! tests need no model download and no `laya` package; the real-model path is
//! a documented manual check (`docs/process-plugin.md`). A platform without
//! `python3` skips the tests with a note.

mod common;

use common::{cmd, temp_dir};
use std::path::Path;
use std::process::Command;

/// Command line selecting the example sidecar in offline stub mode.
fn laya_stub_command() -> String {
    format!(
        "python3 {} --stub",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/laya-judge.py")
    )
}

/// Whether `python3` is available to spawn the sidecar fixture.
fn python3_available() -> bool {
    matches!(
        Command::new("python3").arg("--version").output(),
        Ok(output) if output.status.success()
    )
}

/// Prints a skip note and returns `true` when `python3` is unavailable, so a
/// platform without the interpreter (some Windows runners) skips instead of
/// failing; Linux and macOS CI keep executing these tests.
fn skip_without_python3() -> bool {
    if python3_available() {
        return false;
    }
    eprintln!("skip: python3 is required for the laya judge tests");
    true
}

/// `sanitize --session laya1 --judge process --judge-command <stub>`, `input`
/// on stdin; asserts success and returns captured stdout.
fn sanitize_with_laya(dir: &Path, input: &str) -> String {
    let assert = cmd(dir)
        .args([
            "sanitize",
            "--session",
            "laya1",
            "--judge",
            "process",
            "--judge-command",
        ])
        .arg(laya_stub_command())
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn business_labeled_email_is_kept() {
    if skip_without_python3() {
        return;
    }
    let dir = temp_dir();
    let sanitized = sanitize_with_laya(dir.path(), "contact support@acme.com");
    assert_eq!(sanitized, "contact support@acme.com");
}

#[test]
fn reserved_domain_value_is_kept() {
    if skip_without_python3() {
        return;
    }
    let dir = temp_dir();
    let sanitized = sanitize_with_laya(dir.path(), "contact alice@example.org");
    assert_eq!(sanitized, "contact alice@example.org");
}

#[test]
fn abstained_email_is_pseudonymized() {
    if skip_without_python3() {
        return;
    }
    let dir = temp_dir();
    let sanitized = sanitize_with_laya(dir.path(), "meet alice@personalmail.net");
    assert_eq!(sanitized, "meet __DO_PRIVATE_EMAIL_1__");
}
