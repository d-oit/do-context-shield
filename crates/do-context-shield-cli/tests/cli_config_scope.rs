//! Black-box tests for which configuration sections each subcommand acts on.
//!
//! `docs/configuration.md` documents the per-command applicability. These tests
//! pin the consequence: a plugin selection that cannot be built fails only the
//! commands that actually run that stage, so a broken `[plugins] policy` cannot
//! break `restore`/`inspect`/`forget`, and a broken `[vault]` cannot break
//! `inspect`.

mod common;

use common::{cmd, temp_dir};
use std::path::Path;

/// Run one subcommand with `config` written into the working directory.
fn run(dir: &Path, config: &str, args: &[&str]) -> assert_cmd::assert::Assert {
    if let Err(error) = std::fs::write(dir.join("do-context-shield.toml"), config) {
        panic!("cannot write the config: {error}");
    }
    cmd(dir)
        .args(args)
        .write_stdin("alice@example.com")
        .assert()
}

/// A `process` policy without a command cannot be constructed.
const BROKEN_POLICY: &str = "[plugins]\npolicy = \"process\"\n";
/// A `process` detector without a command cannot be constructed.
const BROKEN_DETECTOR: &str = "[plugins]\ndetector = \"process\"\n";
/// A `process` vault without a command cannot be constructed.
const BROKEN_VAULT: &str = "[vault]\nvault = \"process\"\n";

#[test]
fn a_broken_policy_selection_only_fails_sanitize() {
    let dir = temp_dir();
    run(dir.path(), BROKEN_POLICY, &["sanitize", "--session", "s"])
        .code(1)
        .stderr(predicates::str::contains("process policy unavailable"));
    run(dir.path(), BROKEN_POLICY, &["inspect"]).success();
    run(dir.path(), BROKEN_POLICY, &["restore", "--session", "s"]).success();
    run(dir.path(), BROKEN_POLICY, &["forget", "--session", "s"]).success();
}

#[test]
fn a_broken_detector_selection_fails_sanitize_and_inspect_only() {
    let dir = temp_dir();
    run(dir.path(), BROKEN_DETECTOR, &["sanitize", "--session", "s"])
        .code(1)
        .stderr(predicates::str::contains("process detector unavailable"));
    run(dir.path(), BROKEN_DETECTOR, &["inspect"])
        .code(1)
        .stderr(predicates::str::contains("detector"));
    run(dir.path(), BROKEN_DETECTOR, &["forget", "--session", "s"]).success();
}

#[test]
fn a_broken_vault_selection_never_fails_inspect() {
    let dir = temp_dir();
    run(dir.path(), BROKEN_VAULT, &["sanitize", "--session", "s"]).code(1);
    run(dir.path(), BROKEN_VAULT, &["restore", "--session", "s"]).code(1);
    run(dir.path(), BROKEN_VAULT, &["forget", "--session", "s"]).code(1);
    run(dir.path(), BROKEN_VAULT, &["inspect"]).success();
}
