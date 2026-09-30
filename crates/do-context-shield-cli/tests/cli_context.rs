//! Black-box tests for the documented enforcement-context flags on `sanitize`.
//!
//! `--recipient`, `--data-category`, `--purpose`, and `--jurisdiction` are the
//! CLI surface of the recipient-aware policy: every value must reach the policy
//! (the process-plugin wire included) instead of being silently dropped.

mod common;

use common::{cmd, process_command, temp_dir};
use std::path::Path;

/// `sanitize --session ctx <extra…>`, `input` on stdin; stdout on success.
fn sanitize(dir: &Path, extra: &[&str], input: &str) -> String {
    let assert = cmd(dir)
        .args(["sanitize", "--session", "ctx"])
        .args(extra)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn local_recipient_keeps_personal_values() {
    let dir = temp_dir();
    let kept = sanitize(dir.path(), &["--recipient", "local"], "alice@example.com");
    assert_eq!(kept, "alice@example.com");
    // Control: the default `external` recipient pseudonymizes the same value.
    let defaulted = sanitize(dir.path(), &[], "alice@example.com");
    common::assert_placeholder(&defaulted, "EMAIL", 1);
}

#[test]
fn special_category_blocks_external_recipients() {
    let dir = temp_dir();
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "ctx",
            "--data-category",
            "special_category",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("blocked by policy"));
}

#[test]
fn unknown_recipient_blocks_personal_data() {
    let dir = temp_dir();
    cmd(dir.path())
        .args(["sanitize", "--session", "ctx", "--recipient", "unknown"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("blocked by policy"));
}

#[test]
fn unknown_context_values_exit_2() {
    let dir = temp_dir();
    for (flag, value) in [("--recipient", "nope"), ("--data-category", "nope")] {
        cmd(dir.path())
            .args(["sanitize", "--session", "ctx", flag, value])
            .write_stdin("")
            .assert()
            .code(2)
            .stderr(predicates::str::contains("invalid value"));
    }
}

#[test]
fn context_flags_reach_the_process_policy() {
    let dir = temp_dir();
    let command = process_command("plan-context");
    let base = ["--policy", "process", "--policy-command", command.as_str()];
    // The child keeps for `local`, `legal-hold`, and `DE` and redacts anything
    // else, so a kept value proves that field crossed the child boundary.
    for extra in [
        ["--recipient", "local"],
        ["--purpose", "legal-hold"],
        ["--jurisdiction", "DE"],
    ] {
        let mut flags = base.to_vec();
        flags.extend_from_slice(&extra);
        let kept = sanitize(dir.path(), &flags, "alice@example.com");
        assert_eq!(kept, "alice@example.com", "flags: {flags:?}");
    }
    // Control: without a context flag the same child redacts.
    let redacted = sanitize(dir.path(), &base, "alice@example.com");
    assert_eq!(redacted, "__DO_PRIVATE_REDACTED__");
}

#[test]
fn special_category_to_trusted_without_jurisdiction_blocks() {
    let dir = temp_dir();
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "ctx",
            "--recipient",
            "trusted",
            "--data-category",
            "special_category",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("blocked by policy"));
}

#[test]
fn special_category_to_trusted_with_a_jurisdiction_pseudonymizes() {
    let dir = temp_dir();
    // The shape contract is exactly two ASCII letters; case is preserved, not
    // normalized, so both spellings must keep the declared-jurisdiction path.
    for jurisdiction in ["DE", "de"] {
        let pseudonymized = sanitize(
            dir.path(),
            &[
                "--recipient",
                "trusted",
                "--data-category",
                "special_category",
                "--jurisdiction",
                jurisdiction,
            ],
            "alice@example.com",
        );
        common::assert_placeholder(&pseudonymized, "EMAIL", 1);
    }
}

#[test]
fn malformed_jurisdiction_exits_2_before_processing() {
    // A malformed code must never satisfy the declared-jurisdiction condition:
    // it is an argument error, rejected before stdin is read, so a typo cannot
    // become another way to declare trust for special-category data.
    let dir = temp_dir();
    for value in ["", "Germany", "DEU", "de-DE", "D1", "é"] {
        let assert = cmd(dir.path())
            .args([
                "sanitize",
                "--session",
                "ctx",
                "--recipient",
                "trusted",
                "--data-category",
                "special_category",
                "--jurisdiction",
                value,
            ])
            .write_stdin("alice@example.com")
            .assert()
            .code(2)
            .stderr(predicates::str::contains("ISO 3166-1 alpha-2"));
        let output = assert.get_output();
        assert!(output.stdout.is_empty(), "rejected input produced stdout");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("alice@example.com"),
            "stdin must not be echoed"
        );
    }
}

#[test]
fn purpose_alone_never_loosens() {
    // `purpose` is forwarded intent for policy plugins; the built-in default
    // does not read it, so it cannot keep a value the recipient rules
    // pseudonymize.
    let dir = temp_dir();
    let pseudonymized = sanitize(
        dir.path(),
        &["--purpose", "support", "--recipient", "external"],
        "alice@example.com",
    );
    common::assert_placeholder(&pseudonymized, "EMAIL", 1);
}
