//! Black-box tests for `sanitize` and `restore` over stdin/stdout.
//!
//! Every test spawns the compiled binary and talks to it exactly like a shell
//! pipeline would; no library function is called directly.

mod common;

use common::{cmd, temp_dir};
use std::path::{Path, PathBuf};

/// `sanitize --session <session> --vault-file <vault>`, `input` on stdin.
fn sanitize(dir: &Path, vault: &Path, session: &str, input: &str) -> String {
    let assert = cmd(dir)
        .args(["sanitize", "--session", session, "--vault-file"])
        .arg(vault)
        .write_stdin(input)
        .assert()
        .success();
    stdout_of(&assert)
}

/// `restore --session <session> --vault-file <vault>`, `input` on stdin.
fn restore(dir: &Path, vault: &Path, session: &str, input: &str) -> String {
    let assert = cmd(dir)
        .args(["restore", "--session", session, "--vault-file"])
        .arg(vault)
        .write_stdin(input)
        .assert()
        .success();
    stdout_of(&assert)
}

/// Captured stdout as text.
fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// Vault file inside `dir`, shared by the processes of one test.
fn vault_path(dir: &Path) -> PathBuf {
    dir.join("vault.json")
}

#[test]
fn sanitize_replaces_pii_in_stdout() {
    let dir = temp_dir();
    let sanitized = sanitize(
        dir.path(),
        &vault_path(dir.path()),
        "test1",
        "contact alice@example.com",
    );
    common::assert_contains_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn restore_recovers_original_from_vault_file() {
    let dir = temp_dir();
    let vault = vault_path(dir.path());
    let original = "contact alice@example.com";
    let sanitized = sanitize(dir.path(), &vault, "test1", original);
    assert!(!sanitized.contains("alice@example.com"), "{sanitized}");
    // A second, separate process reconstructs the raw value from the file.
    let restored = restore(dir.path(), &vault, "test1", &sanitized);
    assert_eq!(restored, original);
}

#[test]
fn sanitize_redacts_secrets() {
    let dir = temp_dir();
    let sanitized = sanitize(
        dir.path(),
        &vault_path(dir.path()),
        "secrets",
        "key is sk-abcdefghijklmnopqrstuvwxyz",
    );
    assert_eq!(sanitized, "key is __DO_PRIVATE_REDACTED__");
}

#[test]
fn restore_across_sessions_is_isolated() {
    let dir = temp_dir();
    let vault = vault_path(dir.path());
    let sanitized = sanitize(dir.path(), &vault, "s1", "alice@example.com");
    common::assert_placeholder(&sanitized, "EMAIL", 1);
    // The mapping lives in `s1` only, so `s2` cannot resolve the placeholder.
    let untouched = restore(dir.path(), &vault, "s2", &sanitized);
    assert_eq!(untouched, sanitized);
}

#[test]
fn sanitize_no_entities_passes_through() {
    let dir = temp_dir();
    let sanitized = sanitize(dir.path(), &vault_path(dir.path()), "plain", "hello world");
    assert_eq!(sanitized, "hello world");
}

#[test]
fn explicit_json_vault_selection_round_trips() {
    let dir = temp_dir();
    let vault = vault_path(dir.path());
    let original = "contact alice@example.com";

    let sanitized = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "json1",
            "--vault",
            "json",
            "--vault-file",
        ])
        .arg(&vault)
        .write_stdin(original)
        .assert()
        .success();
    let sanitized = stdout_of(&sanitized);
    common::assert_contains_placeholder(&sanitized, "EMAIL", 1);

    let restored = cmd(dir.path())
        .args([
            "restore",
            "--session",
            "json1",
            "--vault",
            "json",
            "--vault-file",
        ])
        .arg(&vault)
        .write_stdin(sanitized.as_str())
        .assert()
        .success();
    assert_eq!(stdout_of(&restored), original);
}

/// The context flags are wired to the policy, not just parsed: `trusted`
/// pseudonymizes, `local` keeps. A flag dropped on the way to
/// `ProcessingContext` would make both behave like the default `external`.
#[test]
fn context_flags_drive_the_policy() {
    let dir = temp_dir();
    let vulnerable = cmd(dir.path())
        .args(["sanitize", "--session", "trusted", "--recipient", "trusted"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let pseudonymized = stdout_of(&vulnerable);
    common::assert_placeholder(&pseudonymized, "EMAIL", 1);

    let kept = cmd(dir.path())
        .args(["sanitize", "--session", "local", "--recipient", "local"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    assert_eq!(stdout_of(&kept), "alice@example.com");
}

#[test]
fn sanitize_redacts_database_urls_and_developer_tokens() {
    let dir = temp_dir();
    let db_domain = "DATABASE_URL=postgres://app:s3cr3tpass@db.example.com:5432/production";
    let sanitized_domain = cmd(dir.path())
        .args(["sanitize", "--session", "s_db"])
        .write_stdin(db_domain)
        .assert()
        .success();
    let out_domain = stdout_of(&sanitized_domain);
    assert_eq!(
        out_domain, "DATABASE_URL=__DO_PRIVATE_REDACTED__",
        "database URL with credentials must be redacted whole, not misclassified as email"
    );
    assert!(
        !out_domain.contains("EMAIL"),
        "must not contain email placeholder"
    );

    let db_localhost = "DATABASE_URL=postgres://app:s3cr3tpass@localhost:5432/production";
    let sanitized_local = cmd(dir.path())
        .args(["sanitize", "--session", "s_local"])
        .write_stdin(db_localhost)
        .assert()
        .success();
    assert_eq!(
        stdout_of(&sanitized_local),
        "DATABASE_URL=__DO_PRIVATE_REDACTED__",
        "database URL with localhost must be redacted, not leaked raw"
    );

    let sk = format!(
        "sk_live_{}",
        "51NzABCDEFG1234567890abcdefghijklmnopqrstuvwxyz12345678"
    );
    let pat = format!(
        "github_pat_{}_{}",
        "11A2B3C4D5E6F7G8H9I0J1",
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012"
    );
    let tokens = format!("STRIPE={sk} GITHUB={pat}");
    let sanitized_tokens = cmd(dir.path())
        .args(["sanitize", "--session", "s_tokens"])
        .write_stdin(tokens)
        .assert()
        .success();
    assert_eq!(
        stdout_of(&sanitized_tokens),
        "STRIPE=__DO_PRIVATE_REDACTED__ GITHUB=__DO_PRIVATE_REDACTED__",
        "Stripe keys and GitHub PATs must be redacted"
    );
}
