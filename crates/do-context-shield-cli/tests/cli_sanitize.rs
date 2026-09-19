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
    assert_eq!(sanitized, "contact __DO_PRIVATE_EMAIL_1__");
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
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");
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
