//! Black-box tests for `inspect` and `forget` over stdin/stdout.

mod common;

use common::{cmd, temp_dir};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// `inspect`, `input` on stdin.
fn inspect(dir: &Path, input: &str) -> String {
    let assert = cmd(dir)
        .arg("inspect")
        .write_stdin(input)
        .assert()
        .success();
    stdout_of(&assert)
}

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

/// `forget --session <session> --vault-file <vault>`.
fn forget(dir: &Path, vault: &Path, session: &str) {
    cmd(dir)
        .args(["forget", "--session", session, "--vault-file"])
        .arg(vault)
        .write_stdin("")
        .assert()
        .success();
}

/// Captured stdout as text.
fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// Parse captured stdout as JSON, naming the raw output on failure.
fn parse_json(stdout: &str) -> Value {
    match serde_json::from_str(stdout) {
        Ok(value) => value,
        Err(error) => panic!("stdout is not valid JSON: {error} (stdout: {stdout:?})"),
    }
}

/// Vault file inside `dir`, shared by the processes of one test.
fn vault_path(dir: &Path) -> PathBuf {
    dir.join("vault.json")
}

#[test]
fn inspect_outputs_entity_json() {
    let dir = temp_dir();
    let stdout = inspect(dir.path(), "alice@example.com");
    // The privacy invariant: inspect reports kind/span/confidence, never text.
    assert!(!stdout.contains("alice@example.com"), "{stdout}");
    let value = parse_json(&stdout);
    let Some(entities) = value.get("entities").and_then(Value::as_array) else {
        panic!("missing entities array in {stdout}");
    };
    assert_eq!(entities.len(), 1, "{stdout}");
    assert_eq!(entities[0]["kind"], "email", "{stdout}");
}

#[test]
fn inspect_empty_input_returns_empty_entities() {
    let dir = temp_dir();
    let value = parse_json(&inspect(dir.path(), "hello"));
    assert_eq!(value, serde_json::json!({"entities": []}));
}

#[test]
fn forget_clears_vault_session() {
    let dir = temp_dir();
    let vault = vault_path(dir.path());
    let sanitized = sanitize(dir.path(), &vault, "gone", "alice@example.com");
    common::assert_placeholder(&sanitized, "EMAIL", 1);
    forget(dir.path(), &vault, "gone");
    // The mapping is purged from the file, so the placeholder stays unresolved.
    let restored = restore(dir.path(), &vault, "gone", &sanitized);
    assert_eq!(restored, sanitized);
}

#[test]
fn forget_preserves_other_sessions() {
    let dir = temp_dir();
    let vault = vault_path(dir.path());
    let first = sanitize(dir.path(), &vault, "s1", "alice@example.com");
    let second = sanitize(dir.path(), &vault, "s2", "bob@example.com");
    common::assert_placeholder(&second, "EMAIL", 1);
    forget(dir.path(), &vault, "s1");
    let still_resolvable = restore(dir.path(), &vault, "s2", &second);
    assert_eq!(still_resolvable, "bob@example.com");
    let purged = restore(dir.path(), &vault, "s1", &first);
    assert_eq!(purged, first);
}
