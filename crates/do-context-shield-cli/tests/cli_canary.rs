//! Black-box tests for `sanitize --canary-key-file` and `verify-canary`.
//!
//! Every test spawns the compiled binary, like a shell pipeline would.

mod common;

use common::{cmd, temp_dir};
use std::path::{Path, PathBuf};

/// A 64-hex-character canary key file inside `dir`, owner-only on Unix.
fn key_file(dir: &Path, name: &str, hex: &str) -> PathBuf {
    let path = dir.join(name);
    if let Err(error) = std::fs::write(&path, format!("{hex}\n")) {
        panic!("cannot write {}: {error}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            panic!("cannot restrict {}: {error}", path.display());
        }
    }
    path
}

/// Canary key: 32 bytes as hex, built without a literal secret in source.
fn canary_hex() -> String {
    "ab".repeat(32)
}

/// Run `sanitize` with a canary key and return stdout.
fn sanitize_with_canary(dir: &Path, key: &Path, session: &str, input: &str) -> String {
    let vault = dir.join("vault.json");
    let assert = cmd(dir)
        .args(["sanitize", "--session", session, "--vault-file"])
        .arg(&vault)
        .arg("--canary-key-file")
        .arg(key)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// `verify-canary` over `input`; returns whether the command succeeded.
fn verify(dir: &Path, key: &Path, session: &str, input: &str) -> bool {
    cmd(dir)
        .args(["verify-canary", "--session", session, "--canary-key-file"])
        .arg(key)
        .write_stdin(input)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[test]
fn sanitize_appends_a_marker_that_verifies_for_its_session() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let key = key_file(dir, "canary.key", &canary_hex());
    let out = sanitize_with_canary(dir, &key, "s1", "Email alice@example.com today");
    assert!(out.contains("<!-- do-context-shield-canary: "), "{out}");
    assert!(
        verify(dir, &key, "s1", &out),
        "same-session marker must verify: {out}"
    );
}

#[test]
fn marker_is_not_valid_for_another_session() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let key = key_file(dir, "canary.key", &canary_hex());
    let out = sanitize_with_canary(dir, &key, "s1", "plain text");
    assert!(
        !verify(dir, &key, "s2", &out),
        "wrong session must fail closed"
    );
}

#[test]
fn unmarked_text_fails_verification() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let key = key_file(dir, "canary.key", &canary_hex());
    assert!(!verify(dir, &key, "s1", "no marker here"));
}

#[test]
fn marker_is_not_valid_under_a_different_key() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let key = key_file(dir, "canary.key", &canary_hex());
    let other = key_file(dir, "other.key", &"cd".repeat(32));
    let out = sanitize_with_canary(dir, &key, "s1", "plain text");
    assert!(!verify(dir, &other, "s1", &out), "wrong key must fail");
}

#[cfg(unix)]
#[test]
fn group_or_world_readable_key_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = temp_dir();
    let dir = tmp.path();
    let key = key_file(dir, "canary.key", &canary_hex());
    if let Err(error) = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)) {
        panic!("cannot widen {}: {error}", key.display());
    }
    let output = cmd(dir)
        .args(["verify-canary", "--session", "s1", "--canary-key-file"])
        .arg(&key)
        .write_stdin("anything")
        .output();
    let Ok(output) = output else {
        panic!("cannot run verify-canary");
    };
    assert!(!output.status.success(), "a loose key file must be refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("chmod 600"), "{stderr}");
}
