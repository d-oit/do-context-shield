//! Black-box tests for the non-reversible transformers (`generalize`, `mask`).

mod common;

use common::{cmd, temp_dir};
use std::path::Path;

/// `sanitize --transformer <name> --session s --vault-file <vault>` on stdin.
fn sanitize(dir: &Path, transformer: &str, vault: &Path, input: &str) -> String {
    let assert = cmd(dir)
        .args([
            "sanitize",
            "--session",
            "s",
            "--transformer",
            transformer,
            "--vault-file",
        ])
        .arg(vault)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// `restore --session s --vault-file <vault>` on stdin.
fn restore(dir: &Path, vault: &Path, input: &str) -> String {
    let assert = cmd(dir)
        .args(["restore", "--session", "s", "--vault-file"])
        .arg(vault)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// Vault file contents, or an empty string when nothing was written.
fn vault_contents(vault: &Path) -> String {
    std::fs::read_to_string(vault).unwrap_or_default()
}

#[test]
fn generalize_collapses_values_into_kind_tokens() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let sanitized = sanitize(
        dir.path(),
        "generalize",
        &vault,
        "mail alice@example.com and bob@example.com",
    );
    // Two different addresses of one kind share one token: identity is
    // deliberately given up, only the type stays visible.
    assert_eq!(
        sanitized,
        "mail __DO_PRIVATE_EMAIL__ and __DO_PRIVATE_EMAIL__"
    );
}

#[test]
fn generalize_output_is_not_restorable() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let sanitized = sanitize(dir.path(), "generalize", &vault, "mail alice@example.com");
    assert_eq!(sanitized, "mail __DO_PRIVATE_EMAIL__");
    // Nothing was stored, so the same session and vault cannot resolve it.
    assert_eq!(restore(dir.path(), &vault, &sanitized), sanitized);
    assert!(!vault_contents(&vault).contains("alice@example.com"));
}

#[test]
fn mask_reveals_only_the_tail() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let sanitized = sanitize(dir.path(), "mask", &vault, "mail alice@example.com");
    assert_eq!(sanitized, "mail *************.com");
    // Masked text carries no placeholder and no mapping, so restore is a no-op.
    assert_eq!(restore(dir.path(), &vault, &sanitized), sanitized);
    assert!(!vault_contents(&vault).contains("alice@example.com"));
}

#[test]
fn secrets_stay_redacted_under_both_transformers() {
    // Synthetic fixture built programmatically so no secret-like literal is committed.
    let api_key = format!("sk-test-{}", "0123456789abcdef");
    let input = format!("key {api_key}");
    let dir = temp_dir();
    for transformer in ["generalize", "mask"] {
        let vault = dir.path().join(format!("{transformer}.json"));
        let sanitized = sanitize(dir.path(), transformer, &vault, &input);
        assert!(
            sanitized.contains("__DO_PRIVATE_REDACTED__"),
            "{transformer}: {sanitized}"
        );
        assert!(!sanitized.contains(&api_key), "{transformer}: {sanitized}");
    }
}
