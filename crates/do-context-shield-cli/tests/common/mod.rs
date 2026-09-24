//! Helpers shared by the binary-level CLI integration tests.

// Each test binary uses only a subset of the shared helpers.
#![allow(dead_code)]

use std::path::Path;

/// Assert `text` is exactly one minted placeholder for `kind`/`counter`
/// (`__DO_PRIVATE_<KIND>_<counter>_<16 hex>__`).
pub fn assert_placeholder(text: &str, kind: &str, counter: u64) {
    let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
    let Some(rest) = text.strip_prefix(&prefix) else {
        panic!("`{text}` does not start with `{prefix}`");
    };
    assert_token_entropy(rest, text);
}

/// Assert `text` contains a minted placeholder for `kind`/`counter`.
pub fn assert_contains_placeholder(text: &str, kind: &str, counter: u64) {
    let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
    let Some(start) = text.find(&prefix) else {
        panic!("`{text}` does not contain `{prefix}`");
    };
    assert_token_entropy(&text[start + prefix.len()..], text);
}

/// The remainder after a placeholder prefix: 16 hex characters and `__`.
fn assert_token_entropy(rest: &str, text: &str) {
    let Some(entropy) = rest.strip_suffix("__") else {
        panic!("`{text}` is missing the closing `__`");
    };
    assert_eq!(entropy.len(), 16, "unexpected token entropy in `{text}`");
    assert!(
        entropy.chars().all(|c| c.is_ascii_hexdigit()),
        "unexpected token entropy in `{text}`"
    );
}

/// The compiled `do-context-shield` binary, started with a hermetic working
/// directory and `$HOME` so an ambient `do-context-shield.toml` or
/// `$HOME/.config/do-context-shield/config.toml` can never change a test.
pub fn cmd(dir: &Path) -> assert_cmd::Command {
    let mut command = match assert_cmd::Command::cargo_bin("do-context-shield") {
        Ok(command) => command,
        Err(error) => panic!("binary `do-context-shield` is not built: {error}"),
    };
    command.current_dir(dir).env("HOME", dir);
    command
}

/// Fresh temporary directory, removed when the returned handle is dropped.
pub fn temp_dir() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    }
}
