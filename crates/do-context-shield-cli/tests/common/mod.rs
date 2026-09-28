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

/// Every environment variable the binary reads. Cleared by [`cmd`] so an
/// ambient value can never change a test.
pub const CONFIG_ENV_VARS: [&str; 13] = [
    "DO_CONTEXT_SHIELD_DATA_CATEGORY",
    "DO_CONTEXT_SHIELD_DETECTOR",
    "DO_CONTEXT_SHIELD_JUDGE",
    "DO_CONTEXT_SHIELD_JURISDICTION",
    "DO_CONTEXT_SHIELD_POLICY",
    "DO_CONTEXT_SHIELD_PURPOSE",
    "DO_CONTEXT_SHIELD_RECIPIENT",
    "DO_CONTEXT_SHIELD_TOOLS",
    "DO_CONTEXT_SHIELD_TRANSFORMER",
    "DO_CONTEXT_SHIELD_VAULT",
    "DO_CONTEXT_SHIELD_VAULT_FILE",
    "DO_CONTEXT_SHIELD_VAULT_KEY_FILE",
    "DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS",
];

/// The compiled `do-context-shield` binary, started with a hermetic working
/// directory, `$HOME`, and `DO_CONTEXT_SHIELD_*` environment so an ambient
/// `do-context-shield.toml` or config override can never change a test.
pub fn cmd(dir: &Path) -> assert_cmd::Command {
    let mut command = match assert_cmd::Command::cargo_bin("do-context-shield") {
        Ok(command) => command,
        Err(error) => panic!("binary `do-context-shield` is not built: {error}"),
    };
    command.current_dir(dir).env("HOME", dir);
    for name in CONFIG_ENV_VARS {
        command.env_remove(name);
    }
    command
}

/// Command line invoking the process-protocol fixture in `mode`.
///
/// The fixture belongs to the protocol implementation
/// (`crates/plugin-process/tests/fixtures/plugin.sh`), which asserts the wire
/// format itself; the CLI tests reuse it to drive the documented
/// `--detector`/`--policy`/`--transformer`/`--vault process` selections through
/// the compiled binary.
pub fn process_command(mode: &str) -> String {
    format!(
        "sh {}/../plugin-process/tests/fixtures/plugin.sh {mode}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Fresh temporary directory, removed when the returned handle is dropped.
pub fn temp_dir() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    }
}

/// The configured ONNX Runtime and model directory, or `None` when the
/// model-backed tests should skip.
///
/// Both `ORT_DYLIB_PATH` (the runtime pinned in `docs/plugins.md`) and
/// `DO_CONTEXT_SHIELD_E2E_MODEL_DIR` (an absolute fragment export) are needed.
/// Neither set: skip with a note. Only the model directory set: fail, because
/// that is a half-configured run rather than an unconfigured one. CI sets
/// `DO_HARNESS_REQUIRE_ORT=1` after provisioning the runtime, which turns an
/// unset runtime into a failure so a broken download cannot silently skip the
/// runtime-backed tests.
pub fn model_setup() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let (ort, model) = (
        std::env::var_os("ORT_DYLIB_PATH"),
        std::env::var_os("DO_CONTEXT_SHIELD_E2E_MODEL_DIR"),
    );
    assert!(
        !(ort.is_none() && model.is_some()),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR is set but ORT_DYLIB_PATH is not; provide both or neither"
    );
    assert!(
        !(ort.is_none() && std::env::var("DO_HARNESS_REQUIRE_ORT").is_ok_and(|value| value == "1")),
        "DO_HARNESS_REQUIRE_ORT=1 but ORT_DYLIB_PATH is unset; CI must provision the pinned ONNX Runtime (docs/plugins.md)"
    );
    let (Some(ort), Some(model)) = (ort, model) else {
        eprintln!(
            "skip: set ORT_DYLIB_PATH and DO_CONTEXT_SHIELD_E2E_MODEL_DIR to run the model-backed E2E tests"
        );
        return None;
    };
    let (ort, model) = (
        std::path::PathBuf::from(ort),
        std::path::PathBuf::from(model),
    );
    assert!(
        ort.is_file(),
        "ORT_DYLIB_PATH is not a file: {}",
        ort.display()
    );
    assert!(
        model.is_absolute(),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR must be absolute (the binary runs in a temp directory): {}",
        model.display()
    );
    assert!(
        model.is_dir(),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR is not a directory: {}",
        model.display()
    );
    Some((ort, model))
}
