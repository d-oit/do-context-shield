//! Model-backed end-to-end tests: the compiled binary, a real `GLiNER2` export,
//! and a real ONNX Runtime, driven exactly like a shell pipeline would.
//!
//! These tests run only when both are configured through the environment:
//! `ORT_DYLIB_PATH` points at the `libonnxruntime.so` matching the `ort`
//! release (1.28.x; see `docs/plugins.md`) and `DO_CONTEXT_SHIELD_E2E_MODEL_DIR`
//! at an absolute path to a fragment export (`fp16_v2/` or `fp32_v2/` holding
//! the eight fragments and `tokenizer.json`). With either variable unset the
//! tests skip with a note, so the default suite and CI stay light; the test
//! target itself only builds with `--features gliner2`.

mod common;

use common::{cmd, temp_dir};
use std::path::PathBuf;

/// The configured runtime and model directory, or `None` when the tests should
/// skip. A partially configured setup fails loudly instead of skipping.
fn model_setup() -> Option<(PathBuf, PathBuf)> {
    let (ort, model) = if let (Some(ort), Some(model)) = (
        std::env::var_os("ORT_DYLIB_PATH"),
        std::env::var_os("DO_CONTEXT_SHIELD_E2E_MODEL_DIR"),
    ) {
        (PathBuf::from(ort), PathBuf::from(model))
    } else {
        eprintln!(
            "skip: set ORT_DYLIB_PATH and DO_CONTEXT_SHIELD_E2E_MODEL_DIR to run the model-backed E2E tests"
        );
        return None;
    };
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

/// Captured stdout as text.
fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn gliner2_sanitizes_multibyte_input() {
    let Some((ort, model)) = model_setup() else {
        return;
    };
    let dir = temp_dir();
    let assert = cmd(dir.path())
        .env("ORT_DYLIB_PATH", &ort)
        .args(["sanitize", "--detector", "gliner2", "--model-dir"])
        .arg(&model)
        .write_stdin("Grüße von Jane Doe, jane@example.com.")
        .assert()
        .success();
    let stdout = stdout_of(&assert);
    assert_eq!(
        stdout,
        "Grüße von __DO_PRIVATE_FULL_NAME_1__, __DO_PRIVATE_EMAIL_1__."
    );
    assert!(!stdout.contains("jane@example.com"), "{stdout}");
}

#[test]
fn gliner2_finds_tail_entities_in_chunked_input() {
    let Some((ort, model)) = model_setup() else {
        return;
    };
    let dir = temp_dir();
    let filler = "Filler sentence without personal data. ".repeat(30);
    let input = format!("{filler}Contact Jane Doe at jane@example.com.");
    let assert = cmd(dir.path())
        .env("ORT_DYLIB_PATH", &ort)
        .args(["sanitize", "--detector", "gliner2", "--model-dir"])
        .arg(&model)
        .write_stdin(input)
        .assert()
        .success();
    let stdout = stdout_of(&assert);
    assert_eq!(
        stdout,
        format!("{filler}Contact __DO_PRIVATE_FULL_NAME_1__ at __DO_PRIVATE_EMAIL_1__.")
    );
}

#[test]
fn hybrid_merges_regex_and_model_spans() {
    let Some((ort, model)) = model_setup() else {
        return;
    };
    let dir = temp_dir();
    let assert = cmd(dir.path())
        .env("ORT_DYLIB_PATH", &ort)
        .args(["sanitize", "--detector", "hybrid", "--model-dir"])
        .arg(&model)
        .write_stdin("Jane Doe, SSN 123-45-6789, card 4111 1111 1111 1111.")
        .assert()
        .success();
    let stdout = stdout_of(&assert);
    assert_eq!(
        stdout,
        "__DO_PRIVATE_FULL_NAME_1__, SSN __DO_PRIVATE_SSN_1__, card __DO_PRIVATE_CREDIT_CARD_1__."
    );
    assert!(!stdout.contains("123-45-6789"), "{stdout}");
    assert!(!stdout.contains("4111 1111 1111 1111"), "{stdout}");
}
