//! Black-box tests for `--detector hybrid` (regex plus the `GLiNER2` model).
//!
//! The hybrid must never degrade to the detector that happens to work: a
//! missing or unusable model half fails the call even when the regex half
//! finds nothing (the inputs below are plain text, which the default regex
//! detector alone would pass through untouched).

mod common;

use common::{cmd, temp_dir};
use std::path::Path;

/// Captured stderr as text.
fn stderr_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).into_owned()
}

#[test]
fn hybrid_without_model_dir_fails_closed() {
    let dir = temp_dir();
    let assert = cmd(dir.path())
        .args(["sanitize", "--session", "s", "--detector", "hybrid"])
        .write_stdin("hello world")
        .assert()
        .failure();
    let stderr = stderr_of(&assert);
    assert!(stderr.contains("model_dir"), "{stderr}");
}

#[test]
fn hybrid_with_missing_model_dir_fails_closed() {
    let dir = temp_dir();
    let model_dir = dir.path().join("no-such-model");
    let assert = cmd(dir.path())
        .args(["inspect", "--detector", "hybrid", "--model-dir"])
        .arg(&model_dir)
        .write_stdin("hello world")
        .assert()
        .failure();
    let stderr = stderr_of(&assert);
    assert!(stderr.contains("does not exist"), "{stderr}");
}

#[test]
fn hybrid_with_empty_model_dir_fails_closed() {
    let dir = temp_dir();
    let model_dir = dir.path().join("empty-model");
    create_dir(&model_dir);
    let assert = cmd(dir.path())
        .args(["inspect", "--detector", "hybrid", "--model-dir"])
        .arg(&model_dir)
        .write_stdin("hello world")
        .assert()
        .failure();
    let stderr = stderr_of(&assert);
    assert!(stderr.contains("gliner2"), "{stderr}");
}

/// Create `dir`, panicking with context on failure.
fn create_dir(dir: &Path) {
    if let Err(error) = std::fs::create_dir_all(dir) {
        panic!("cannot create {}: {error}", dir.display());
    }
}
