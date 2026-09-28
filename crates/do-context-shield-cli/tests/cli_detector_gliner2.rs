//! Black-box tests for single-file `gliner2` export validation.
//!
//! A `model_dir` that cannot supply the export's tag names must fail closed
//! through the compiled binary: decoding every token as `O` would report an
//! empty scan for a misconfigured export. These tests need no ONNX runtime —
//! the label map is validated before any session is created.

mod common;

use common::{cmd, temp_dir};
use std::path::{Path, PathBuf};

/// `model_dir` holding `model.onnx`, `tokenizer.json`, and `config.json` with
/// `config` as its contents (`None` leaves the file out).
fn model_dir(root: &Path, config: Option<&str>) -> PathBuf {
    let model = root.join("model");
    if let Err(error) = std::fs::create_dir(&model) {
        panic!("cannot create {}: {error}", model.display());
    }
    for name in ["model.onnx", "tokenizer.json"] {
        let path = model.join(name);
        if let Err(error) = std::fs::write(&path, "") {
            panic!("cannot write {}: {error}", path.display());
        }
    }
    if let Some(config) = config {
        let path = model.join("config.json");
        if let Err(error) = std::fs::write(&path, config) {
            panic!("cannot write {}: {error}", path.display());
        }
    }
    model
}

#[test]
fn missing_config_json_fails_closed() {
    let dir = temp_dir();
    let model = model_dir(dir.path(), None);
    cmd(dir.path())
        .args(["inspect", "--detector", "gliner2", "--model-dir"])
        .arg(&model)
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "config.json not found in model_dir",
        ));
}

#[test]
fn config_json_without_id2label_fails_closed() {
    let dir = temp_dir();
    let model = model_dir(dir.path(), Some(r#"{"model_type":"bert"}"#));
    cmd(dir.path())
        .args(["inspect", "--detector", "gliner2", "--model-dir"])
        .arg(&model)
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("no usable `id2label` map"));
}
