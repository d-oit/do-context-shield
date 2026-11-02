//! Black-box tests for `doctor`: local detector preflight without a scan.
//!
//! Every test spawns the compiled binary. The probe never reads stdin, never
//! downloads anything, and reports only stable categories and fixed guidance.

mod common;

use std::path::{Path, PathBuf};

use common::{cmd, temp_dir};
use serde_json::Value;

fn temp_dir_with(names: &[&str]) -> tempfile::TempDir {
    let dir = temp_dir();
    for name in names {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            panic!("cannot create fixture directory: {error}");
        }
        if let Err(error) = std::fs::write(&path, b"") {
            panic!("cannot write fixture file: {error}");
        }
    }
    dir
}

/// Run `doctor` with `args`; return (stdout, stderr, success).
fn doctor(dir: &Path, args: &[&str]) -> (String, String, bool) {
    let assert = cmd(dir).arg("doctor").args(args).assert();
    let output = assert.get_output().clone();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (stdout, stderr, output.status.success())
}

fn json_report(dir: &Path, args: &[&str]) -> (Value, bool) {
    let (stdout, stderr, success) = doctor(dir, args);
    let report: Value = match serde_json::from_str(stdout.trim()) {
        Ok(report) => report,
        Err(error) => panic!("doctor did not emit JSON ({error}): {stdout:?} / {stderr:?}"),
    };
    (report, success)
}

#[test]
fn regex_is_ready_and_reports_no_model_limits() {
    let dir = temp_dir();
    let (report, success) = json_report(dir.path(), &["--detector", "regex", "--format", "json"]);
    assert!(success, "{report}");
    assert_eq!(report["detector"], "regex");
    assert_eq!(report["available"], true);
    assert_eq!(report["reason_code"], "ready");
    assert!(report.get("max_tokens").is_none(), "{report}");
    assert!(report.get("layout").is_none(), "{report}");
}

#[test]
fn unconfigured_and_missing_directories_are_distinct() {
    let dir = temp_dir();
    let (report, success) = json_report(dir.path(), &["--detector", "gliner2", "--format", "json"]);
    assert!(!success);
    assert_eq!(report["reason_code"], "not_configured");

    let missing = dir.path().join("no-such-model-dir");
    let (report, success) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &missing.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert!(!success);
    assert_eq!(report["reason_code"], "missing_model_dir");
}

#[test]
fn unsupported_and_incomplete_exports_are_distinct() {
    let dir = temp_dir();

    let boundary = temp_dir_with(&["boundary_manifest.json"]);
    let (report, success) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &boundary.path().to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert!(!success);
    assert_eq!(report["reason_code"], "unsupported_export");

    let incomplete = temp_dir_with(&["encoder.onnx", "span_rep.onnx"]);
    let (report, success) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &incomplete.path().to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert!(!success);
    assert_eq!(report["reason_code"], "incomplete_fragments");
    assert_eq!(report["layout"], "fragments");
}

#[test]
fn single_file_layout_failures_name_the_missing_piece() {
    let dir = temp_dir();
    let missing_tokenizer = temp_dir_with(&["model.onnx", "config.json"]);
    let (report, _) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &missing_tokenizer.path().to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(report["reason_code"], "missing_tokenizer");
    assert_eq!(report["layout"], "single_file");

    let unusable_labels = temp_dir_with(&["model.onnx", "tokenizer.json", "config.json"]);
    let (report, _) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &unusable_labels.path().to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(report["reason_code"], "missing_labels");
}

#[test]
fn complete_export_reports_limits_and_never_looks_ready_without_a_backend() {
    // A valid file layout with unusable contents: the default (feature-off)
    // build reports `feature_disabled`; an --all-features build tries the real
    // load and reports `runtime_unavailable`. Neither may report `ready`.
    let dir = temp_dir();
    let model = temp_dir_with(&["model.onnx", "tokenizer.json", "config.json"]);
    if let Err(error) = std::fs::write(
        model.path().join("config.json"),
        r#"{"id2label":{"0":"B-name","1":"O"}}"#,
    ) {
        panic!("cannot write config.json: {error}");
    }
    let (report, success) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &model.path().to_string_lossy(),
            "--model-max-tokens",
            "64",
            "--model-threads",
            "1",
            "--format",
            "json",
        ],
    );
    assert!(!success);
    assert_eq!(report["available"], false);
    let code = report["reason_code"].as_str().unwrap_or_default();
    assert!(
        code == "feature_disabled" || code == "runtime_unavailable",
        "unexpected code: {report}"
    );
    assert_eq!(report["max_tokens"], 64);
    assert_eq!(report["intra_threads"], 1);
}

#[test]
fn hybrid_never_degrades_to_a_regex_only_success() {
    let dir = temp_dir();
    let (report, success) = json_report(dir.path(), &["--detector", "hybrid", "--format", "json"]);
    assert!(!success);
    assert_eq!(report["available"], false);
    let guidance = report["guidance"].as_str().unwrap_or_default();
    assert!(guidance.contains("not a hybrid result"), "{guidance}");
}

#[test]
fn process_detector_reports_configuration_only() {
    let dir = temp_dir();
    let (report, success) = json_report(dir.path(), &["--detector", "process", "--format", "json"]);
    assert!(!success);
    assert_eq!(report["reason_code"], "not_configured");

    let (report, success) = json_report(
        dir.path(),
        &[
            "--detector",
            "process",
            "--detector-command",
            "python3 /nonexistent/plugin.py",
            "--format",
            "json",
        ],
    );
    assert!(success, "{report}");
    assert_eq!(report["reason_code"], "ready");
    assert_eq!(report["available"], true);
}

#[test]
fn diagnostics_never_echo_the_model_path_and_text_mode_is_human_readable() {
    let dir = temp_dir();
    let canary = "canary-doctor-model-dir";
    let model = dir.path().join(canary);
    if let Err(error) = std::fs::create_dir(&model) {
        panic!("cannot create the canary directory: {error}");
    }
    let (report, success) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &model.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert!(!success);
    assert_eq!(report["reason_code"], "missing_model_file");
    let rendered = report.to_string();
    assert!(!rendered.contains(canary), "path leaked: {rendered}");

    let (stdout, stderr, success) = doctor(dir.path(), &["--detector", "regex"]);
    assert!(success, "{stderr}");
    assert!(stdout.contains("detector: regex"), "{stdout}");
    assert!(stdout.contains("available: true"), "{stdout}");
    assert!(stdout.contains("reason_code: ready"), "{stdout}");
}

/// A model directory path with spaces must round-trip through the flag parser.
#[test]
fn model_dir_with_spaces_is_accepted() {
    let dir = temp_dir();
    let model: PathBuf = dir.path().join("model dir");
    if let Err(error) = std::fs::create_dir(&model) {
        panic!("cannot create the model directory: {error}");
    }
    let (report, _) = json_report(
        dir.path(),
        &[
            "--detector",
            "gliner2",
            "--model-dir",
            &model.to_string_lossy(),
            "--format",
            "json",
        ],
    );
    assert_eq!(report["reason_code"], "missing_model_file");
}
