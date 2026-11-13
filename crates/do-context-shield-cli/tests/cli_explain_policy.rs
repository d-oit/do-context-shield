//! Black-box tests for the value-free policy simulation command.

mod common;

use common::{cmd, temp_dir, write_config};
use serde_json::Value;

fn run_json(dir: &std::path::Path, text: &str, args: &[&str]) -> (Value, String, String) {
    let assert = cmd(dir)
        .arg("explain-policy")
        .args(args)
        .arg("--format")
        .arg("json")
        .write_stdin(text)
        .assert()
        .success();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let report = match serde_json::from_str(stdout.trim()) {
        Ok(report) => report,
        Err(error) => panic!("invalid explain-policy JSON ({error}): {stdout:?} / {stderr:?}"),
    };
    (report, stdout, stderr)
}

#[test]
fn default_policy_explains_without_echoing_values() {
    let dir = temp_dir();
    let value = "alice@example.com";
    let (report, stdout, stderr) = run_json(dir.path(), value, &["--recipient", "external"]);
    let entity = &report["entities"][0];
    assert_eq!(report["simulation"], true);
    assert_eq!(report["policy"], "default");
    assert_eq!(entity["kind"], "email");
    assert_eq!(entity["start"], 0);
    assert_eq!(entity["end"], value.len());
    assert_eq!(entity["action"], "pseudonymize");
    assert_eq!(entity["reason_code"], "default_pseudonymize");
    assert_eq!(entity["used_default"], true);
    assert!(
        !stdout.contains(value),
        "raw value leaked to stdout: {stdout}"
    );
    assert!(
        !stderr.contains(value),
        "raw value leaked to stderr: {stderr}"
    );
}

#[test]
fn secret_kinds_redact_and_unknown_recipient_blocks() {
    let dir = temp_dir();
    let secret_input = format!("password={}", "x".repeat(16));
    let (secret, _, _) = run_json(dir.path(), &secret_input, &["--recipient", "local"]);
    assert_eq!(secret["entities"][0]["action"], "redact");
    assert_eq!(secret["entities"][0]["reason_code"], "secret_kind");

    let (unknown, _, _) = run_json(dir.path(), "alice@example.com", &["--recipient", "unknown"]);
    assert_eq!(unknown["blocked"], true);
    assert_eq!(unknown["entities"][0]["action"], "block");
    assert_eq!(
        unknown["entities"][0]["reason_code"],
        "unknown_recipient_blocked"
    );
}

#[test]
fn missing_jurisdiction_blocks_trusted_special_category() {
    let dir = temp_dir();
    let (report, _, _) = run_json(
        dir.path(),
        "alice@example.com",
        &[
            "--recipient",
            "trusted",
            "--data-category",
            "special_category",
        ],
    );
    assert_eq!(report["entities"][0]["action"], "block");
    assert_eq!(
        report["entities"][0]["reason_code"],
        "jurisdiction_required_blocked"
    );
}

#[test]
fn matrix_policy_reports_matched_rule_index_without_context_values() {
    let dir = temp_dir();
    write_config(
        &dir.path().join("do-context-shield.toml"),
        "[plugins]\npolicy = 'matrix'\n[policy_matrix]\n[[policy_matrix.purpose_rules]]\npurpose = 'support'\naction = 'keep'\n",
    );
    let (report, stdout, _) = run_json(
        dir.path(),
        "alice@example.com",
        &["--purpose", "support", "--recipient", "trusted"],
    );
    assert_eq!(report["policy"], "matrix");
    assert_eq!(report["entities"][0]["action"], "keep");
    assert_eq!(report["entities"][0]["reason_code"], "purpose_rule_match");
    assert_eq!(report["entities"][0]["matched_rule"], 0);
    assert_eq!(report["entities"][0]["used_default"], false);
    assert!(!stdout.contains("support"));
    let (fallback, _, _) = run_json(
        dir.path(),
        "alice@example.com",
        &["--purpose", "other", "--recipient", "trusted"],
    );
    assert_eq!(fallback["entities"][0]["action"], "pseudonymize");
    assert_eq!(fallback["entities"][0]["used_default"], true);
    assert_eq!(fallback["entities"][0]["matched_rule"], Value::Null);
}

#[test]
fn simulation_does_not_create_vault_or_audit_files_from_config() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let audit = dir.path().join("audit.jsonl");
    let config = format!(
        "[vault]\nvault = 'json'\nvault_file = {vault:?}\n[audit]\naudit_file = {audit:?}\n",
    );
    write_config(&dir.path().join("do-context-shield.toml"), &config);
    let _ = run_json(
        dir.path(),
        "alice@example.com",
        &["--recipient", "external"],
    );
    assert!(!vault.exists(), "simulation created a vault file");
    assert!(!audit.exists(), "simulation created an audit file");
}

#[test]
fn text_output_identifies_simulation_and_never_contains_input() {
    let dir = temp_dir();
    let value = "alice@example.com";
    let output = cmd(dir.path())
        .arg("explain-policy")
        .arg("--recipient")
        .arg("external")
        .write_stdin(value)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("policy simulation"));
    assert!(text.contains("pseudonymize"));
    assert!(!text.contains(value));
}
