//! Black-box tests for `config`: effective values, the four-layer precedence
//! (CLI flag > environment > file > built-in default), and the whitelist that
//! keeps paths, process commands, key material, and purpose text out of the
//! report.

mod common;

use common::{cmd, temp_dir};
use serde_json::Value;
use std::path::Path;

/// Run `config` with `args` in `dir` and parse the JSON report.
fn explain(dir: &Path, args: &[&str]) -> Value {
    report(&cmd(dir).arg("config").args(args).assert().success())
}

/// Parse a `config` invocation's stdout as the JSON report.
fn report(assert: &assert_cmd::assert::Assert) -> Value {
    match serde_json::from_slice(&assert.get_output().stdout) {
        Ok(value) => value,
        Err(error) => panic!("config output is not JSON: {error}"),
    }
}

/// The `source` field at `pointer`, e.g. `/detector` or `/context/recipient`.
fn source(doc: &Value, pointer: &str) -> String {
    doc.pointer(pointer)
        .and_then(|value| value.get("source"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn defaults_name_the_builtin_layer() {
    let dir = temp_dir();
    let doc = explain(dir.path(), &[]);
    assert_eq!(doc["detector"]["value"], "regex");
    assert_eq!(source(&doc, "/detector"), "default");
    assert_eq!(source(&doc, "/policy"), "default");
    assert_eq!(source(&doc, "/transformer"), "default");
    assert_eq!(doc["judge"]["value"], Value::Null);
    assert_eq!(source(&doc, "/judge"), "none");
    assert_eq!(doc["effective_vault"], "memory");
    assert_eq!(doc["audit_file"]["configured"], false);
    assert_eq!(source(&doc, "/audit_file"), "none");
    assert_eq!(doc["context"]["recipient"]["value"], "external");
    assert_eq!(source(&doc, "/context/recipient"), "default");
    assert_eq!(source(&doc, "/context/data_category"), "default");
    assert_eq!(doc["process_timeout_ms"]["value"], 30000);
    assert_eq!(source(&doc, "/process_timeout_ms"), "default");
}

#[test]
fn precedence_cli_over_environment_over_file() {
    let dir = temp_dir();
    common::write_config(
        &dir.path().join("do-context-shield.toml"),
        "[plugins]\ndetector = \"gliner2\"\n",
    );

    // The file value is named as such; the detector is never built, so a
    // model-less `gliner2` selection is still printable.
    let doc = explain(dir.path(), &[]);
    assert_eq!(doc["detector"]["value"], "gliner2");
    assert_eq!(source(&doc, "/detector"), "file");

    // The environment variable beats the file.
    let doc = report(
        &cmd(dir.path())
            .env("DO_CONTEXT_SHIELD_DETECTOR", "hybrid")
            .args(["config"])
            .assert()
            .success(),
    );
    assert_eq!(doc["detector"]["value"], "hybrid");
    assert_eq!(source(&doc, "/detector"), "environment");

    // The CLI flag beats the environment.
    let doc = report(
        &cmd(dir.path())
            .env("DO_CONTEXT_SHIELD_DETECTOR", "hybrid")
            .args(["config", "--detector", "regex"])
            .assert()
            .success(),
    );
    assert_eq!(doc["detector"]["value"], "regex");
    assert_eq!(source(&doc, "/detector"), "cli");
}

#[test]
fn vault_selection_reports_the_effective_vault() {
    let dir = temp_dir();
    // A `vault_file` flag selects the JSON vault without naming it.
    let doc = explain(dir.path(), &["--vault-file", "vault.json"]);
    assert_eq!(doc["effective_vault"], "json");
    assert_eq!(doc["vault"]["value"], Value::Null);
    assert_eq!(source(&doc, "/vault"), "none");
    assert_eq!(doc["vault_file"]["configured"], true);
    assert_eq!(source(&doc, "/vault_file"), "cli");

    // The environment can supply the same setting; the file names the vault.
    let doc = report(
        &cmd(dir.path())
            .env("DO_CONTEXT_SHIELD_VAULT_FILE", "vault.json")
            .args(["config"])
            .assert()
            .success(),
    );
    assert_eq!(doc["effective_vault"], "json");
    assert_eq!(source(&doc, "/vault_file"), "environment");
}

#[test]
fn sensitive_material_never_appears_in_the_report() {
    let dir = temp_dir();
    common::write_config(
        &dir.path().join("do-context-shield.toml"),
        "[vault]\nvault = \"json\"\nvault_file = \"/tmp/SECRET-VAULT.json\"\n\
         vault_key_file = \"/tmp/SECRET-KEY.hex\"\n\n\
         [plugins]\ndetector = \"process\"\ndetector_command = \"sh /tmp/SECRET-PLUGIN.sh\"\n\n\
         [context]\npurpose = \"SECRET-PURPOSE-TEXT\"\njurisdiction = \"DE\"\n",
    );

    let audit_path = dir.path().join("CLI-SECRET-AUDIT.jsonl");
    let Some(audit_path_text) = audit_path.to_str() else {
        panic!("audit fixture path is not valid UTF-8");
    };
    let assert = cmd(dir.path())
        .args([
            "config",
            "--vault-file",
            "/tmp/CLI-SECRET-VAULT.json",
            "--vault-key-file",
            "/tmp/CLI-SECRET-KEY.hex",
            "--audit-file",
            audit_path_text,
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    for (index, secret) in [
        "SECRET-VAULT",
        "SECRET-KEY",
        "SECRET-PLUGIN",
        "SECRET-PURPOSE-TEXT",
        "CLI-SECRET",
        audit_path_text,
    ]
    .iter()
    .enumerate()
    {
        // The needle and the report are deliberately not interpolated: the
        // assertion message must not become a place where a fixture value is
        // written out (CodeQL flags that as cleartext logging).
        assert!(
            !stdout.contains(secret),
            "sensitive fixture value {index} leaked into the report"
        );
    }
    let doc = report(&assert);
    // Presence and provenance are reported instead of the values.
    assert_eq!(
        doc["vault_file"],
        serde_json::json!({"configured": true, "source": "cli"})
    );
    assert_eq!(
        doc["vault_key_file"],
        serde_json::json!({"configured": true, "source": "cli"})
    );
    assert_eq!(
        doc["audit_file"],
        serde_json::json!({"configured": true, "source": "cli"})
    );
    assert!(!audit_path.exists());
    assert_eq!(
        doc["detector_command"],
        serde_json::json!({"configured": true, "source": "file"})
    );
    assert_eq!(
        doc["context"]["purpose"],
        serde_json::json!({"configured": true, "source": "file"})
    );
    assert_eq!(doc["context"]["jurisdiction"]["value"], "DE");
    assert_eq!(source(&doc, "/context/jurisdiction"), "file");
}

#[test]
fn contradictory_vault_selection_fails_like_sanitize() {
    let dir = temp_dir();
    let conflict = cmd(dir.path())
        .args(["config", "--vault", "memory", "--vault-file", "x.json"])
        .assert()
        .code(1);
    let config_stderr = String::from_utf8_lossy(&conflict.get_output().stderr).into_owned();
    assert!(
        config_stderr.contains("cannot be combined with a vault file"),
        "{config_stderr}"
    );

    let sanitize = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "ctx",
            "--vault",
            "memory",
            "--vault-file",
            "x.json",
        ])
        .write_stdin("")
        .assert()
        .code(1);
    assert_eq!(
        config_stderr,
        String::from_utf8_lossy(&sanitize.get_output().stderr),
        "config must report the same selection conflict as sanitize"
    );
}

#[test]
fn malformed_jurisdiction_is_rejected_at_argument_parsing() {
    let dir = temp_dir();
    cmd(dir.path())
        .args(["config", "--jurisdiction", "Germany"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("ISO 3166-1 alpha-2"));
}
