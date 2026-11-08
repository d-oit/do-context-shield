//! Black-box tests for chained audit records: `verify-audit` and opt-in
//! rotation over the compiled binary.

#![cfg(unix)]

mod common;

use common::{cmd, temp_dir};
use serde_json::Value;
use std::fs;
use std::path::Path;

fn path_text(path: &Path) -> String {
    match path.to_str() {
        Some(path) => path.to_owned(),
        None => panic!("fixture path is not valid UTF-8"),
    }
}

#[cfg(unix)]
fn operation_args(
    operation: &str,
    session: &str,
    vault: Option<&Path>,
    key: Option<&Path>,
    audit: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        operation.to_owned(),
        "--session".to_owned(),
        session.to_owned(),
    ];
    if let Some(vault) = vault {
        args.extend(["--vault-file".to_owned(), path_text(vault)]);
    }
    if let Some(key) = key {
        args.extend(["--vault-key-file".to_owned(), path_text(key)]);
    }
    if let Some(audit) = audit {
        args.extend(["--audit-file".to_owned(), path_text(audit)]);
    }
    args
}

#[cfg(unix)]
fn invoke(dir: &Path, args: &[String], input: &str) -> assert_cmd::assert::Assert {
    cmd(dir).args(args).write_stdin(input).assert()
}

#[cfg(unix)]
/// Run `verify-audit --format json` over `audit` and return the parsed report.
fn verify_audit(dir: &Path, audit: &Path) -> (Value, bool) {
    let assert = cmd(dir)
        .args([
            "verify-audit",
            "--audit-file",
            &path_text(audit),
            "--format",
            "json",
        ])
        .assert();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let report: Value = match serde_json::from_str(stdout.trim()) {
        Ok(report) => report,
        Err(error) => panic!("verify-audit did not emit JSON ({error}): {stdout:?}"),
    };
    (report, output.status.success())
}

#[cfg(unix)]
#[test]
fn verify_audit_reports_a_valid_chain_and_rejects_tampering() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let audit = dir.join("audit.jsonl");
    let session = "verify-session";
    for _ in 0..2 {
        invoke(
            dir,
            &operation_args("sanitize", session, None, None, Some(&audit)),
            "alice@example.com",
        )
        .success();
    }
    let (report, success) = verify_audit(dir, &audit);
    assert!(success, "{report}");
    assert_eq!(report["format"], "v2");
    assert_eq!(report["records"], 2);
    assert_eq!(report["ok"], true);

    // Tamper with the session text inside one record; the report must detect
    // the modification without echoing the value.
    let canary = "CANARY-AUDIT-VERIFY";
    let second = dir.join("second.jsonl");
    invoke(
        dir,
        &operation_args("sanitize", canary, None, None, Some(&second)),
        "bob@example.com",
    )
    .success();
    let mut bytes = match fs::read(&second) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read audit fixture: {error}"),
    };
    let Some(position) = bytes
        .windows(canary.len())
        .position(|window| window == canary.as_bytes())
    else {
        panic!("audit fixture does not contain the session");
    };
    bytes[position..position + canary.len()].copy_from_slice(b"CANARY-AUDIT-VERIFZ");
    if let Err(error) = fs::write(&second, &bytes) {
        panic!("cannot tamper with audit fixture: {error}");
    }
    let (report, success) = verify_audit(dir, &second);
    assert!(!success, "{report}");
    assert_eq!(report["ok"], false);
    assert_eq!(report["category"], "record_hash_mismatch");
    assert_eq!(report["record_index"], 1);
    assert!(!report.to_string().contains("CANARY"), "{report}");
}

#[cfg(unix)]
#[test]
fn verify_audit_accepts_empty_and_reports_malformed_files() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let empty = dir.join("empty.jsonl");
    if let Err(error) = fs::write(&empty, b"") {
        panic!("cannot create empty audit fixture: {error}");
    }
    let (report, success) = verify_audit(dir, &empty);
    assert!(success, "{report}");
    assert_eq!(report["format"], "empty");

    let malformed = dir.join("malformed.jsonl");
    if let Err(error) = fs::write(&malformed, b"not an audit record\n") {
        panic!("cannot create malformed audit fixture: {error}");
    }
    let (report, success) = verify_audit(dir, &malformed);
    assert!(!success, "{report}");
    assert_eq!(report["format"], "failure");
    assert_eq!(report["category"], "malformed");
}

#[cfg(unix)]
#[test]
fn audit_retention_rotates_at_the_configured_record_bound() {
    let tmp = temp_dir();
    let dir = tmp.path();
    let audit = dir.join("retained.jsonl");
    let mut args = operation_args("sanitize", "retention", None, None, Some(&audit));
    args.extend(["--audit-max-records".to_owned(), "1".to_owned()]);

    invoke(dir, &args, "alice@example.com").success();
    invoke(dir, &args, "bob@example.com").success();

    let rotated = dir.join("retained.jsonl.1");
    assert!(rotated.is_file(), "the first record must be rotated");
    let (current, current_ok) = verify_audit(dir, &audit);
    let (previous, previous_ok) = verify_audit(dir, &rotated);
    assert!(current_ok && previous_ok, "{current} {previous}");
    assert_eq!(current["records"], 1);
    assert_eq!(previous["records"], 1);
}
