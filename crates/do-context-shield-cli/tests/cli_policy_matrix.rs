//! Integration tests for policy-matrix configuration, jurisdiction adequacy, and purpose mapping.

mod common;

use common::{cmd, temp_dir};

#[test]
fn matrix_policy_enforces_adequacy_for_special_category_data() {
    let dir = temp_dir();
    let config = dir.path().join("do-context-shield.toml");
    let config_content = r#"
[plugins]
policy = "matrix"

[policy_matrix]
origin = "DE"
adequate_jurisdictions = ["FR", "GB"]
enforce_adequacy_for_trusted = true
"#;
    common::write_config(&config, config_content);

    // 1. Adequate destination ("FR") with trusted recipient -> Success (pseudonymize)
    let res_ok = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s1",
            "--recipient",
            "trusted",
            "--jurisdiction",
            "FR",
            "--data-category",
            "special_category",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let out_ok = String::from_utf8_lossy(&res_ok.get_output().stdout);
    common::assert_placeholder(&out_ok, "EMAIL", 1);

    // 2. Inadequate destination ("US") with trusted recipient -> Block (exit code 1)
    let res_block = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s2",
            "--recipient",
            "trusted",
            "--jurisdiction",
            "US",
            "--data-category",
            "special_category",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .code(1);
    assert!(res_block.get_output().stdout.is_empty());
}

#[test]
fn matrix_policy_evaluates_purpose_rules_and_preserves_secret_redaction() {
    let dir = temp_dir();
    let config = dir.path().join("do-context-shield.toml");
    let config_content = r#"
[plugins]
policy = "matrix"

[[policy_matrix.purpose_rules]]
purpose = "internal_analytics"
recipients = ["local", "trusted"]
action = "keep"

[[policy_matrix.purpose_rules]]
purpose = "forbidden_marketing"
action = "block"
"#;
    common::write_config(&config, config_content);

    // 1. Purpose internal_analytics keeps email
    let res_keep = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s_keep",
            "--recipient",
            "trusted",
            "--purpose",
            "internal_analytics",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let out_keep = String::from_utf8_lossy(&res_keep.get_output().stdout);
    assert_eq!(out_keep, "alice@example.com");

    // 2. Even with action="keep", secret kinds are strictly redacted!
    let res_secret = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s_secret",
            "--recipient",
            "trusted",
            "--purpose",
            "internal_analytics",
        ])
        .write_stdin("token=s3cr3t-password-123")
        .assert()
        .success();
    let out_secret = String::from_utf8_lossy(&res_secret.get_output().stdout);
    assert_eq!(out_secret, "__DO_PRIVATE_REDACTED__");

    // 3. Purpose forbidden_marketing blocks
    let res_block = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s_block",
            "--purpose",
            "forbidden_marketing",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .code(1);
    assert!(res_block.get_output().stdout.is_empty());
}

#[test]
fn policy_matrix_is_selectable_from_the_cli_flag() {
    // The file supplies only the matrix configuration: `--policy matrix` on the
    // command line selects it, so an operator can keep `[plugins] policy` unset.
    let dir = temp_dir();
    let config = dir.path().join("do-context-shield.toml");
    common::write_config(
        &config,
        r#"
[policy_matrix]
origin = "DE"
adequate_jurisdictions = ["FR"]
"#,
    );

    let allowed = cmd(dir.path())
        .args([
            "sanitize",
            "--policy",
            "matrix",
            "--session",
            "s_ok",
            "--recipient",
            "trusted",
            "--jurisdiction",
            "FR",
            "--data-category",
            "special_category",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let out = String::from_utf8_lossy(&allowed.get_output().stdout);
    common::assert_placeholder(&out, "EMAIL", 1);

    let blocked = cmd(dir.path())
        .args([
            "sanitize",
            "--policy",
            "matrix",
            "--session",
            "s_block",
            "--recipient",
            "trusted",
            "--jurisdiction",
            "US",
            "--data-category",
            "special_category",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .code(1);
    assert!(blocked.get_output().stdout.is_empty());
}

#[test]
fn matrix_configuration_under_another_policy_is_rejected() {
    // `[policy_matrix]` with a different file policy would be loaded and
    // silently ignored; startup rejects it instead of reading as enforced.
    let dir = temp_dir();
    let config = dir.path().join("do-context-shield.toml");
    common::write_config(
        &config,
        r#"
[plugins]
policy = "default"

[policy_matrix]
origin = "DE"
"#,
    );
    cmd(dir.path())
        .args(["sanitize", "--session", "s"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("`[policy_matrix]` is configured"));
}
