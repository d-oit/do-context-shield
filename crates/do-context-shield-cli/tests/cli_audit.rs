//! Black-box CLI acceptance tests for explicit local audit logging.

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

fn invoke(dir: &Path, args: &[String], input: &str) -> assert_cmd::assert::Assert {
    cmd(dir).args(args).write_stdin(input).assert()
}

fn stdout(assertion: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assertion.get_output().stdout).into_owned()
}

fn events(path: &Path) -> Vec<Value> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read audit fixture ({:?})", error.kind()),
    };
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| match serde_json::from_slice(line) {
            Ok(event) => event,
            Err(error) => panic!("cannot parse audit fixture ({:?})", error.classify()),
        })
        .collect()
}

fn action_count(event: &Value, kind: &str, action: &str) -> Option<u64> {
    event
        .get("actions")?
        .as_array()?
        .iter()
        .find(|item| item.get("kind").and_then(Value::as_str) == Some(kind))?
        .get("action")
        .and_then(Value::as_str)
        .filter(|actual| *actual == action)?;
    event
        .get("actions")?
        .as_array()?
        .iter()
        .find(|item| item.get("kind").and_then(Value::as_str) == Some(kind))?
        .get("count")?
        .as_u64()
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
#[test]
fn separate_cli_processes_keep_scoped_audit_history_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let key = dir.path().join("vault.key");
    let audit = dir.path().join("audit.jsonl");
    let key_hex = "ab".repeat(32);
    if let Err(error) = fs::write(&key, format!("{key_hex}\n")) {
        panic!("cannot create key fixture: {error}");
    }
    if let Err(error) = fs::set_permissions(&key, fs::Permissions::from_mode(0o600)) {
        panic!("cannot restrict key fixture: {error}");
    }

    let mut first_args = operation_args(
        "sanitize",
        "audit-a",
        Some(&vault),
        Some(&key),
        Some(&audit),
    );
    first_args.extend(["--purpose".to_owned(), "audit-fixture-purpose".to_owned()]);
    let first = invoke(
        dir.path(),
        &first_args,
        "contact alice@example.com token=s3cr3t-value-1234",
    )
    .success();
    let first_text = stdout(&first);
    assert!(!first_text.ends_with('\n'));
    assert!(first_text.starts_with("contact "));
    assert!(first_text.ends_with(" __DO_PRIVATE_REDACTED__"));
    let Some(first_token) = first_text.split_whitespace().nth(1) else {
        panic!("sanitized output omitted the email placeholder");
    };
    common::assert_placeholder(first_token, "EMAIL", 1);

    let second = invoke(
        dir.path(),
        &operation_args(
            "sanitize",
            "audit-b",
            Some(&vault),
            Some(&key),
            Some(&audit),
        ),
        "bob@example.com",
    )
    .success();
    let second_token = stdout(&second);
    common::assert_placeholder(&second_token, "EMAIL", 1);

    let restored_a = invoke(
        dir.path(),
        &operation_args("restore", "audit-a", Some(&vault), Some(&key), Some(&audit)),
        &first_text,
    )
    .success();
    assert_eq!(
        stdout(&restored_a),
        "contact alice@example.com __DO_PRIVATE_REDACTED__"
    );

    let cross_scope = invoke(
        dir.path(),
        &operation_args("restore", "audit-b", Some(&vault), Some(&key), Some(&audit)),
        &first_text,
    )
    .success();
    assert_eq!(stdout(&cross_scope), first_text);

    invoke(
        dir.path(),
        &operation_args("forget", "audit-a", Some(&vault), Some(&key), Some(&audit)),
        "",
    )
    .success();
    let forgotten = invoke(
        dir.path(),
        &operation_args("restore", "audit-a", Some(&vault), Some(&key), Some(&audit)),
        &first_text,
    )
    .success();
    assert_eq!(stdout(&forgotten), first_text);
    let restored_b = invoke(
        dir.path(),
        &operation_args("restore", "audit-b", Some(&vault), Some(&key), Some(&audit)),
        &second_token,
    )
    .success();
    assert_eq!(stdout(&restored_b), "bob@example.com");

    let records = events(&audit);
    assert_eq!(records.len(), 7);
    assert_eq!(records[0]["operation"], "sanitize");
    assert_eq!(records[0]["session"], "audit-a");
    assert_eq!(records[0]["outcome"], "ok");
    assert_eq!(action_count(&records[0], "email", "Pseudonymize"), Some(1));
    assert_eq!(
        action_count(&records[0], "generic_secret", "Redact"),
        Some(1)
    );
    assert_eq!(records[1]["operation"], "sanitize");
    assert_eq!(records[1]["session"], "audit-b");
    assert_eq!(records[2]["operation"], "restore");
    assert_eq!(records[2]["session"], "audit-a");
    assert_eq!(records[2]["resolved"], 1);
    assert_eq!(records[3]["operation"], "restore");
    assert_eq!(records[3]["session"], "audit-b");
    assert_eq!(records[3]["resolved"], 0);
    assert_eq!(records[4]["operation"], "forget");
    assert_eq!(records[4]["session"], "audit-a");
    assert_eq!(records[5]["operation"], "restore");
    assert_eq!(records[5]["resolved"], 0);
    assert_eq!(records[6]["operation"], "restore");
    assert_eq!(records[6]["session"], "audit-b");
    assert_eq!(records[6]["resolved"], 1);

    let log = match fs::read_to_string(&audit) {
        Ok(log) => log,
        Err(error) => panic!("cannot inspect audit fixture ({:?})", error.kind()),
    };
    for private in [
        "alice@example.com",
        "bob@example.com",
        "s3cr3t-value-1234",
        first_token,
        second_token.as_str(),
        "audit-fixture-purpose",
        key_hex.as_str(),
    ] {
        assert!(
            !log.contains(private),
            "private fixture value leaked into audit log"
        );
    }
}

#[cfg(unix)]
#[test]
fn policy_block_is_audited_without_stdout_or_sensitive_diagnostics() {
    let dir = temp_dir();
    let audit = dir.path().join("blocked.jsonl");
    let mut args = operation_args("sanitize", "blocked-scope", None, None, Some(&audit));
    args.extend(["--recipient".to_owned(), "unknown".to_owned()]);
    let result = invoke(dir.path(), &args, "alice@example.com").code(1);
    assert!(result.get_output().stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.get_output().stderr);
    assert!(!stderr.contains("alice@example.com"));
    let records = events(&audit);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["operation"], "sanitize");
    assert_eq!(records[0]["outcome"], "blocked");
    assert_eq!(records[0]["session"], "blocked-scope");
    assert!(!fs::read_to_string(&audit).is_ok_and(|log| log.contains("alice@example.com")));
}

#[cfg(unix)]
#[test]
fn cli_environment_file_precedence_and_empty_environment_are_runtime_effective() {
    let dir = temp_dir();
    let config_dir = dir.path().join("config");
    if let Err(error) = fs::create_dir(&config_dir) {
        panic!("cannot create config fixture directory: {error}");
    }
    let config = config_dir.join("settings.toml");
    common::write_config(&config, "[audit]\naudit_file = \"file-layer.jsonl\"\n");
    let config = path_text(&config);
    let file_log = dir.path().join("file-layer.jsonl");
    let config_relative_log = config_dir.join("file-layer.jsonl");
    let env_log = dir.path().join("env-layer.jsonl");
    let cli_log = dir.path().join("cli-layer.jsonl");
    let env_value = path_text(&env_log);
    let cli_value = path_text(&cli_log);

    let cli = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_AUDIT_FILE", &env_value)
        .args([
            "--config",
            &config,
            "sanitize",
            "--session",
            "cli-layer",
            "--audit-file",
            &cli_value,
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    assert!(!stdout(&cli).is_empty());
    assert_eq!(events(&cli_log).len(), 1);
    assert!(!env_log.exists());
    assert!(!file_log.exists());
    assert!(!config_relative_log.exists());

    let env = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_AUDIT_FILE", &env_value)
        .args(["--config", &config, "sanitize", "--session", "env-layer"])
        .write_stdin("bob@example.com")
        .assert()
        .success();
    assert!(!stdout(&env).is_empty());
    assert_eq!(events(&env_log).len(), 1);
    assert!(!file_log.exists());

    let file = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_AUDIT_FILE", "")
        .args(["--config", &config, "sanitize", "--session", "file-layer"])
        .write_stdin("carol@example.com")
        .assert()
        .success();
    assert!(!stdout(&file).is_empty());
    assert_eq!(events(&file_log).len(), 1);
    assert!(!config_relative_log.exists());
}

#[test]
fn inspect_and_disabled_audit_ignore_unusable_file_settings() {
    let dir = temp_dir();
    let config = dir.path().join("inspect.toml");
    common::write_config(
        &config,
        "[audit]\naudit_file = \"missing-parent/audit.jsonl\"\n",
    );
    let config = path_text(&config);
    let inspected = cmd(dir.path())
        .args(["--config", &config, "inspect"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&inspected.get_output().stdout).contains("\"email\""));
    assert!(!dir.path().join("missing-parent").exists());

    let disabled = cmd(dir.path())
        .args(["sanitize", "--session", "audit-disabled"])
        .write_stdin("bob@example.com")
        .assert()
        .success();
    assert!(!stdout(&disabled).is_empty());
    assert!(!dir.path().join("audit.jsonl").exists());
}

#[test]
fn malformed_audit_configuration_fails_strictly() {
    let dir = temp_dir();
    for (index, body) in ["[audit]\nunknown = true\n", "[audit]\naudit_file = 42\n"]
        .into_iter()
        .enumerate()
    {
        let config = dir.path().join(format!("invalid-{index}.toml"));
        common::write_config(&config, body);
        let config = path_text(&config);
        let result = cmd(dir.path())
            .args(["--config", &config, "config"])
            .assert()
            .code(1);
        assert!(result.get_output().stdout.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn invalid_destination_and_vault_aliases_fail_before_stdout_or_mutation() {
    use std::os::unix::fs::symlink;

    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let key = dir.path().join("vault.key");
    let protected_vault = b"preserved-vault-bytes";
    let protected_key = b"preserved-key-bytes";
    if let Err(error) = fs::write(&vault, protected_vault) {
        panic!("cannot create protected vault fixture: {error}");
    }
    if let Err(error) = fs::write(&key, protected_key) {
        panic!("cannot create protected key fixture: {error}");
    }
    let missing = dir.path().join("missing/child/audit.jsonl");
    let invalid = invoke(
        dir.path(),
        &operation_args("sanitize", "bad-path", None, None, Some(&missing)),
        "alice@example.com",
    )
    .code(1);
    assert!(invalid.get_output().stdout.is_empty());
    assert!(!dir.path().join("missing").exists());

    let vault_lock = vault.with_extension("json.lock");
    let vault_temp = vault.with_extension("json.tmp");
    let relative_vault = Path::new("./vault.json");
    let alias_parent = dir.path().join("parent-alias");
    if let Err(error) = symlink(dir.path(), &alias_parent) {
        panic!("cannot create parent symlink fixture: {error}");
    }
    let parent_alias = alias_parent.join("vault.json");
    let cases = [
        (path_text(&vault), Some(&vault), None),
        (path_text(&key), Some(&vault), Some(&key)),
        (path_text(&vault_lock), Some(&vault), None),
        (path_text(&vault_temp), Some(&vault), None),
        (path_text(relative_vault), Some(&vault), None),
        (path_text(&parent_alias), Some(&vault), None),
    ];
    for (audit, protected_file, protected_key_file) in cases {
        let mut args = vec![
            "sanitize".to_owned(),
            "--session".to_owned(),
            "collision".to_owned(),
            "--vault-file".to_owned(),
            path_text(&vault),
            "--audit-file".to_owned(),
            audit,
        ];
        if let Some(key_file) = protected_key_file {
            args.extend(["--vault-key-file".to_owned(), path_text(key_file)]);
        }
        let result = invoke(dir.path(), &args, "not processed").code(1);
        assert!(result.get_output().stdout.is_empty());
        if let Some(protected_file) = protected_file {
            assert_eq!(
                fs::read(protected_file).ok().as_deref(),
                Some(protected_vault.as_slice())
            );
        }
        assert_eq!(
            fs::read(&key).ok().as_deref(),
            Some(protected_key.as_slice())
        );
    }
    assert!(!vault_lock.exists());
    assert!(!vault_temp.exists());
}

#[cfg(unix)]
#[test]
fn no_audit_destination_fails_before_input_processing() {
    let dir = temp_dir();
    let missing = dir.path().join("absent/audit.jsonl");
    let result = invoke(
        dir.path(),
        &operation_args("sanitize", "invalid", None, None, Some(&missing)),
        "alice@example.com",
    )
    .code(1);
    assert!(result.get_output().stdout.is_empty());
    assert!(!dir.path().join("absent").exists());
}
