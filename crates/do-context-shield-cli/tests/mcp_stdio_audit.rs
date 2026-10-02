//! Black-box MCP stdio acceptance tests for explicit local audit logging.

mod common;

use common::{McpSession, content_text, temp_dir, tool_call, tool_names, write_config};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn path_text(path: &Path) -> String {
    match path.to_str() {
        Some(path) => path.to_owned(),
        None => panic!("fixture path is not valid UTF-8"),
    }
}

fn child_home(parent: &Path) -> TempDir {
    match tempfile::tempdir_in(parent) {
        Ok(home) => home,
        Err(error) => panic!("cannot create a child home directory: {error}"),
    }
}

fn start(home: TempDir, args: &[String], envs: &[(&str, &str)]) -> McpSession {
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    McpSession::start_configured(home, &args, envs)
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

fn audit_args(path: &Path) -> Vec<String> {
    vec!["--audit-file".to_owned(), path_text(path)]
}

fn persisted_args(vault: &Path, key: &Path, audit: &Path) -> Vec<String> {
    vec![
        "--tools".to_owned(),
        "all".to_owned(),
        "--vault-file".to_owned(),
        path_text(vault),
        "--vault-key-file".to_owned(),
        path_text(key),
        "--audit-file".to_owned(),
        path_text(audit),
    ]
}

fn assert_private(log: &str, values: &[&str]) {
    for value in values {
        assert!(
            !log.contains(value),
            "private fixture value leaked into audit output"
        );
    }
}

#[cfg(unix)]
#[test]
fn all_tools_keep_scoped_persisted_history_across_process_restart() {
    use std::os::unix::fs::PermissionsExt;

    let outer = temp_dir();
    let vault = outer.path().join("vault.json");
    let key = outer.path().join("vault.key");
    let audit = outer.path().join("audit.jsonl");
    let key_hex = "cd".repeat(32);
    if let Err(error) = fs::write(&key, format!("{key_hex}\n")) {
        panic!("cannot create key fixture: {error}");
    }
    if let Err(error) = fs::set_permissions(&key, fs::Permissions::from_mode(0o600)) {
        panic!("cannot restrict key fixture: {error}");
    }
    let args = persisted_args(&vault, &key, &audit);
    let mut server = start(child_home(outer.path()), &args, &[]);
    let listed = server.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(tool_names(&listed).len(), 4);

    let first = content_text(&server.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "scope-a", "purpose": "audit-fixture-purpose"}),
    )));
    common::assert_placeholder(&first, "EMAIL", 1);
    let second = content_text(&server.send(&tool_call(
        "context.sanitize",
        &json!({"text": "bob@example.com", "session": "scope-b"}),
    )));
    common::assert_placeholder(&second, "EMAIL", 1);

    let restored_a = content_text(&server.send(&tool_call(
        "context.restore",
        &json!({"text": &first, "session": "scope-a"}),
    )));
    assert_eq!(restored_a, "alice@example.com");
    let cross_scope = content_text(&server.send(&tool_call(
        "context.restore",
        &json!({"text": &first, "session": "scope-b"}),
    )));
    assert_eq!(cross_scope, first);

    let forgotten =
        content_text(&server.send(&tool_call("context.forget", &json!({"session": "scope-a"}))));
    assert!(forgotten.contains(r#""forgotten":true"#));
    let after_forget = content_text(&server.send(&tool_call(
        "context.restore",
        &json!({"text": &first, "session": "scope-a"}),
    )));
    assert_eq!(after_forget, first);
    let restored_b = content_text(&server.send(&tool_call(
        "context.restore",
        &json!({"text": &second, "session": "scope-b"}),
    )));
    assert_eq!(restored_b, "bob@example.com");
    server.close();

    let mut restarted = start(child_home(outer.path()), &args, &[]);
    let after_restart = content_text(&restarted.send(&tool_call(
        "context.restore",
        &json!({"text": &second, "session": "scope-b"}),
    )));
    assert_eq!(after_restart, "bob@example.com");
    restarted.close();

    let records = events(&audit);
    assert_eq!(records.len(), 8);
    assert_eq!(records[0]["operation"], "sanitize");
    assert_eq!(records[0]["session"], "scope-a");
    assert_eq!(records[0]["outcome"], "ok");
    assert_eq!(records[1]["session"], "scope-b");
    assert_eq!(records[2]["operation"], "restore");
    assert_eq!(records[2]["resolved"], 1);
    assert_eq!(records[3]["session"], "scope-b");
    assert_eq!(records[3]["resolved"], 0);
    assert_eq!(records[4]["operation"], "forget");
    assert_eq!(records[4]["session"], "scope-a");
    assert_eq!(records[5]["resolved"], 0);
    assert_eq!(records[6]["session"], "scope-b");
    assert_eq!(records[6]["resolved"], 1);
    assert_eq!(records[7]["session"], "scope-b");
    assert_eq!(records[7]["resolved"], 1);

    let log = match fs::read_to_string(&audit) {
        Ok(log) => log,
        Err(error) => panic!("cannot inspect audit fixture ({:?})", error.kind()),
    };
    assert_private(
        &log,
        &[
            "alice@example.com",
            "bob@example.com",
            first.as_str(),
            second.as_str(),
            "audit-fixture-purpose",
            key_hex.as_str(),
        ],
    );
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
#[test]
fn read_only_protocol_and_disabled_tool_calls_do_not_audit() {
    let outer = temp_dir();
    let audit = outer.path().join("events.jsonl");
    let mut server = start(child_home(outer.path()), &audit_args(&audit), &[]);

    let initialized = server.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    assert!(initialized.get("result").is_some());
    let discovered =
        server.send(r#"{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{}}"#);
    assert!(discovered.get("result").is_some());
    let listed = server.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#);
    assert_eq!(tool_names(&listed), ["context.sanitize", "context.inspect"]);

    let inspected = content_text(&server.send(&tool_call(
        "context.inspect",
        &json!({"text": "inspect-only@example.com"}),
    )));
    assert!(!inspected.contains("inspect-only@example.com"));
    let disabled = server.send(&tool_call(
        "context.restore",
        &json!({"text": "__DO_PRIVATE_EMAIL_1__", "session": "disabled"}),
    ));
    assert!(disabled.pointer("/error/message").is_some());
    let malformed = server.send("{not valid json");
    assert_eq!(
        malformed.pointer("/error/code").and_then(Value::as_i64),
        Some(-32700)
    );
    let unknown = server.send(r#"{"jsonrpc":"2.0","id":4,"method":"unsupported"}"#);
    assert_eq!(
        unknown.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601)
    );
    assert!(events(&audit).is_empty());

    let sanitized = content_text(&server.send(&tool_call(
        "context.sanitize",
        &json!({"text": "private@example.com", "session": "success", "purpose": "private-purpose"}),
    )));
    common::assert_placeholder(&sanitized, "EMAIL", 1);
    let blocked = server.send(&tool_call(
        "context.sanitize",
        &json!({"text": "blocked@example.com", "session": "blocked", "recipient": "unknown"}),
    ));
    assert_eq!(
        blocked.pointer("/result/isError").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        blocked
            .pointer("/result/resultType")
            .and_then(Value::as_str),
        Some("complete")
    );
    assert!(blocked.get("error").is_none());
    assert!(!content_text(&blocked).contains("blocked@example.com"));

    let first = events(&audit);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0]["outcome"], "ok");
    assert_eq!(first[0]["session"], "success");
    assert_eq!(first[1]["outcome"], "blocked");
    assert_eq!(first[1]["session"], "blocked");

    let backup = outer.path().join("events.saved");
    if let Err(error) = fs::rename(&audit, &backup) {
        panic!("cannot move audit fixture: {error}");
    }
    if let Err(error) = fs::create_dir(&audit) {
        panic!("cannot replace audit fixture with directory: {error}");
    }
    let failed = server.send(&tool_call(
        "context.sanitize",
        &json!({"text": "rotation-failure@example.com", "session": "failed"}),
    ));
    assert_eq!(
        failed.pointer("/result/isError").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        failed.pointer("/result/resultType").and_then(Value::as_str),
        Some("complete")
    );
    assert!(failed.get("error").is_none());
    assert!(!content_text(&failed).contains("rotation-failure@example.com"));
    assert_eq!(events(&backup).len(), 2);

    if let Err(error) = fs::remove_dir(&audit) {
        panic!("cannot remove audit path fixture: {error}");
    }
    if let Err(error) = fs::rename(&backup, &audit) {
        panic!("cannot restore audit fixture: {error}");
    }
    let recovered = content_text(&server.send(&tool_call(
        "context.sanitize",
        &json!({"text": "recovered@example.com", "session": "recovered"}),
    )));
    common::assert_placeholder(&recovered, "EMAIL", 1);
    assert_eq!(events(&audit).len(), 3);
    let stderr = server.close_with_stderr();
    assert_private(
        &stderr,
        &[
            "private@example.com",
            "blocked@example.com",
            "rotation-failure@example.com",
            sanitized.as_str(),
            "private-purpose",
        ],
    );
    let log = match fs::read_to_string(&audit) {
        Ok(log) => log,
        Err(error) => panic!("cannot inspect audit fixture ({:?})", error.kind()),
    };
    assert_private(
        &log,
        &[
            "private@example.com",
            "blocked@example.com",
            "rotation-failure@example.com",
            "recovered@example.com",
            sanitized.as_str(),
            "private-purpose",
        ],
    );
}

#[cfg(unix)]
#[test]
fn ambient_config_is_ignored_and_explicit_environment_cli_precedence_applies() {
    let outer = temp_dir();
    let config_dir = outer.path().join("config");
    if let Err(error) = fs::create_dir(&config_dir) {
        panic!("cannot create config fixture directory: {error}");
    }
    let file_log = outer.path().join("file-layer.jsonl");
    let env_log = outer.path().join("env-layer.jsonl");
    let cli_log = outer.path().join("cli-layer.jsonl");
    let ambient_cwd = outer.path().join("ambient-cwd.jsonl");
    let ambient_home = outer.path().join("ambient-home.jsonl");
    let config_file = config_dir.join("explicit.toml");
    let file_value = path_text(&file_log);
    write_config(
        &config_file,
        &format!("[audit]\naudit_file = \"{file_value}\"\n"),
    );
    let explicit_config = path_text(&config_file);

    let ambient_text = format!("[audit]\naudit_file = \"{}\"\n", path_text(&ambient_cwd));
    write_config(&outer.path().join("do-context-shield.toml"), &ambient_text);
    let home_config = outer.path().join(".config/do-context-shield");
    if let Err(error) = fs::create_dir_all(&home_config) {
        panic!("cannot create ambient home config directory: {error}");
    }
    write_config(
        &home_config.join("config.toml"),
        &format!("[audit]\naudit_file = \"{}\"\n", path_text(&ambient_home)),
    );

    let home = child_home(outer.path());
    let mut session = start(home, &[], &[]);
    let ignored = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "ambient@example.com", "session": "ambient"}),
    )));
    common::assert_placeholder(&ignored, "EMAIL", 1);
    session.close();
    assert!(!ambient_cwd.exists());
    assert!(!ambient_home.exists());

    let mut explicit = start(
        child_home(outer.path()),
        &["--config".to_owned(), explicit_config.clone()],
        &[],
    );
    let _ = explicit.send(&tool_call(
        "context.sanitize",
        &json!({"text": "file@example.com", "session": "file"}),
    ));
    explicit.close();
    assert_eq!(events(&file_log).len(), 1);

    let env_value = path_text(&env_log);
    let mut environment = start(
        child_home(outer.path()),
        &["--config".to_owned(), explicit_config.clone()],
        &[("DO_CONTEXT_SHIELD_AUDIT_FILE", &env_value)],
    );
    let _ = environment.send(&tool_call(
        "context.sanitize",
        &json!({"text": "env@example.com", "session": "environment"}),
    ));
    environment.close();
    assert_eq!(events(&env_log).len(), 1);
    assert_eq!(events(&file_log).len(), 1);

    let cli_value = path_text(&cli_log);
    let mut cli = start(
        child_home(outer.path()),
        &[
            "--config".to_owned(),
            explicit_config.clone(),
            "--audit-file".to_owned(),
            cli_value,
        ],
        &[("DO_CONTEXT_SHIELD_AUDIT_FILE", &env_value)],
    );
    let _ = cli.send(&tool_call(
        "context.sanitize",
        &json!({"text": "cli@example.com", "session": "cli"}),
    ));
    cli.close();
    assert_eq!(events(&cli_log).len(), 1);
    assert_eq!(events(&env_log).len(), 1);

    let mut empty_environment = start(
        child_home(outer.path()),
        &["--config".to_owned(), explicit_config],
        &[("DO_CONTEXT_SHIELD_AUDIT_FILE", "")],
    );
    let _ = empty_environment.send(&tool_call(
        "context.sanitize",
        &json!({"text": "fallback@example.com", "session": "empty-env"}),
    ));
    empty_environment.close();
    assert_eq!(events(&file_log).len(), 2);
}

#[cfg(unix)]
#[test]
fn audit_startup_failure_exits_before_protocol_input_is_handled() {
    let home = temp_dir();
    let missing = home.path().join("missing/audit.jsonl");
    let missing_text = path_text(&missing);
    let mut command = Command::new(env!("CARGO_BIN_EXE_do-context-shield"));
    command
        .arg("mcp-stdio")
        .args(["--audit-file", &missing_text])
        .current_dir(home.path())
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in common::CONFIG_ENV_VARS {
        command.env_remove(name);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => panic!("cannot spawn mcp server: {error}"),
    };
    let Some(mut stdin) = child.stdin.take() else {
        panic!("piped stdin missing");
    };
    let request = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}
"#;
    let _write_result = stdin.write_all(request);
    drop(stdin);
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => panic!("cannot wait for mcp server: {error}"),
    };
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&missing_text));
    assert!(!home.path().join("missing").exists());
}
