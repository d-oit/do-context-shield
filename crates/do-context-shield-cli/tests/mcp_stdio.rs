//! Black-box tests for the MCP stdio server (`do-context-shield mcp-stdio`).
//!
//! The server runs as a real subprocess, so the newline-delimited JSON-RPC
//! transport itself — error recovery and the clean EOF shutdown included — is
//! exercised, not just request handling. Configuration-driven behavior lives in
//! `mcp_stdio_config.rs`.

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

mod common;

use common::{McpSession, content_text, error_code, tool_call, tool_names};

#[test]
fn discover_returns_supported_versions() {
    let mut session = McpSession::start();
    let response =
        session.send(r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#);
    let Some(versions) = response
        .pointer("/result/supportedVersions")
        .and_then(Value::as_array)
    else {
        panic!("missing supportedVersions in {response}");
    };
    assert!(
        versions.iter().any(|version| version == "2026-07-28"),
        "{response}"
    );
    session.close();
}

#[test]
fn initialize_returns_legacy_protocol_version() {
    let mut session = McpSession::start();
    let response = session.send(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    assert_eq!(
        response
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str),
        Some("2025-11-25")
    );
    assert_eq!(
        response
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("do-context-shield")
    );
    // A notification is never answered: the next line read is the discover
    // reply and carries its own id.
    session.send_notification(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let follow_up =
        session.send(r#"{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{}}"#);
    assert_eq!(follow_up["id"], 2);
    session.close();
}

#[test]
fn sanitize_restore_round_trip_over_stdio() {
    let mut session = McpSession::start_with(&["--tools", "all"]);
    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "s1"}),
    )));
    common::assert_placeholder(&sanitized, "EMAIL", 1);
    let restored = content_text(&session.send(&tool_call(
        "context.restore",
        &json!({"text": &sanitized, "session": "s1"}),
    )));
    assert_eq!(restored, "alice@example.com");
    session.close();
}

#[test]
fn inspect_over_stdio() {
    let mut session = McpSession::start();
    let inspected = content_text(&session.send(&tool_call(
        "context.inspect",
        &json!({"text": "alice@example.com"}),
    )));
    // The matched text must never travel back to the calling agent.
    assert!(!inspected.contains("alice@example.com"), "{inspected}");
    let entities: Value = match serde_json::from_str(&inspected) {
        Ok(entities) => entities,
        Err(error) => panic!("inspect payload is not JSON: {error} ({inspected:?})"),
    };
    let Some(first) = entities.get(0) else {
        panic!("no entity in {inspected}");
    };
    assert_eq!(first["kind"], "email", "{inspected}");
    session.close();
}

#[test]
fn default_surface_hides_restore_and_forget() {
    let mut session = McpSession::start();
    let listed = session.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(tool_names(&listed), ["context.sanitize", "context.inspect"]);

    // A disabled tool is rejected before it could resolve raw values.
    let denied = session.send(&tool_call(
        "context.restore",
        &json!({"text": "__DO_PRIVATE_EMAIL_1__", "session": "s1"}),
    ));
    let message = denied
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("not enabled"), "{denied}");
    session.close();
}

#[test]
fn forget_over_stdio() {
    let mut session = McpSession::start_with(&["--tools", "all"]);
    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "f1"}),
    )));
    common::assert_placeholder(&sanitized, "EMAIL", 1);
    let forgotten =
        content_text(&session.send(&tool_call("context.forget", &json!({"session": "f1"}))));
    assert!(forgotten.contains(r#""forgotten":true"#), "{forgotten}");
    // After the wipe the placeholder no longer resolves.
    let restored = content_text(&session.send(&tool_call(
        "context.restore",
        &json!({"text": &sanitized, "session": "f1"}),
    )));
    assert_eq!(restored, sanitized);
    session.close();
}

#[test]
fn malformed_json_returns_error() {
    let mut session = McpSession::start();
    let response = session.send("{not valid json");
    assert_eq!(error_code(&response), Some(-32000), "{response}");
    // The loop survives the bad line and keeps serving requests.
    let follow_up =
        session.send(r#"{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{}}"#);
    assert!(follow_up.get("result").is_some(), "{follow_up}");
    session.close();
}

#[test]
fn unknown_method_returns_error() {
    let mut session = McpSession::start();
    let response = session.send(r#"{"jsonrpc":"2.0","id":1,"method":"bogus"}"#);
    assert_eq!(error_code(&response), Some(-32000), "{response}");
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("unknown method"), "{response}");
    session.close();
}

#[test]
fn tool_failure_is_an_iserror_result() {
    let mut session = McpSession::start();
    // `text` is missing: the failure must arrive as a tool result with
    // `isError: true`, not as a JSON-RPC transport error.
    let response = session.send(&tool_call("context.sanitize", &json!({"session": "s1"})));
    assert_eq!(
        response.pointer("/result/isError").and_then(Value::as_bool),
        Some(true),
        "{response}"
    );
    assert!(response.get("error").is_none(), "{response}");
    let message = response
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("text"), "{response}");
    session.close();
}

#[test]
fn meta_version_warning_goes_to_stderr_for_legacy_requests() {
    let home = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let mut child = match Command::new(env!("CARGO_BIN_EXE_do-context-shield"))
        .arg("mcp-stdio")
        .current_dir(home.path())
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => panic!("cannot spawn `do-context-shield mcp-stdio`: {error}"),
    };
    let Some(mut stdin) = child.stdin.take() else {
        panic!("piped stdin missing");
    };
    let requests = [
        // Pre-2026 request: no `_meta`, so the warning is expected.
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        // Modern request: `_meta.protocolVersion` is present, so no warning.
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"protocolVersion":"2026-07-28"}}}"#,
    ];
    for request in requests {
        if let Err(error) = writeln!(stdin, "{request}") {
            panic!("cannot write request: {error}");
        }
        if let Err(error) = stdin.flush() {
            panic!("cannot flush request: {error}");
        }
    }
    drop(stdin);
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => panic!("cannot wait for mcp-stdio: {error}"),
    };
    assert!(
        output.status.success(),
        "mcp-stdio exited with {}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("pre-2026").count(),
        1,
        "expected exactly one legacy warning, got stderr: {stderr}"
    );
}

/// The documented "MCP server with a local judge and a bounded memory vault"
/// example: both values come from the configuration file, not from flags.
#[test]
fn config_file_supplies_the_judge_and_the_vault_ttl() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let config = dir.path().join("do-context-shield.toml");
    if let Err(error) = std::fs::write(
        &config,
        "[plugins]\njudge = \"heuristics\"\n\n[vault]\nvault_ttl_seconds = 1\n",
    ) {
        panic!("cannot write the config file: {error}");
    }
    let Some(config_path) = config.to_str() else {
        panic!("config path is not valid UTF-8");
    };
    let mut session = McpSession::start_with(&["--config", config_path, "--tools", "all"]);

    // `example.com` is a reserved documentation domain, so the file-selected
    // heuristic judge labels the address `Test` and the policy keeps it.
    let kept = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "test@example.com", "session": "cfg-judge"}),
    )));
    assert_eq!(kept, "test@example.com");

    // The file's `vault_ttl_seconds` bounds the mapping: once it elapses the
    // placeholder no longer resolves, inside this single server process.
    // A non-reserved domain, so the same judge does not keep it: the TTL is
    // observed on a value that really is pseudonymized.
    let tokenized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@corp-mail.com", "session": "cfg-ttl"}),
    )));
    common::assert_placeholder(&tokenized, "EMAIL", 1);
    std::thread::sleep(std::time::Duration::from_millis(1_200));
    let restored = content_text(&session.send(&tool_call(
        "context.restore",
        &json!({"text": &tokenized, "session": "cfg-ttl"}),
    )));
    assert_eq!(restored, tokenized);
    session.close();
}
