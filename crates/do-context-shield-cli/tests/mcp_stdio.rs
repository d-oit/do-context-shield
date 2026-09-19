//! Black-box tests for the MCP stdio server (`do-context-shield mcp-stdio`).
//!
//! The server runs as a real subprocess, so the newline-delimited JSON-RPC
//! transport itself — error recovery and the clean EOF shutdown included — is
//! exercised, not just request handling.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// One running `mcp-stdio` server with piped stdio.
struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Hermetic `$HOME`, kept alive for as long as the child runs.
    _home: tempfile::TempDir,
}

impl McpSession {
    /// Spawn `do-context-shield mcp-stdio` with pipes for both directions.
    fn start() -> Self {
        let home = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("cannot create a temp directory: {error}"),
        };
        let mut child = match Command::new(env!("CARGO_BIN_EXE_do-context-shield"))
            .arg("mcp-stdio")
            .current_dir(home.path())
            .env("HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => panic!("cannot spawn `do-context-shield mcp-stdio`: {error}"),
        };
        let Some(stdin) = child.stdin.take() else {
            panic!("piped stdin missing");
        };
        let Some(stdout) = child.stdout.take() else {
            panic!("piped stdout missing");
        };
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            _home: home,
        }
    }

    /// Send one JSON-RPC message and return the response line that follows.
    fn send(&mut self, request: &str) -> Value {
        self.write_line(request);
        self.read_response()
    }

    /// Send a JSON-RPC notification, which must not produce a response.
    fn send_notification(&mut self, request: &str) {
        self.write_line(request);
    }

    /// Close stdin (EOF) and assert the server shut down cleanly.
    fn close(mut self) {
        drop(self.stdin);
        match self.child.wait() {
            Ok(status) => assert!(status.success(), "mcp-stdio exited with {status}"),
            Err(error) => panic!("cannot wait for mcp-stdio: {error}"),
        }
    }

    fn write_line(&mut self, request: &str) {
        if let Err(error) = writeln!(self.stdin, "{request}") {
            panic!("cannot write request: {error}");
        }
        if let Err(error) = self.stdin.flush() {
            panic!("cannot flush request: {error}");
        }
    }

    fn read_response(&mut self) -> Value {
        let mut line = String::new();
        match self.stdout.read_line(&mut line) {
            Ok(0) => panic!("server closed stdout before answering"),
            Ok(_) => {}
            Err(error) => panic!("cannot read response: {error}"),
        }
        match serde_json::from_str(&line) {
            Ok(response) => response,
            Err(error) => panic!("response is not valid JSON: {error} (line: {line:?})"),
        }
    }
}

/// A `tools/call` request line for `name` with `arguments`.
fn tool_call(name: &str, arguments: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    .to_string()
}

/// Text payload of a successful `tools/call` response.
fn content_text(response: &Value) -> String {
    match response
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
    {
        Some(text) => text.to_owned(),
        None => panic!("missing content text in {response}"),
    }
}

/// JSON-RPC error code, if the response is an error.
fn error_code(response: &Value) -> Option<i64> {
    response.pointer("/error/code").and_then(Value::as_i64)
}

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
    let mut session = McpSession::start();
    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "s1"}),
    )));
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");
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
fn forget_over_stdio() {
    let mut session = McpSession::start();
    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "f1"}),
    )));
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");
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
