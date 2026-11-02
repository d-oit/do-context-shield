//! Table-driven MCP threat matrix over the real stdio transport.
//!
//! Every case runs against the compiled binary in a fresh process with a
//! persistent vault. A known mapping is created first, the case's hostile
//! request is sent, and the test asserts four things: the protocol result, that
//! the mapping survived (a rejected request never mutates the vault), that no
//! response or stderr carries the raw canary, and that a valid follow-up
//! request still works (one malicious request cannot poison the next). The
//! manifest lives in `tests/fixtures/mcp_threat_cases.json`.

use std::path::Path;

use serde_json::{Value, json};

mod common;

use common::{McpSession, content_text, error_code, temp_dir, tool_call};

const MANIFEST: &str = include_str!("fixtures/mcp_threat_cases.json");

fn manifest() -> Value {
    match serde_json::from_str(MANIFEST) {
        Ok(value) => value,
        Err(error) => panic!("threat manifest is not valid JSON: {error}"),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("threat manifest case is missing `{key}`: {value}"))
}

/// Start a session with the declared tool surface and an optional persistent
/// vault file.
fn session_with(tools: &str, vault: Option<&Path>) -> McpSession {
    let mut args: Vec<String> = Vec::new();
    if tools == "all" {
        args.push("--tools".to_owned());
        args.push("all".to_owned());
    }
    if let Some(vault) = vault {
        args.push("--vault-file".to_owned());
        args.push(vault.to_string_lossy().into_owned());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    McpSession::start_with(&refs)
}

fn sanitize(session: &mut McpSession, canary: &str, session_id: &str) -> String {
    let response = session.send(&tool_call(
        "context.sanitize",
        &json!({"text": canary, "session": session_id}),
    ));
    let token = content_text(&response);
    assert!(
        !token.contains(canary),
        "sanitize returned the raw value: {token}"
    );
    token
}

/// Restore `token` in a verifier process sharing the vault: the mapping must
/// still resolve to the canary.
fn assert_mapping_alive(vault: &Path, token: &str, session_id: &str, canary: &str, label: &str) {
    let mut verifier = session_with("all", Some(vault));
    let restored = content_text(&verifier.send(&tool_call(
        "context.restore",
        &json!({"text": token, "session": session_id}),
    )));
    assert_eq!(restored, canary, "{label}: the mapping was mutated");
    verifier.close();
}

fn assert_expectation(response: &Value, expect: &Value, label: &str) {
    match expect.get("response").and_then(Value::as_str) {
        Some("error") => {
            assert_eq!(
                error_code(response),
                expect.get("code").and_then(Value::as_i64),
                "{label}: {response}"
            );
        }
        Some("tool_error") => {
            assert_eq!(
                response.pointer("/result/isError").and_then(Value::as_bool),
                Some(true),
                "{label}: expected a tool error: {response}"
            );
        }
        Some("result") => {
            assert!(
                response.get("result").is_some(),
                "{label}: expected a result envelope: {response}"
            );
        }
        other => panic!("{label}: unknown expected response kind {other:?}"),
    }
}

#[test]
fn threat_matrix_cases_leave_state_and_egress_safe() {
    let manifest = manifest();
    let canary = field(&manifest, "canary");
    let session_id = field(&manifest, "session");
    let temp = temp_dir();
    let vault = temp.path().join("threat-vault.json");

    let Some(cases) = manifest.get("cases").and_then(Value::as_array) else {
        panic!("threat manifest has no cases");
    };
    for case in cases {
        let name = field(case, "name");
        // A case always needs `sanitize`; the hostile request itself decides
        // whether the extra tools are exposed.
        let tools = case.get("tools").and_then(Value::as_str).unwrap_or("all");
        let mut session = session_with(tools, Some(&vault));
        let token = sanitize(&mut session, canary, session_id);

        let response = session.send(field(case, "request"));
        assert_expectation(&response, &case["expect"], name);
        assert!(
            !response.to_string().contains(canary),
            "{name}: the response echoed the raw canary: {response}"
        );
        if let Some(fragment) = case.get("response_contains").and_then(Value::as_str) {
            assert!(
                response.to_string().contains(fragment),
                "{name}: missing `{fragment}` in {response}"
            );
        }

        // One malicious request must not poison the following valid request.
        let inspected =
            content_text(&session.send(&tool_call("context.inspect", &json!({"text": canary}))));
        assert!(
            !inspected.contains(canary),
            "{name}: inspect leaked the value after the hostile request"
        );

        let stderr = session.close_with_stderr();
        assert!(
            !stderr.contains(canary),
            "{name}: stderr leaked the raw canary: {stderr}"
        );
        assert_mapping_alive(&vault, &token, session_id, canary, name);
    }
}

#[test]
fn oversized_frame_never_reaches_the_pipeline() {
    let manifest = manifest();
    let canary = field(&manifest, "canary");
    let session_id = field(&manifest, "session");
    let oversized = &manifest["oversized"];
    let name = field(oversized, "name");
    let temp = temp_dir();
    let vault = temp.path().join("oversized-vault.json");

    let mut session = session_with("all", Some(&vault));
    let token = sanitize(&mut session, canary, session_id);

    // One byte over the transport limit, no newline inside the frame.
    let prefix = field(oversized, "request_prefix");
    let frame = format!(
        "{prefix}{}",
        " ".repeat(do_context_shield_mcp_server::DEFAULT_MAX_REQUEST_BYTES)
    );
    session.write_line(&frame);
    let response = session.read_response();
    assert_expectation(&response, &oversized["expect"], name);
    assert_eq!(response.get("id"), Some(&Value::Null), "{response}");
    assert!(
        !response.to_string().contains(canary),
        "{name}: the response echoed the raw canary: {response}"
    );
    let message = response
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("limit"), "{name}: {response}");
    // The session ends deterministically after the oversized frame.
    session.close();

    assert_mapping_alive(&vault, &token, session_id, canary, name);
}
