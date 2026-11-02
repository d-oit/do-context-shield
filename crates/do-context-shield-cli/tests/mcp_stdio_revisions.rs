//! Stdio protocol fixtures for both advertised MCP wire revisions.
//!
//! The official `@modelcontextprotocol/conformance` server runner accepts only
//! an HTTP `--url`, so it cannot drive a stdio server (upstream issue #258).
//! Rather than invent an HTTP transport in the product or mark HTTP-only
//! scenarios as passed, these fixtures exercise the real compiled binary over
//! stdio for each advertised revision independently: discovery, tool listing, a
//! benign inspect, a synthetic PII sanitize, and default-denied restore.

use serde_json::{Value, json};

mod common;

use common::{McpSession, content_text, error_code, tool_names};

/// A synthetic email; it must never appear in a model-facing response or on
/// stderr.
const CANARY: &str = "alice@example.com";

/// A `tools/call` request that carries namespaced request metadata.
fn tool_call_with_meta(name: &str, arguments: &Value, meta: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": meta},
    })
    .to_string()
}

#[test]
fn modern_revision_round_trip() {
    let mut session = McpSession::start();
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "conformance-fixture", "version": "1.0.0"},
    });

    let discover = session.send(
        &json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}})
            .to_string(),
    );
    let versions = discover
        .pointer("/result/supportedVersions")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing supportedVersions in {discover}"));
    assert!(versions.iter().any(|version| version == "2026-07-28"));
    assert!(versions.iter().any(|version| version == "2025-11-25"));
    assert_eq!(
        discover
            .pointer("/result/resultType")
            .and_then(Value::as_str),
        Some("complete"),
        "{discover}"
    );

    let listed = session.send(
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":meta}}).to_string(),
    );
    assert_eq!(
        tool_names(&listed),
        ["context.sanitize", "context.inspect"],
        "the modern model-facing surface"
    );

    let inspected = content_text(&session.send(&tool_call_with_meta(
        "context.inspect",
        &json!({"text": CANARY}),
        &meta,
    )));
    assert!(!inspected.contains(CANARY), "inspect leaked the value");
    assert!(inspected.contains("email"), "{inspected}");

    let sanitized = content_text(&session.send(&tool_call_with_meta(
        "context.sanitize",
        &json!({"text": CANARY, "session": "conformance"}),
        &meta,
    )));
    common::assert_placeholder(&sanitized, "EMAIL", 1);

    // Default-denied: restore is not on the model-facing surface.
    let denied = session.send(&tool_call_with_meta(
        "context.restore",
        &json!({"text": sanitized, "session": "conformance"}),
        &meta,
    ));
    assert_eq!(error_code(&denied), Some(-32601), "{denied}");
    assert!(!denied.to_string().contains(CANARY), "{denied}");

    let stderr = session.close_with_stderr();
    assert!(
        !stderr.contains(CANARY),
        "stderr leaked the value: {stderr}"
    );
}

#[test]
fn legacy_revision_round_trip() {
    let mut session = McpSession::start();
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
        "io.modelcontextprotocol/clientCapabilities": {},
    });

    let initialized = session.send(
        &json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{
                "protocolVersion":"2025-11-25",
                "capabilities":{},
                "clientInfo":{"name":"conformance-fixture","version":"1.0.0"},
            },
        })
        .to_string(),
    );
    assert_eq!(
        initialized
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str),
        Some("2025-11-25"),
        "{initialized}"
    );
    session.send_notification(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);

    let listed = session.send(
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":meta}}).to_string(),
    );
    assert_eq!(
        tool_names(&listed),
        ["context.sanitize", "context.inspect"],
        "the legacy model-facing surface"
    );

    let inspected = content_text(&session.send(&tool_call_with_meta(
        "context.inspect",
        &json!({"text": CANARY}),
        &meta,
    )));
    assert!(!inspected.contains(CANARY), "inspect leaked the value");
    assert!(inspected.contains("email"), "{inspected}");

    let sanitized = content_text(&session.send(&tool_call_with_meta(
        "context.sanitize",
        &json!({"text": CANARY, "session": "conformance"}),
        &meta,
    )));
    common::assert_placeholder(&sanitized, "EMAIL", 1);

    let denied = session.send(&tool_call_with_meta(
        "context.restore",
        &json!({"text": sanitized, "session": "conformance"}),
        &meta,
    ));
    assert_eq!(error_code(&denied), Some(-32601), "{denied}");
    assert!(!denied.to_string().contains(CANARY), "{denied}");

    let stderr = session.close_with_stderr();
    assert!(
        !stderr.contains(CANARY),
        "stderr leaked the value: {stderr}"
    );
}

/// Both revisions reject a JSON-RPC batch array without executing a member,
/// even when the member is a valid mutation.
#[test]
fn both_revisions_reject_batch_arrays_without_side_effects() {
    for meta in [
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2025-11-25",
            "io.modelcontextprotocol/clientCapabilities": {},
        }),
    ] {
        let mut session = McpSession::start_with(&["--tools", "all"]);
        let sanitized = content_text(&session.send(&tool_call_with_meta(
            "context.sanitize",
            &json!({"text": CANARY, "session": "batch"}),
            &meta,
        )));
        common::assert_placeholder(&sanitized, "EMAIL", 1);

        let member = tool_call_with_meta(
            "context.forget",
            &json!({"session": "batch"}),
            &json!({"unused": true}),
        );
        let batch = format!("[{member}]");
        let rejected = session.send(&batch);
        assert_eq!(error_code(&rejected), Some(-32600), "{rejected}");
        assert_eq!(rejected.get("id"), Some(&Value::Null), "{rejected}");

        // The mapping still resolves: no member ran.
        let restored = content_text(&session.send(&tool_call_with_meta(
            "context.restore",
            &json!({"text": sanitized, "session": "batch"}),
            &meta,
        )));
        assert_eq!(restored, CANARY);
        session.close();
    }
}
