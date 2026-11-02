//! JSON-RPC batch arrays are unsupported in every advertised revision.
//!
//! Batching was removed from MCP with the 2025-06-18 revision, so neither the
//! `2025-11-25` nor the `2026-07-28` wire accepts an array. An array is one
//! invalid MCP message: no member is dispatched, so a batch cannot smuggle a
//! mutation past the boundary even when a valid mutating request comes first.

use super::*;

/// Assert `response` is one JSON-RPC invalid-request error with a `null` id.
fn assert_batch_rejected(response: Option<Value>, label: &str) {
    let Some(value) = response else {
        panic!("{label}: expected an error response");
    };
    assert!(
        value.is_object(),
        "{label}: a batch must produce one object response, not {value}"
    );
    assert_eq!(
        value.get("id"),
        Some(&Value::Null),
        "{label}: an array has no id to echo: {value}"
    );
    assert_eq!(
        value.pointer("/error/code").and_then(Value::as_i64),
        Some(-32600),
        "{label}: {value}"
    );
    assert!(
        value.get("result").is_none(),
        "{label}: a rejected batch must not carry a result: {value}"
    );
}

#[test]
fn batch_arrays_are_rejected_for_every_shape() {
    let mut pipeline = pipeline();
    let valid_call = tool_call("context.sanitize", "alice@example.com", Some("s"));
    let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let empty = "[]";
    let one = format!("[{valid_call}]");
    let mixed = format!("[{valid_call},{notification}]");
    let malformed_members = r#"[{"jsonrpc":"2.0","id":1},5,null,{"method":"tools/call"}]"#;
    let nested = format!("[[{valid_call}]]");

    for (label, body) in [
        ("empty", empty.to_owned()),
        ("one element", one),
        ("mixed with notification", mixed),
        ("malformed members", malformed_members.to_owned()),
        ("nested array", nested),
    ] {
        assert_batch_rejected(request(&mut pipeline, &body), label);
    }
    // No member ran: a batched sanitize for this session never minted the
    // mapping, so a fresh sanitize still starts at counter 1.
    let fresh = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "bob@example.com", Some("s")),
    ));
    assert_placeholder(&fresh, "EMAIL", 1);
}

#[test]
fn a_batched_mutation_cannot_delete_a_live_mapping() {
    let mut pipeline = pipeline();
    let sanitized = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert_placeholder(&sanitized, "EMAIL", 1);

    // A valid mutating request first, then a notification: if the server
    // dispatched members, the mapping would be gone and this restore empty.
    let batch = format!(
        r#"[{},{{"jsonrpc":"2.0","method":"notifications/initialized"}}]"#,
        tool_call("context.forget", "", Some("s"))
    );
    assert_batch_rejected(request(&mut pipeline, &batch), "batched forget");

    let restored = content_text(request(
        &mut pipeline,
        &tool_call("context.restore", &sanitized, Some("s")),
    ));
    assert_eq!(restored, "alice@example.com");
}

#[test]
fn a_batch_is_distinct_from_a_single_object_request() {
    let mut pipeline = pipeline();
    // The same request as a single object is answered normally...
    let single = tool_call("context.sanitize", "alice@example.com", Some("s"));
    let value = request(&mut pipeline, &single);
    let Some(value) = value else {
        panic!("expected a response");
    };
    assert!(value.get("result").is_some(), "{value}");
    // ...while the array wrapper is a protocol error, not a result.
    let batched = format!("[{single}]");
    assert_batch_rejected(request(&mut pipeline, &batched), "array wrapper");
}
