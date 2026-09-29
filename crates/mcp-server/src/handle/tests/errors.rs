//! Error shapes: protocol failures stay JSON-RPC errors, tool failures are results.

use super::*;

/// Message of an `isError` tool result, asserting it is not a protocol error.
fn tool_error_text(response: Option<Value>) -> String {
    let Some(value) = response else {
        panic!("expected a response");
    };
    assert_eq!(
        value.pointer("/result/isError").and_then(Value::as_bool),
        Some(true),
        "expected an isError result in {value}"
    );
    assert!(
        value.get("error").is_none(),
        "expected no JSON-RPC error in {value}"
    );
    value
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing content text in {value}"))
        .to_owned()
}

#[test]
fn unknown_method_malformed_json_and_bad_params_are_protocol_errors() {
    let mut pipeline = pipeline();
    for body in [
        tool_call("context.nope", "x", None),
        r#"{"jsonrpc":"2.0","id":2,"method":"bogus/method","params":{}}"#.to_owned(),
        r#"{"jsonrpc": broken"#.to_owned(),
        // A non-object `arguments` value is a failure of the request shape, not
        // of the tool's own validation.
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"context.sanitize","arguments":"alice@example.com"}}"#.to_owned(),
    ] {
        let response = request(&mut pipeline, &body);
        let Some(value) = response else {
            panic!("expected an error response for {body}");
        };
        assert!(value.get("error").is_some(), "expected error in {value}");
        assert!(
            value.get("result").is_none(),
            "expected no result in {value}"
        );
    }
}

#[test]
fn argument_validation_failures_are_iserror_results() {
    // A malformed call must not silently sanitize an empty string, and its
    // failure must reach the caller as a tool result.
    let mut pipeline = pipeline();
    for (label, arguments) in [
        ("missing text", r#"{"session":"s"}"#),
        ("non-string text", r#"{"text":42,"session":"s"}"#),
        ("invalid context enum", r#"{"text":"x","recipient":"boss"}"#),
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"context.sanitize","arguments":{arguments}}}}}"#
        );
        let message = tool_error_text(request(&mut pipeline, &body));
        assert!(!message.is_empty(), "{label}: empty tool error");
    }

    let message = tool_error_text(request(
        &mut pipeline,
        &tool_call("context.restore", "__DO_PRIVATE_EMAIL_1__", None),
    ));
    assert!(message.contains("session"), "{message}");

    let message = tool_error_text(request(
        &mut pipeline,
        &tool_call("context.forget", "", None),
    ));
    assert!(message.contains("session"), "{message}");

    for (name, arguments) in [
        ("context.sanitize", r#"{"text":"x","session":5}"#),
        ("context.inspect", r#"{"text":true}"#),
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
        );
        let message = tool_error_text(request(&mut pipeline, &body));
        assert!(!message.is_empty(), "{name}: empty tool error");
    }
}

#[test]
fn blocked_policy_is_an_iserror_result() {
    let mut pipeline = pipeline();
    let message = tool_error_text(context_sanitize(
        &mut pipeline,
        "alice@example.com",
        r#","recipient":"unknown""#,
    ));
    assert!(message.contains("blocked by policy"), "{message}");
}

#[test]
fn invalid_context_args_fail_closed() {
    let mut pipeline = pipeline();
    for extra in [
        r#","recipient":"boss""#,
        r#","data_category":"health""#,
        r#","recipient":42"#,
        r#","data_category":true"#,
        r#","purpose":42"#,
    ] {
        let message = tool_error_text(context_sanitize(&mut pipeline, "alice@example.com", extra));
        assert!(!message.is_empty(), "{extra}: empty tool error");
    }
}
