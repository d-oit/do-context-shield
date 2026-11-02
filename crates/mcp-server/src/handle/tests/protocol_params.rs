//! Method-aware parameter validation: the schema is pinned per method and a
//! malformed request is rejected before dispatch, so it can never reach the
//! sanitizer, vault, plugins, or audit sink.

use std::sync::atomic::Ordering;

use super::*;

#[allow(clippy::too_many_lines)] // one table: every method schema in one place
#[test]
fn method_parameter_shapes_are_rejected_before_dispatch() {
    let mut pipeline = pipeline();
    let oversized_name = "n".repeat(200);
    let cases: Vec<(String, i64)> = vec![
        // `server/discover` accepts no parameters besides `_meta`.
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"cursor":"x"}}"#.to_owned(),
            -32602,
        ),
        // `tools/list` implements no pagination: a cursor is not silently
        // ignored (that would repeat a page forever).
        (
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"x"}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":7}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"unexpected":true}}"#.to_owned(),
            -32602,
        ),
        // `tools/call` requires `name`.
        (
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call"}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"arguments":{}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":null,"arguments":{}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":42,"arguments":{}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"","arguments":{}}}"#.to_owned(),
            -32602,
        ),
        (
            format!(
                r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":"{oversized_name}","arguments":{{}}}}}}"#
            ),
            -32602,
        ),
        // `arguments` is optional but must be an object when present.
        (
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"context.inspect","arguments":null}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"context.inspect","arguments":"x"}}"#.to_owned(),
            -32602,
        ),
        // Task/request fields are only accepted when implemented.
        (
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"context.inspect","arguments":{"text":"x"},"task":{"id":"t"}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"context.inspect","arguments":{"text":"x"},"requestId":"r"}}"#.to_owned(),
            -32602,
        ),
        // `initialize` was removed in the modern revision; malformed modern
        // metadata is never downgraded to a legacy handshake.
        (
            r#"{"jsonrpc":"2.0","id":15,"method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":16,"method":"initialize","params":{"protocolVersion":42}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":17,"method":"initialize","params":{"protocolVersion":"1900-01-01"}}"#.to_owned(),
            -32022,
        ),
        (
            r#"{"jsonrpc":"2.0","id":18,"method":"initialize","params":{"capabilities":[]}}"#.to_owned(),
            -32602,
        ),
        // `clientInfo` is validated whenever supplied, and never trusted.
        (
            r#"{"jsonrpc":"2.0","id":19,"method":"initialize","params":{"clientInfo":"x"}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"clientInfo":{"name":"n"}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":21,"method":"initialize","params":{"clientInfo":{"name":"","version":"1"}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":22,"method":"initialize","params":{"clientInfo":{"name":"n","version":""}}}"#.to_owned(),
            -32602,
        ),
        (
            r#"{"jsonrpc":"2.0","id":23,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientInfo":[]}}}"#.to_owned(),
            -32602,
        ),
        (
            format!(
                r#"{{"jsonrpc":"2.0","id":24,"method":"tools/list","params":{{"_meta":{{"io.modelcontextprotocol/clientInfo":{{"name":"{oversized_name}","version":"1"}}}}}}}}"#
            ),
            -32602,
        ),
        // `_meta` itself must be an object.
        (
            r#"{"jsonrpc":"2.0","id":25,"method":"tools/list","params":{"_meta":[]}}"#.to_owned(),
            -32602,
        ),
    ];
    for (body, code) in cases {
        let response = request(&mut pipeline, &body);
        assert_eq!(
            error_code(response.as_ref()),
            Some(code),
            "for {body}: {response:?}"
        );
    }
}

#[test]
fn valid_method_parameters_are_accepted() {
    let mut pipeline = pipeline();
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"client","version":"1.0.0","vendor":"extension"}}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientInfo":{"name":"client","version":"1.0.0"}}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}"#,
        // `arguments` is optional; a missing one dispatches (and this tool
        // then reports its own missing `text` as a tool error).
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"context.inspect"}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"context.inspect","arguments":{"text":"alice@example.com"},"_meta":{}}}"#,
    ] {
        let response = request(&mut pipeline, body);
        let Some(value) = response else {
            panic!("expected a response for {body}");
        };
        assert!(
            value.get("result").is_some(),
            "expected a result envelope for {body}: {value}"
        );
    }
}

#[test]
fn rejected_parameters_never_reach_the_pipeline_or_echo_submitted_text() {
    let (mut pipeline, calls) = counting_pipeline();
    let canary = "CANARY-do-not-echo-1234";
    for body in [
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"context.sanitize","arguments":"{canary}"}}}}"#
        ),
        format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"context.sanitize","arguments":{{"text":"{canary}"}},"{canary}":1}}}}"#
        ),
        format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"context.sanitize","arguments":{{"text":"{canary}"}},"task":{{"id":"{canary}"}}}}}}"#
        ),
        format!(
            r#"{{"jsonrpc":"2.0","id":4,"method":"server/discover","params":{{"{canary}":true}}}}"#
        ),
        format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"initialize","params":{{"clientInfo":{{"name":"{canary}","version":""}}}}}}"#
        ),
    ] {
        let response = request(&mut pipeline, &body);
        assert_eq!(
            error_code(response.as_ref()),
            Some(-32602),
            "for {body}: {response:?}"
        );
        let rendered = response.map_or_else(String::new, |value| value.to_string());
        assert!(
            !rendered.contains(canary),
            "error echoed submitted text: {rendered}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a rejected request reached the detector"
    );

    // A valid request in the same session still runs.
    let ok = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"context.inspect","arguments":{"text":"alice@example.com"}}}"#,
    );
    assert!(
        ok.as_ref()
            .is_some_and(|value| value.get("result").is_some()),
        "{ok:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
