//! The `--tools` surface: the default must hide the raw-value tools.

use super::*;

#[test]
fn default_tool_set_exposes_only_sanitize_and_inspect() {
    let mut pipeline = pipeline();
    let response = request_with(
        &mut pipeline,
        ToolSet::model_facing(),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    );
    let Some(value) = response else {
        panic!("expected a response");
    };
    let names: Vec<&str> = value
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .map_or_else(
            || panic!("missing tools in {value}"),
            |tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool.get("name").and_then(Value::as_str))
                    .collect()
            },
        );
    assert_eq!(names, ["context.sanitize", "context.inspect"]);
}

#[test]
fn disabled_tools_are_rejected_with_guidance() {
    let mut pipeline = pipeline();
    for body in [
        tool_call(
            "context.restore",
            "__DO_PRIVATE_EMAIL_1_9F3A2C7B5D1E4F08__",
            Some("s"),
        ),
        tool_call("context.forget", "", Some("s")),
    ] {
        let response = request_with(&mut pipeline, ToolSet::model_facing(), &body);
        let Some(value) = response else {
            panic!("expected a response for {body}");
        };
        let message = value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains("not enabled"), "{value}");
        assert!(
            value.get("result").is_none(),
            "expected no result in {value}"
        );
    }
}
