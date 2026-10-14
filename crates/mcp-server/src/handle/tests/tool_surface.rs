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

fn annotations<'a>(tools: &'a [Value], name: &str) -> &'a Value {
    let Some(tool) = tools
        .iter()
        .find(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
    else {
        panic!("missing tool `{name}`");
    };
    tool.get("annotations")
        .unwrap_or_else(|| panic!("missing annotations for `{name}`"))
}

#[test]
fn tools_list_advertises_spec_defined_behavior_hints() {
    let mut pipeline = pipeline();
    let response = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    );
    let Some(value) = response else {
        panic!("expected a response");
    };
    let tools = value
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing tools in {value}"));

    let inspect = annotations(tools, "context.inspect");
    assert_eq!(
        inspect.get("readOnlyHint").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        inspect.get("openWorldHint").and_then(Value::as_bool),
        Some(false)
    );

    for name in ["context.sanitize", "context.restore"] {
        let annotation = annotations(tools, name);
        assert_eq!(
            annotation.get("readOnlyHint").and_then(Value::as_bool),
            Some(false),
            "{name}"
        );
        assert_eq!(
            annotation.get("destructiveHint").and_then(Value::as_bool),
            Some(false),
            "{name}"
        );
        assert_eq!(
            annotation.get("openWorldHint").and_then(Value::as_bool),
            Some(false),
            "{name}"
        );
    }

    let forget = annotations(tools, "context.forget");
    assert_eq!(
        forget.get("readOnlyHint").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        forget.get("destructiveHint").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        forget.get("openWorldHint").and_then(Value::as_bool),
        Some(false)
    );
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
        assert_eq!(
            value.pointer("/error/code").and_then(Value::as_i64),
            Some(-32601),
            "{value}"
        );
        assert!(
            value.get("result").is_none(),
            "expected no result in {value}"
        );
    }
}
