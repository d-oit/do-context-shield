use super::*;
use do_context_shield_plugin_api::{Entity, JudgeError, Judgment, SemanticJudge, SemanticLabel};

fn pipeline() -> PrivacyPipeline {
    let vault = match do_context_shield_plugin_registry::vault("memory") {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let detector = match do_context_shield_plugin_registry::detector("regex") {
        Ok(detector) => detector,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let policy = match do_context_shield_plugin_registry::policy("default") {
        Ok(policy) => policy,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let transformer = match do_context_shield_plugin_registry::transformer("pseudonymize") {
        Ok(transformer) => transformer,
        Err(error) => panic!("unexpected error: {error}"),
    };
    PrivacyPipeline::new(detector, policy, transformer, vault)
}

fn request(pipeline: &mut PrivacyPipeline, body: &str) -> Option<Value> {
    match handle_request(pipeline, body) {
        Ok(response) => response,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn tool_call(name: &str, text: &str, session: Option<&str>) -> String {
    let session_arg = match session {
        Some(session) => format!(r#","session":"{session}""#),
        None => String::new(),
    };
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{{"text":{text:?}{session_arg}}}}}}}"#
    )
}

fn content_text(response: Option<Value>) -> String {
    let Some(value) = response else {
        panic!("expected a response");
    };
    value
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing content text in {value}"))
        .to_owned()
}

/// Tool call with extra raw JSON argument fragments appended after `session`
/// (e.g. `,"recipient":"local"`).
fn tool_call_with_context(name: &str, text: &str, extra: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{{"text":{text:?},"session":"ctx-test"{extra}}}}}}}"#
    )
}

fn context_sanitize(pipeline: &mut PrivacyPipeline, text: &str, extra: &str) -> Option<Value> {
    request(
        pipeline,
        &tool_call_with_context("context.sanitize", text, extra),
    )
}

#[test]
fn discover_advertises_modern_and_legacy() {
    let mut pipeline = pipeline();
    let response = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#,
    );
    let Some(value) = response else {
        panic!("expected a response");
    };
    let versions = value
        .pointer("/result/supportedVersions")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing supportedVersions in {value}"));
    assert!(versions.iter().any(|version| version == MODERN_VERSION));
    assert!(versions.iter().any(|version| version == LEGACY_VERSION));
}

#[test]
fn legacy_initialize_and_notification() {
    let mut pipeline = pipeline();
    let response = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );
    let Some(value) = response else {
        panic!("expected a response");
    };
    assert_eq!(
        value
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str),
        Some(LEGACY_VERSION)
    );
    let notified = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    assert_eq!(notified, None);
}

#[test]
fn tools_list_is_deterministic_and_cacheable() {
    let mut pipeline = pipeline();
    let response = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
    );
    let Some(value) = response else {
        panic!("expected a response");
    };
    let names: Vec<&str> = value
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing tools in {value}"))
        .iter()
        .map(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("tool without name in {tool}"))
        })
        .collect();
    assert_eq!(
        names,
        vec![
            "context.sanitize",
            "context.restore",
            "context.inspect",
            "context.forget"
        ]
    );
    assert_eq!(
        value.pointer("/result/ttlMs").and_then(Value::as_u64),
        Some(300_000)
    );
    assert_eq!(
        value.pointer("/result/cacheScope").and_then(Value::as_str),
        Some("private")
    );
    // `context.sanitize` advertises the optional enforcement-context fields.
    let category_enum = value
        .pointer("/result/tools/0/inputSchema/properties/data_category/enum")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing data_category enum in {value}"));
    assert_eq!(category_enum.len(), 3);
    let recipient_enum = value
        .pointer("/result/tools/0/inputSchema/properties/recipient/enum")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing recipient enum in {value}"));
    assert_eq!(recipient_enum.len(), 4);
}

#[test]
fn sanitize_restore_round_trip_is_scope_limited() {
    let mut pipeline = pipeline();
    let sanitized = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert!(!sanitized.contains("alice@example.com"));
    let restored = content_text(request(
        &mut pipeline,
        &tool_call("context.restore", &sanitized, Some("s")),
    ));
    assert_eq!(restored, "alice@example.com");
    let blocked = content_text(request(
        &mut pipeline,
        &tool_call("context.restore", &sanitized, Some("other")),
    ));
    assert_eq!(blocked, sanitized);
}

#[test]
fn sanitize_without_session_falls_back_to_default_scope() {
    let mut pipeline = pipeline();
    let sanitized = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", None),
    ));
    assert!(sanitized.contains("__DO_PRIVATE_EMAIL_1__"), "{sanitized}");
}

#[test]
fn restore_without_session_is_rejected() {
    let mut pipeline = pipeline();
    let response = request(
        &mut pipeline,
        &tool_call("context.restore", "__DO_PRIVATE_EMAIL_1__", None),
    );
    let Some(value) = response else {
        panic!("expected an error response");
    };
    assert!(value.get("error").is_some(), "expected error in {value}");
}

#[test]
fn inspect_reports_entities_as_json() {
    let mut pipeline = pipeline();
    let text = content_text(request(
        &mut pipeline,
        &tool_call("context.inspect", "alice@example.com", None),
    ));
    assert!(text.contains(r#""kind":"email""#), "{text}");
    assert!(text.contains(r#""end":17"#), "{text}");
    // The matched text must never travel back to the calling agent.
    assert!(!text.contains("alice@example.com"), "{text}");
}

struct TestDomainJudge;

impl SemanticJudge for TestDomainJudge {
    fn judge(&self, _input: &str, entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        Ok(entities
            .iter()
            .enumerate()
            .map(|(index, _)| Judgment::Labeled {
                index,
                label: SemanticLabel::Test,
                confidence: 0.95,
            })
            .collect())
    }
}

#[test]
fn judge_labels_reach_the_policy() {
    let mut judged = pipeline().with_judge(Box::new(TestDomainJudge));
    let kept = content_text(request(
        &mut judged,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert_eq!(kept, "alice@example.com");
    let mut plain = pipeline();
    let replaced = content_text(request(
        &mut plain,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert_eq!(replaced, "__DO_PRIVATE_EMAIL_1__");
}

#[test]
fn unknown_tool_method_and_malformed_json_are_errors() {
    let mut pipeline = pipeline();
    for body in [
        tool_call("context.nope", "x", None),
        r#"{"jsonrpc":"2.0","id":2,"method":"bogus/method","params":{}}"#.to_owned(),
        r#"{"jsonrpc": broken"#.to_owned(),
    ] {
        let response = request(&mut pipeline, &body);
        let Some(value) = response else {
            panic!("expected an error response for {body}");
        };
        assert!(value.get("error").is_some(), "expected error in {value}");
    }
}

#[test]
fn missing_or_non_string_text_is_rejected() {
    // A malformed call must not silently sanitize an empty string.
    let mut pipeline = pipeline();
    for (name, arguments) in [
        ("context.sanitize", r#"{"session":"s"}"#),
        ("context.restore", r#"{"text":42,"session":"s"}"#),
        ("context.inspect", "{}"),
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
        );
        let response = request(&mut pipeline, &body);
        let Some(value) = response else {
            panic!("expected a response for {body}");
        };
        assert!(value.get("error").is_some(), "expected error in {value}");
        assert!(
            value.get("result").is_none(),
            "expected no result in {value}"
        );
    }
}

#[test]
fn non_object_arguments_is_rejected() {
    let mut pipeline = pipeline();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"context.sanitize","arguments":"alice@example.com"}}"#;
    let response = request(&mut pipeline, body);
    let Some(value) = response else {
        panic!("expected a response");
    };
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("arguments"), "{value}");
    assert!(
        value.get("result").is_none(),
        "expected no result in {value}"
    );
}

#[test]
fn non_string_session_is_rejected() {
    let mut pipeline = pipeline();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"context.restore","arguments":{"text":"__DO_PRIVATE_EMAIL_1__","session":5}}}"#;
    let response = request(&mut pipeline, body);
    let Some(value) = response else {
        panic!("expected a response");
    };
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("session"), "{value}");
}

#[test]
fn sanitize_context_recipient_reaches_the_policy() {
    let mut pipeline = pipeline();
    let kept = content_text(context_sanitize(
        &mut pipeline,
        "alice@example.com",
        r#","recipient":"local""#,
    ));
    assert_eq!(kept, "alice@example.com");

    let blocked = context_sanitize(
        &mut pipeline,
        "alice@example.com",
        r#","recipient":"unknown""#,
    );
    let Some(value) = blocked else {
        panic!("expected a response");
    };
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("blocked by policy"), "{value}");
}

#[test]
fn sanitize_context_data_category_reaches_the_policy() {
    let mut pipeline = pipeline();
    let blocked = context_sanitize(
        &mut pipeline,
        "alice@example.com",
        r#","data_category":"special_category""#,
    );
    let Some(value) = blocked else {
        panic!("expected a response");
    };
    assert!(value.get("error").is_some(), "{value}");
}

#[test]
fn sanitize_context_purpose_and_jurisdiction_are_accepted() {
    let mut pipeline = pipeline();
    let sanitized = content_text(context_sanitize(
        &mut pipeline,
        "alice@example.com",
        r#","purpose":"support","jurisdiction":"DE""#,
    ));
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");
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
        let response = context_sanitize(&mut pipeline, "alice@example.com", extra);
        let Some(value) = response else {
            panic!("expected an error response for {extra}");
        };
        assert!(
            value.get("error").is_some(),
            "expected error for {extra} in {value}"
        );
    }
}

/// `context.forget` call with an optional session argument.
fn forget_call(session: Option<&str>) -> String {
    let session_arg = match session {
        Some(session) => format!(r#""session":"{session}""#),
        None => String::new(),
    };
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"context.forget","arguments":{{{session_arg}}}}}}}"#
    )
}

#[test]
fn forget_requires_an_explicit_session() {
    let mut pipeline = pipeline();
    let response = request(&mut pipeline, &forget_call(None));
    let Some(value) = response else {
        panic!("expected a response");
    };
    assert!(value.get("error").is_some(), "{value}");
}

#[test]
fn forget_deletes_the_session_mappings() {
    let mut pipeline = pipeline();
    let sanitized = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");

    let forgotten = content_text(request(&mut pipeline, &forget_call(Some("s"))));
    assert!(forgotten.contains(r#""forgotten":true"#), "{forgotten}");

    // After the wipe, restore can no longer resolve the placeholder.
    let restored = content_text(request(
        &mut pipeline,
        &tool_call("context.restore", &sanitized, Some("s")),
    ));
    assert_eq!(restored, sanitized);

    // Other sessions are untouched.
    let other = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "bob@example.com", Some("other")),
    ));
    content_text(request(&mut pipeline, &forget_call(Some("s"))));
    let still_resolvable = content_text(request(
        &mut pipeline,
        &tool_call("context.restore", &other, Some("other")),
    ));
    assert_eq!(still_resolvable, "bob@example.com");
}
