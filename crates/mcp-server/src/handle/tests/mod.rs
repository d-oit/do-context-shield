use super::*;
use do_context_shield_plugin_api::{Entity, JudgeError, Judgment, SemanticJudge, SemanticLabel};

mod context;
mod errors;
mod tool_surface;

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
    request_with(pipeline, ToolSet::all(), body)
}

fn request_with(pipeline: &mut PrivacyPipeline, tools: ToolSet, body: &str) -> Option<Value> {
    request_with_context(pipeline, tools, &ProcessingContext::default(), body)
}

fn request_with_context(
    pipeline: &mut PrivacyPipeline,
    tools: ToolSet,
    context: &ProcessingContext,
    body: &str,
) -> Option<Value> {
    match handle_request(pipeline, tools, context, body) {
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

/// Assert `text` starts with a minted placeholder for `kind`/`counter`.
fn assert_placeholder(text: &str, kind: &str, counter: u64) {
    let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
    assert!(
        text.starts_with(&prefix),
        "`{text}` does not start with `{prefix}`"
    );
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
    // Every successful 2026-07-28 result carries `resultType: "complete"`.
    assert_eq!(
        value.pointer("/result/resultType").and_then(Value::as_str),
        Some("complete"),
        "{value}"
    );
    // Discovery is cacheable, but privately: the tool surface depends on the
    // registration.
    assert_eq!(
        value.pointer("/result/ttlMs").and_then(Value::as_u64),
        Some(300_000),
        "{value}"
    );
    assert_eq!(
        value.pointer("/result/cacheScope").and_then(Value::as_str),
        Some("private"),
        "{value}"
    );
}

#[test]
fn meta_version_is_read_and_optional() {
    let mut pipeline = pipeline();
    // A modern request carries the namespaced `_meta` keys; it is answered.
    let modern = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
    );
    let Some(value) = modern else {
        panic!("expected a response");
    };
    assert!(value.get("result").is_some(), "{value}");
    // A pre-2026 request without the namespaced metadata is warned about but
    // still answered.
    let legacy = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    let Some(value) = legacy else {
        panic!("expected a response");
    };
    assert!(value.get("result").is_some(), "{value}");
    // The bare pre-2026 key is not the 2026 wire contract: it is treated as
    // absent, so the request is answered with a warning, never rejected.
    let bare = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"protocolVersion":"2026-07-28"}}}"#,
    );
    let Some(value) = bare else {
        panic!("expected a response");
    };
    assert!(value.get("result").is_some(), "{value}");
}

/// JSON-RPC error code of an error response, if the response is an error.
fn error_code(response: Option<&Value>) -> Option<i64> {
    let value = response?;
    value.pointer("/error/code").and_then(Value::as_i64)
}

#[test]
fn protocol_version_metadata_is_enforced() {
    let mut pipeline = pipeline();
    // An unsupported namespaced version is rejected before dispatch — even on
    // `server/discover` and with no capabilities — with the supported set and
    // the requested value in `data`.
    for body in [
        r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"context.sanitize","arguments":{"text":"x"},"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
    ] {
        let response = request(&mut pipeline, body);
        assert_eq!(
            error_code(response.as_ref()),
            Some(-32022),
            "for {body}: {response:?}"
        );
        let Some(value) = response else {
            panic!("expected an error response for {body}");
        };
        assert_eq!(
            value
                .pointer("/error/data/requested")
                .and_then(Value::as_str),
            Some("1900-01-01"),
            "{value}"
        );
        let supported = value
            .pointer("/error/data/supported")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing supported list in {value}"));
        assert!(supported.iter().any(|version| version == MODERN_VERSION));
        assert!(supported.iter().any(|version| version == LEGACY_VERSION));
    }
    // A namespaced version that is not a string is a params-shape error.
    let response = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":2026,"io.modelcontextprotocol/clientCapabilities":{}}}}"#,
    );
    assert_eq!(error_code(response.as_ref()), Some(-32602), "{response:?}");
    // A supported namespaced version requires client capabilities.
    for version in [MODERN_VERSION, LEGACY_VERSION] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{version}"}}}}}}"#
        );
        let response = request(&mut pipeline, &body);
        assert_eq!(
            error_code(response.as_ref()),
            Some(-32602),
            "for {version}: {response:?}"
        );
    }
    // Capabilities that are present but not an object are rejected too.
    let response = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}"#,
    );
    assert_eq!(error_code(response.as_ref()), Some(-32602), "{response:?}");
}

#[test]
fn notifications_are_never_dispatched() {
    let mut pipeline = pipeline();
    // A notification (no `id`) is never answered.
    let cancelled = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
    );
    assert_eq!(cancelled, None);
    let initialized = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    assert_eq!(initialized, None);

    // An id-less `tools/call` that would wipe the scope must not run: the
    // minted mapping still resolves afterwards.
    let sanitized = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert_placeholder(&sanitized, "EMAIL", 1);
    let wipe = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"context.forget","arguments":{"session":"s"}}}"#,
    );
    assert_eq!(wipe, None);
    let restored = content_text(request(
        &mut pipeline,
        &tool_call("context.restore", &sanitized, Some("s")),
    ));
    assert_eq!(restored, "alice@example.com");

    // With an `id` the same method is a request, not a notification: the
    // removed dispatch arm makes it an unknown method.
    let with_id = request(
        &mut pipeline,
        r#"{"jsonrpc":"2.0","id":9,"method":"notifications/initialized"}"#,
    );
    assert_eq!(error_code(with_id.as_ref()), Some(-32601), "{with_id:?}");
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
        value.pointer("/result/resultType").and_then(Value::as_str),
        Some("complete"),
        "{value}"
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
    let call = request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    );
    // A successful tool call is a complete result, never a protocol error.
    assert_eq!(
        call.as_ref()
            .and_then(|value| value.pointer("/result/resultType"))
            .and_then(Value::as_str),
        Some("complete"),
        "{call:?}"
    );
    let sanitized = content_text(call);
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
    assert_placeholder(&sanitized, "EMAIL", 1);
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
    assert_placeholder(&replaced, "EMAIL", 1);
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
fn forget_deletes_the_session_mappings() {
    let mut pipeline = pipeline();
    let sanitized = content_text(request(
        &mut pipeline,
        &tool_call("context.sanitize", "alice@example.com", Some("s")),
    ));
    assert_placeholder(&sanitized, "EMAIL", 1);

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
