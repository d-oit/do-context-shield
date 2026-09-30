//! Pipeline round-trips through the dispatch path: sanitize/restore/inspect,
//! the optional judge, and session deletion.

use super::*;
use do_context_shield_plugin_api::{Entity, JudgeError, Judgment, SemanticJudge, SemanticLabel};

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
