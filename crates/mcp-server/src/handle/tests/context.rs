//! Enforcement-context tests: server defaults, per-call overrides, fail-closed parsing.

use super::*;

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
    assert_eq!(
        value.pointer("/result/isError").and_then(Value::as_bool),
        Some(true),
        "{value}"
    );
    let message = value
        .pointer("/result/content/0/text")
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
    assert_eq!(
        value.pointer("/result/isError").and_then(Value::as_bool),
        Some(true),
        "{value}"
    );
    assert!(value.get("error").is_none(), "{value}");
}

#[test]
fn malformed_jurisdiction_is_rejected_before_the_policy() {
    let mut pipeline = pipeline();
    for value in ["", "Germany", "DEU", "de-DE", "D1", "é"] {
        let extra = format!(
            r#","recipient":"trusted","data_category":"special_category","jurisdiction":"{value}""#
        );
        let Some(response) = context_sanitize(&mut pipeline, "alice@example.com", &extra) else {
            panic!("expected a response");
        };
        assert_eq!(
            response.pointer("/result/isError").and_then(Value::as_bool),
            Some(true),
            "{response}"
        );
        assert!(response.get("error").is_none(), "{response}");
        let message = response
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(message.contains("ISO 3166-1 alpha-2"), "{response}");
        assert!(
            !response.to_string().contains("alice@example.com"),
            "{response}"
        );
    }
}

#[test]
fn invalid_jurisdiction_override_never_inherits_the_server_default() {
    // The server default declares a valid code; the per-call value replaces it
    // and must be validated on its own instead of silently falling back.
    let server = ProcessingContext {
        recipient: RecipientClass::Trusted,
        data_category: DataCategory::SpecialCategory,
        jurisdiction: Some("DE".to_owned()),
        ..ProcessingContext::default()
    };
    let mut pipeline = pipeline();
    let Some(rejected) = request_with_context(
        &mut pipeline,
        ToolSet::all(),
        &server,
        &tool_call_with_context(
            "context.sanitize",
            "alice@example.com",
            r#","jurisdiction":"Germany""#,
        ),
    ) else {
        panic!("expected a response");
    };
    assert_eq!(
        rejected.pointer("/result/isError").and_then(Value::as_bool),
        Some(true),
        "{rejected}"
    );

    // Control: a valid override still reaches the policy and declares the
    // jurisdiction, so the trusted special-category transfer pseudonymizes.
    let Some(sanitized) = request_with_context(
        &mut pipeline,
        ToolSet::all(),
        &server,
        &tool_call_with_context(
            "context.sanitize",
            "alice@example.com",
            r#","jurisdiction":"de""#,
        ),
    ) else {
        panic!("expected a response");
    };
    assert_placeholder(&content_text(Some(sanitized)), "EMAIL", 1);
}

#[test]
fn sanitize_context_purpose_and_jurisdiction_are_accepted() {
    let mut pipeline = pipeline();
    let sanitized = content_text(context_sanitize(
        &mut pipeline,
        "alice@example.com",
        r#","purpose":"support","jurisdiction":"DE""#,
    ));
    assert_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn server_context_supplies_defaults_and_tool_arguments_override() {
    let server = ProcessingContext {
        recipient: RecipientClass::Local,
        ..ProcessingContext::default()
    };
    let mut pipeline = pipeline();

    // Omitted arguments inherit the server context: a local recipient keeps a
    // personal value, so the text comes back verbatim instead of pseudonymized.
    let response = request_with_context(
        &mut pipeline,
        ToolSet::all(),
        &server,
        &tool_call_with_context("context.sanitize", "alice@example.com", ""),
    );
    assert_eq!(content_text(response), "alice@example.com");

    // An explicit tool argument still wins over the server default.
    let response = request_with_context(
        &mut pipeline,
        ToolSet::all(),
        &server,
        &tool_call_with_context(
            "context.sanitize",
            "bob@example.com",
            r#","recipient":"external""#,
        ),
    );
    let text = content_text(response);
    assert!(text.starts_with("__DO_PRIVATE_EMAIL_1_"), "{text}");
}
