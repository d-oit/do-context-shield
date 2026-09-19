//! End-to-end privacy invariants across the default plugin set.
//!
//! These tests exercise the real pipeline (`regex` detector, `default` policy,
//! pseudonymizing transformer, memory vault) instead of asserting documentation.

use do_context_shield_core::{PipelineError, PrivacyPipeline};
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{DataCategory, ProcessingContext, RecipientClass, ScopeId};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;
use std::fmt::Debug;

fn pipeline() -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    )
}

fn unwrap_ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

#[test]
fn raw_pii_is_absent_from_sanitized_output() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let input = "Contact alice@example.com or +1 555 123 4567 about the invoice";
    let result = unwrap_ok(pipeline.sanitize(&scope, input, &ProcessingContext::default()));
    assert!(!result.text.contains("alice@example.com"), "{result:?}");
    assert!(!result.text.contains("+1 555 123 4567"), "{result:?}");
    assert!(!result.entities.is_empty(), "{result:?}");
}

#[test]
fn stable_placeholders_preserve_repeated_entity_identity() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let result = unwrap_ok(pipeline.sanitize(
        &scope,
        "mail alice@example.com then alice@example.com",
        &ProcessingContext::default(),
    ));
    assert_eq!(
        result.text.matches("__DO_PRIVATE_EMAIL_1__").count(),
        2,
        "{result:?}"
    );
}

#[test]
fn secret_like_values_are_redacted() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    // Synthetic fixtures built programmatically so no secret-like literal is committed.
    let api_key_fixture = format!("sk-test-{}", "0123456789abcdef");
    let jwt_fixture = format!(
        "eyJ{}.eyJ{}.{}",
        "hbGciOiJIUzI1NiJ9", "zdWIiOiIxIn0", "signature0123456789"
    );
    let input = format!("{api_key_fixture} {jwt_fixture}");
    let result = unwrap_ok(pipeline.sanitize(&scope, &input, &ProcessingContext::default()));
    assert!(!result.text.contains(&api_key_fixture), "{result:?}");
    assert!(!result.text.contains(&jwt_fixture), "{result:?}");
    assert!(
        result.text.contains("__DO_PRIVATE_REDACTED__"),
        "{result:?}"
    );
    // Redacted secrets have no reversible mapping: restore cannot bring them back.
    assert_eq!(
        unwrap_ok(pipeline.restore(&scope, &result.text)),
        result.text
    );
}

#[test]
fn credit_card_is_pseudonymized_not_redacted() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let card = "4111 1111 1111 1111";
    let result = unwrap_ok(pipeline.sanitize(&scope, card, &ProcessingContext::default()));
    // Card numbers are personal data: restorable pseudonyms, not burned values.
    assert!(!result.text.contains(card), "{result:?}");
    assert!(
        !result.text.contains("__DO_PRIVATE_REDACTED__"),
        "{result:?}"
    );
    assert_eq!(unwrap_ok(pipeline.restore(&scope, &result.text)), card);
}

#[test]
fn result_metadata_never_carries_raw_values() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let input = "Contact alice@example.com or +1 555 123 4567 about the invoice";
    let result = unwrap_ok(pipeline.sanitize(&scope, input, &ProcessingContext::default()));

    // Spans still point at the detected regions of the original input…
    let matched: Vec<&str> = result
        .entities
        .iter()
        .map(|entity| &input[entity.start..entity.end])
        .collect();
    assert!(matched.contains(&"alice@example.com"), "{result:?}");
    assert!(matched.contains(&"1 555 123 4567"), "{result:?}");

    // …but the result never repeats the matched text back to a caller.
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("alice@example.com"), "{rendered}");
    assert!(!rendered.contains("1 555 123 4567"), "{rendered}");
}

#[test]
fn restore_is_scope_limited() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let other = ScopeId("unrelated".to_owned());
    let result =
        unwrap_ok(pipeline.sanitize(&scope, "alice@example.com", &ProcessingContext::default()));
    let restored = unwrap_ok(pipeline.restore(&scope, &result.text));
    let blocked = unwrap_ok(pipeline.restore(&other, &result.text));
    assert_eq!(restored, "alice@example.com");
    assert_eq!(blocked, result.text);
}

#[test]
fn context_default_is_safe() {
    let mut pipeline = pipeline();
    let scope = ScopeId("default-context".to_owned());
    let result =
        unwrap_ok(pipeline.sanitize(&scope, "alice@example.com", &ProcessingContext::default()));
    assert!(!result.text.contains("alice@example.com"), "{result:?}");
    assert!(result.text.contains("__DO_PRIVATE_EMAIL_1__"), "{result:?}");
}

#[test]
fn unknown_recipient_blocks() {
    let mut pipeline = pipeline();
    let scope = ScopeId("unknown-recipient".to_owned());
    let context = ProcessingContext {
        recipient: RecipientClass::Unknown,
        ..ProcessingContext::default()
    };
    match pipeline.sanitize(&scope, "alice@example.com", &context) {
        Ok(result) => panic!("expected a policy block, got {result:?}"),
        Err(error) => assert!(matches!(error, PipelineError::Policy(_)), "{error:?}"),
    }
}

#[test]
fn special_category_to_external_blocks() {
    let mut pipeline = pipeline();
    let scope = ScopeId("special-category".to_owned());
    let context = ProcessingContext {
        recipient: RecipientClass::External,
        data_category: DataCategory::SpecialCategory,
        ..ProcessingContext::default()
    };
    match pipeline.sanitize(&scope, "alice@example.com", &context) {
        Ok(result) => panic!("expected a policy block, got {result:?}"),
        Err(error) => assert!(matches!(error, PipelineError::Policy(_)), "{error:?}"),
    }
}

#[test]
fn local_recipient_keeps_non_secret() {
    let mut pipeline = pipeline();
    let scope = ScopeId("local-recipient".to_owned());
    let context = ProcessingContext {
        recipient: RecipientClass::Local,
        ..ProcessingContext::default()
    };
    let result = unwrap_ok(pipeline.sanitize(&scope, "mail alice@example.com", &context));
    assert!(result.text.contains("alice@example.com"), "{result:?}");

    // Secrets stay redacted even for a local recipient.
    let api_key_fixture = format!("sk-test-{}", "0123456789abcdef");
    let result = unwrap_ok(pipeline.sanitize(&scope, &api_key_fixture, &context));
    assert!(!result.text.contains(&api_key_fixture), "{result:?}");
    assert!(
        result.text.contains("__DO_PRIVATE_REDACTED__"),
        "{result:?}"
    );
}
