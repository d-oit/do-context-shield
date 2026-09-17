//! End-to-end privacy invariants across the default plugin set.
//!
//! These tests exercise the real pipeline (`regex` detector, `default` policy,
//! pseudonymizing transformer, memory vault) instead of asserting documentation.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::ScopeId;
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
    let result = unwrap_ok(pipeline.sanitize(&scope, input));
    assert!(!result.text.contains("alice@example.com"), "{result:?}");
    assert!(!result.text.contains("+1 555 123 4567"), "{result:?}");
    assert!(!result.entities.is_empty(), "{result:?}");
}

#[test]
fn stable_placeholders_preserve_repeated_entity_identity() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let result =
        unwrap_ok(pipeline.sanitize(&scope, "mail alice@example.com then alice@example.com"));
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
    let secret = "sk-12345678901234567890";
    let result = unwrap_ok(pipeline.sanitize(&scope, secret));
    assert!(!result.text.contains(secret), "{result:?}");
    assert!(
        result.text.contains("__DO_PRIVATE_REDACTED__"),
        "{result:?}"
    );
    assert!(result.mappings.is_empty(), "{result:?}");
}

#[test]
fn restore_is_scope_limited() {
    let mut pipeline = pipeline();
    let scope = ScopeId("invariants".to_owned());
    let other = ScopeId("unrelated".to_owned());
    let result = unwrap_ok(pipeline.sanitize(&scope, "alice@example.com"));
    let restored = unwrap_ok(pipeline.restore(&scope, &result.text));
    let blocked = unwrap_ok(pipeline.restore(&other, &result.text));
    assert_eq!(restored, "alice@example.com");
    assert_eq!(blocked, result.text);
}
