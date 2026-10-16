//! Plan postconditions on the transformer's output: a successful sanitize
//! never returns text that still contains a value the plan removed.
//!
//! Detection is boundary- and width-based, so a duplicated secret can sit just
//! outside every detectable span. These regressions pin the fuzz-found case
//! where redacting only the detected span left the raw value in the output;
//! the pipeline now fails closed instead.

use super::*;
use do_context_shield_plugin_api::RecipientClass;

/// A google-shaped key: `AIza` plus exactly 35 tail characters, ending in `_`.
fn google_shaped_key() -> String {
    format!("AIza{}_", "SYNTHETIC0123456789012345678901234")
}

#[test]
fn a_glued_duplicate_of_a_redacted_key_fails_closed() {
    let mut pipeline = pipeline();
    let key = google_shaped_key();
    assert_eq!(key.len(), 39);
    // The second copy is glued to word characters, so the boundary rules
    // report only the first one; redacting that span alone would emit the raw
    // key. The call must fail closed instead, and the error must not carry the
    // value it refused to protect.
    let input = format!("{key} and x{key}y");
    let error = sanitize_err(&mut pipeline, &input);
    assert!(matches!(error, PipelineError::Transform(_)), "{error:?}");
    assert!(!error.to_string().contains(&key), "{error}");
}

#[test]
fn a_duplicate_glued_after_a_digit_fails_closed() {
    let mut pipeline = pipeline();
    let key = format!("sk-{}", "SYNTHETIC0123456789");
    let input = format!("{key} and 8{key}");
    let error = sanitize_err(&mut pipeline, &input);
    assert!(matches!(error, PipelineError::Transform(_)), "{error:?}");
}

#[test]
fn a_lone_detected_key_still_sanitizes() {
    let mut pipeline = pipeline();
    let key = google_shaped_key();
    let result = sanitize_ok(&mut pipeline, &format!("use {key} now"));
    assert!(!result.text.contains(&key), "{result:?}");
    assert!(
        result.text.contains("__DO_PRIVATE_REDACTED__"),
        "{result:?}"
    );
}

#[test]
fn an_undetected_copy_of_a_pseudonymized_value_fails_closed() {
    let value = "alice@example.com";
    // The fixed detector reports only the first copy, so pseudonymizing the
    // span leaves the second one raw.
    let mut pipeline = with_detector(vec![entity("email", 0, value.len(), value)]);
    let error = sanitize_err(&mut pipeline, &format!("{value} then {value}"));
    assert!(matches!(error, PipelineError::Transform(_)), "{error:?}");
}

#[test]
fn a_kept_value_is_not_checked() {
    let value = "alice@example.com";
    let mut pipeline = with_detector(vec![entity("email", 0, value.len(), value)]);
    let context = ProcessingContext {
        recipient: RecipientClass::Local,
        ..ProcessingContext::default()
    };
    let result = match pipeline.sanitize(&ScopeId("test".to_owned()), value, &context) {
        Ok(result) => result,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(result.text.contains(value), "{result:?}");
}

#[test]
fn a_keep_alias_does_not_exempt_a_removed_secret() {
    // One secret labelled under a secret kind and a non-secret kind: with a
    // local recipient the default policy redacts `api_key` and keeps `note`.
    // Exempting a value because some entity keeps it would return the raw
    // secret at the kept span, so a contradictory plan fails closed.
    let value = format!("sk-{}", "SYNTHETIC0123456789");
    let offset = value.len() + " and ".len();
    let mut pipeline = with_detector(vec![
        entity("api_key", 0, value.len(), &value),
        entity("note", offset, offset + value.len(), &value),
    ]);
    let context = ProcessingContext {
        recipient: RecipientClass::Local,
        ..ProcessingContext::default()
    };
    let input = format!("{value} and {value}");
    let error = match pipeline.sanitize(&ScopeId("test".to_owned()), &input, &context) {
        Ok(result) => panic!("expected a fail-closed error, got {result:?}"),
        Err(error) => error,
    };
    assert!(matches!(error, PipelineError::Transform(_)), "{error:?}");
}
