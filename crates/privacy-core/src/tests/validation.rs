use super::*;

#[test]
fn bad_utf8_boundary_fails_closed() {
    // "grüße": byte 3 is inside the two-byte `ü`.
    let mut pipeline = with_detector(vec![entity("person", 3, 7, "e")]);
    let error = sanitize_err(&mut pipeline, "grüße");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(
        error.to_string().contains("character boundaries"),
        "{error}"
    );
}

#[test]
fn tampered_value_fails_closed() {
    let mut pipeline = with_detector(vec![entity("email", 0, 5, "bob@x")]);
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("does not match"), "{error}");
}

#[test]
fn out_of_bounds_span_fails_closed() {
    let mut past_end = with_detector(vec![entity("email", 0, 18, "alice@example.com")]);
    let error = sanitize_err(&mut past_end, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");

    let mut reversed = with_detector(vec![entity("email", 5, 2, "x")]);
    let error = sanitize_err(&mut reversed, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("out of bounds"), "{error}");
}

#[test]
fn empty_kind_fails_closed() {
    // A malformed model label can canonicalize to an empty kind; the pipeline
    // rejects it instead of letting an untyped entity reach policy decisions.
    let mut pipeline = with_detector(vec![entity("  ", 0, 5, "alice")]);
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("empty kind"), "{error}");
}

#[test]
fn confidence_out_of_range_fails_closed() {
    let mut too_high = with_detector(vec![Entity {
        confidence: 1.5,
        ..entity("email", 0, 5, "alice")
    }]);
    let error = sanitize_err(&mut too_high, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
    assert!(error.to_string().contains("outside 0..=1"), "{error}");

    // NaN compares false against every bound, so it must be rejected too.
    let mut not_a_number = with_detector(vec![Entity {
        confidence: f32::NAN,
        ..entity("email", 0, 5, "alice")
    }]);
    let error = sanitize_err(&mut not_a_number, "alice@example.com");
    assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
}

#[test]
fn overlapping_spans_resolved_to_longest() {
    let mut pipeline = with_detector(vec![
        entity("person", 0, 5, "alice"),
        entity("email", 0, 17, "alice@example.com"),
    ]);
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert_eq!(result.entities.len(), 1, "{result:?}");
    assert_eq!(result.entities[0].kind, "email");
    assert!(
        result.text.starts_with("__DO_PRIVATE_EMAIL_1_"),
        "{result:?}"
    );
    assert!(!result.text.contains("PERSON"), "{result:?}");
}

#[test]
fn a_later_span_that_is_longer_displaces_a_shorter_overlapping_one() {
    // `api_key` starts inside `person` and covers far more text. Keeping the
    // leftmost span instead of the longest leaves the secret's tail in the
    // sanitized output.
    let mut pipeline = with_detector(vec![
        entity("person", 0, 2, "we"),
        entity("api_key", 1, 12, "e BCDEFGHIJ"),
    ]);
    let result = sanitize_ok(&mut pipeline, "we BCDEFGHIJ");
    assert_eq!(result.entities.len(), 1, "{result:?}");
    assert_eq!(result.entities[0].kind, "api_key");
    assert_eq!(result.text, "w__DO_PRIVATE_REDACTED__");
}
