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

#[test]
fn empty_spans_fail_closed() {
    // An `start == end` span points at no text at all: a placeholder minted
    // for it would replace nothing while claiming a value was protected.
    let cases: [(&str, Entity); 4] = [
        ("alice@example.com", entity("email", 0, 0, "")),
        ("alice@example.com", entity("email", 8, 8, "")),
        ("alice@example.com", entity("email", 17, 17, "")),
        ("", entity("email", 0, 0, "")),
    ];
    for (input, empty) in cases {
        let mut pipeline = with_detector(vec![empty.clone()]);
        let error = sanitize_err(&mut pipeline, input);
        assert!(matches!(error, PipelineError::Detector(_)), "{error:?}");
        assert!(error.to_string().contains("is empty"), "{error}");
        assert!(!error.to_string().contains("__DO_PRIVATE_"), "{error}");
    }

    // Control: a non-empty span for the same kind still sanitizes.
    let mut pipeline = with_detector(vec![entity("email", 0, 17, "alice@example.com")]);
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    assert_eq!(result.entities.len(), 1, "{result:?}");
    assert!(
        result.text.starts_with("__DO_PRIVATE_EMAIL_1_"),
        "{result:?}"
    );
}

#[test]
fn inspect_rejects_invalid_detector_output() {
    // `inspect` discloses findings from the same detector contract `sanitize`
    // enforces; invalid output must not be summarized as if it were real.
    let cases: [(&str, &str, Entity); 8] = [
        ("empty span", "alice@example.com", entity("email", 0, 0, "")),
        (
            "reversed span",
            "alice@example.com",
            entity("email", 5, 2, "x"),
        ),
        (
            "out of bounds span",
            "alice@example.com",
            entity("email", 0, 18, "alice@example.com"),
        ),
        ("bad utf-8 boundary", "grüße", entity("person", 3, 7, "e")),
        (
            "value mismatch",
            "alice@example.com",
            entity("email", 0, 5, "bob@x"),
        ),
        (
            "empty kind",
            "alice@example.com",
            entity("  ", 0, 5, "alice"),
        ),
        (
            "confidence above 1",
            "alice@example.com",
            Entity {
                confidence: 1.5,
                ..entity("email", 0, 5, "alice")
            },
        ),
        (
            "nan confidence",
            "alice@example.com",
            Entity {
                confidence: f32::NAN,
                ..entity("email", 0, 5, "alice")
            },
        ),
    ];
    for (label, input, invalid) in cases {
        let pipeline = with_detector(vec![invalid]);
        match pipeline.inspect(input) {
            Ok(summaries) => panic!("{label} was accepted: {summaries:?}"),
            Err(error) => {
                assert!(
                    matches!(error, PipelineError::Detector(_)),
                    "{label}: {error:?}"
                );
            }
        }
    }

    // Control: valid output is still summarized.
    let pipeline = with_detector(vec![entity("email", 0, 17, "alice@example.com")]);
    let summaries = match pipeline.inspect("alice@example.com") {
        Ok(summaries) => summaries,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0].kind, "email");
}

#[test]
fn inspect_and_sanitize_resolve_the_same_overlap() {
    // Both entry points validate and resolve overlaps through the shared path,
    // so `inspect` must report the span `sanitize` actually transforms.
    let input = "we BCDEFGHIJ";
    let mut pipeline = with_detector(vec![
        entity("person", 0, 2, "we"),
        entity("api_key", 1, 12, "e BCDEFGHIJ"),
    ]);
    let summaries = match pipeline.inspect(input) {
        Ok(summaries) => summaries,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let sanitized = sanitize_ok(&mut pipeline, input);
    assert_eq!(
        summaries, sanitized.entities,
        "inspect and sanitize disagree"
    );
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0].kind, "api_key");
    assert_eq!(summaries[0].start, 1);
    assert_eq!(summaries[0].end, 12);
    assert_eq!(sanitized.text, "w__DO_PRIVATE_REDACTED__");
}
