//! ONNX backend tests: decoding, label validation, and bounded windows.

use super::{bio_decode, probe};
use crate::load_id2label;

/// `config.json` with `contents`, or no file at all, inside a fresh
/// temporary directory.
fn config_dir(contents: Option<&str>) -> tempfile::TempDir {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    if let Some(contents) = contents {
        let path = dir.path().join("config.json");
        if let Err(error) = std::fs::write(&path, contents) {
            panic!("cannot write {}: {error}", path.display());
        }
    }
    dir
}

/// Unwrap a decode result in a test.
fn decoded(
    seq_len: usize,
    num_labels: usize,
    logits: &[f32],
    offsets: &[(usize, usize)],
    labels: &[String],
) -> Vec<(String, usize, usize)> {
    match bio_decode(seq_len, num_labels, logits, offsets, labels) {
        Ok(spans) => spans
            .into_iter()
            .map(|span| (span.label, span.start, span.end))
            .collect(),
        Err(error) => panic!("unexpected decode error: {error}"),
    }
}

#[test]
fn id2label_is_ordered_by_class_index() {
    let dir = config_dir(Some(
        r#"{"id2label":{"2":"B-city","0":"B-name","1":"I-name"}}"#,
    ));
    let labels = match load_id2label(&dir.path().join("config.json")) {
        Ok(labels) => labels,
        Err(error) => panic!("expected labels, got error: {error}"),
    };
    assert_eq!(labels, ["B-name", "I-name", "B-city"]);
}

#[test]
fn unusable_id2label_fails_closed() {
    // Decoding without tag names maps every token to `O`, so a
    // misconfigured export would look like a clean scan.
    for contents in [
        r#"{"model_type":"bert"}"#,
        r#"{"id2label":{"name":"B-name"}}"#,
        r#"{"id2label":["B-name","O"]}"#,
        r#"{"id2label":{"0":7}}"#,
    ] {
        let dir = config_dir(Some(contents));
        let error = match load_id2label(&dir.path().join("config.json")) {
            Ok(labels) => panic!("expected an error for {contents}, got {labels:?}"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("no usable `id2label`"), "got: {error}");
    }
}

#[test]
fn missing_config_json_fails_closed() {
    let dir = config_dir(None);
    let error = match load_id2label(&dir.path().join("config.json")) {
        Ok(labels) => panic!("expected an error, got {labels:?}"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("config.json not found in model_dir"),
        "got: {error}"
    );
}

#[test]
fn invalid_config_json_fails_closed() {
    let dir = config_dir(Some("not json"));
    let error = match load_id2label(&dir.path().join("config.json")) {
        Ok(labels) => panic!("expected an error, got {labels:?}"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("not valid JSON"), "got: {error}");
}

#[test]
fn decoding_without_tag_names_fails_closed() {
    // The trap `load_id2label` exists for: without tag names every token
    // would map to `O` and a misconfigured export would look like a clean
    // scan. Decoding refuses the mismatch instead.
    let offsets = [(0, 0), (0, 4), (0, 0)];
    #[rustfmt::skip]
        let logits = [
            0.0, 9.0,
            9.0, 0.0,
            0.0, 9.0,
        ];
    match bio_decode(offsets.len(), 2, &logits, &offsets, &[]) {
        Ok(spans) => panic!("expected a label error, got {spans:?}"),
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("id2label"), "{text}");
        }
    }
}

fn labels() -> Vec<String> {
    ["B-name", "I-name", "B-city", "I-city", "O"]
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn spans(logits: &[f32], offsets: &[(usize, usize)]) -> Vec<(String, usize, usize)> {
    decoded(offsets.len(), 5, logits, offsets, &labels())
}

#[test]
fn closes_span_open_at_last_text_token_when_special_row_follows() {
    // [CLS](0,0) "John"(0,4) [SEP](0,0): the trailing special row is
    // skipped, so the open B-name span must close at end of input.
    let offsets = [(0, 0), (0, 4), (0, 0)];
    #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 9.0,
        ];
    assert_eq!(spans(&logits, &offsets), vec![("name".to_owned(), 0, 4)]);
}

#[test]
fn special_and_o_rows_close_spans_without_shifting_alignment() {
    // [CLS](0,0) "John"(0,4) " Doe"(4,8) " "(8,9): a different kind closes
    // the first span and opens the second on the right offsets.
    let offsets = [(0, 0), (0, 4), (4, 8), (8, 9)];
    #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 9.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 9.0,
        ];
    assert_eq!(
        spans(&logits, &offsets),
        vec![("name".to_owned(), 0, 4), ("city".to_owned(), 4, 8)]
    );
}

#[test]
fn merges_adjacent_tags_of_the_same_kind() {
    // Word-level exports repeat `B-` for every subtoken; fragments of one
    // entity must decode to a single span.
    let offsets = [(0, 0), (0, 4), (4, 8), (8, 12)];
    #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 9.0, 0.0, 0.0, 0.0,
        ];
    assert_eq!(spans(&logits, &offsets), vec![("name".to_owned(), 0, 12)]);
}

#[test]
fn kind_change_on_i_tag_closes_the_open_span() {
    // B-name then I-city must emit the name span and start the city span;
    // dropping the open span would silently lose a detected entity.
    let offsets = [(0, 0), (0, 4), (4, 8)];
    #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 9.0, 0.0,
        ];
    assert_eq!(
        spans(&logits, &offsets),
        vec![("name".to_owned(), 0, 4), ("city".to_owned(), 4, 8)]
    );
}

#[test]
fn non_finite_logits_are_rejected_not_mapped_to_a_score() {
    let offsets = [(0, 4)];
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        // Both class rows non-finite: whichever the argmax picks is
        // rejected instead of turned into a confidence.
        let logits = [bad, bad];
        match bio_decode(1, 2, &logits, &offsets, &labels()) {
            Ok(spans) => panic!("expected a non-finite error, got {spans:?}"),
            Err(error) => {
                let text = error.to_string();
                assert!(text.contains("non-finite"), "{text}");
            }
        }
    }
}

#[test]
fn short_logits_and_unknown_labels_fail_closed() {
    let offsets = [(0, 4)];
    match bio_decode(1, 5, &[9.0], &offsets, &labels()) {
        Ok(spans) => panic!("expected a shape error, got {spans:?}"),
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("shorter"), "{text}");
        }
    }
    // Rows point past the label list: decoding must not invent a kind.
    let logits = [0.0, 0.0, 0.0, 0.0, 9.0];
    let short_labels = vec!["B-name".to_owned(), "I-name".to_owned()];
    match bio_decode(1, 5, &logits, &offsets, &short_labels) {
        Ok(spans) => panic!("expected a label error, got {spans:?}"),
        Err(error) => {
            let text = error.to_string();
            assert!(
                text.contains("logits shorter") || text.contains("id2label"),
                "{text}"
            );
        }
    }
}

#[test]
fn probe_without_runtime_reports_a_scrubbed_error() {
    // No model files: the probe fails before touching ORT, and the message
    // must never carry a path or file contents.
    let dir = config_dir(Some(r#"{"id2label":{"0":"O"}}"#));
    let error = match probe(dir.path(), 1) {
        Ok(()) => panic!("expected a probe failure"),
        Err(error) => error.to_string(),
    };
    assert!(!error.contains("config.json"), "{error}");
    assert!(!error.contains("id2label"), "{error}");
}
