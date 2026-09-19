//! Unit tests for the detector, moved out of `lib.rs` to stay under the LOC
//! ceiling (the `super` path still resolves to the crate root).

use super::*;
use std::path::PathBuf;

fn span(label: &str, start: usize, end: usize, score: f32) -> RawSpan {
    RawSpan {
        label: label.to_owned(),
        start,
        end,
        score,
    }
}

#[test]
fn default_labels_cover_42_pii_types() {
    assert_eq!(PII_LABELS_42.len(), 42);
    let config = Gliner2Config::default();
    assert_eq!(config.labels.len(), 42);
    assert!((config.threshold - DEFAULT_THRESHOLD).abs() < f32::EPSILON);
}

#[test]
fn canonical_kind_normalizes_labels() {
    assert_eq!(canonical_kind("email"), "email");
    assert_eq!(canonical_kind(" Phone Number "), "phone_number");
    assert_eq!(canonical_kind("PERSON"), "person");
}

#[test]
fn decode_applies_threshold_and_dedup() {
    let input = "alice@example.com";
    let spans = vec![
        span("email", 0, 17, 0.9),
        span("person", 0, 5, 0.8),
        span("email", 0, 17, 0.2),
    ];
    let entities = decode_spans(input, &spans, 0.5);
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "email");
    assert_eq!(entities[0].value, input);
}

#[test]
fn decode_rejects_non_char_boundaries() {
    let input = "grüße";
    let spans = vec![span("person", 1, 3, 0.9)];
    assert!(decode_spans(input, &spans, 0.0).is_empty());
}

#[test]
fn detect_without_model_dir_fails_closed() {
    let detector = Gliner2Detector::default();
    match detector.detect("alice@example.com") {
        Ok(_) => panic!("expected fail-closed error"),
        Err(error) => assert!(error.to_string().contains("model_dir")),
    }
}

#[test]
fn detect_with_missing_dir_fails_closed() {
    let config = Gliner2Config::with_model_dir(PathBuf::from("/nonexistent-gliner2-model-xyz"));
    let detector = Gliner2Detector::new(config);
    match detector.detect("alice@example.com") {
        Ok(_) => panic!("expected fail-closed error"),
        Err(error) => assert!(error.to_string().contains("does not exist")),
    }
}

/// Temp directory holding the named files (parent directories created).
fn temp_dir_with(names: &[&str]) -> tempfile::TempDir {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    for name in names {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            panic!("cannot create fixture directory {parent:?}: {error}");
        }
        if let Err(error) = std::fs::write(&path, b"") {
            panic!("cannot write fixture file {path:?}: {error}");
        }
    }
    dir
}

/// Detector pointed at a fixture directory.
fn detector_with(model_dir: &std::path::Path) -> Gliner2Detector {
    Gliner2Detector::new(Gliner2Config::with_model_dir(model_dir.to_path_buf()))
}

#[test]
fn fragment_export_matches_flat_and_legacy_layouts() {
    let flat = temp_dir_with(&["encoder_fp32.onnx", "tokenizer.json"]);
    assert!(fragment_export(flat.path()));
    let iobinding = temp_dir_with(&["encoder_fp16_iobinding.onnx"]);
    assert!(fragment_export(iobinding.path()));
    let legacy = temp_dir_with(&["fp32_v2/encoder_fp32.onnx"]);
    assert!(fragment_export(legacy.path()));
    let single_file = temp_dir_with(&["model.onnx", "tokenizer.json", "config.json"]);
    assert!(!fragment_export(single_file.path()));
    let empty = temp_dir_with(&[]);
    assert!(!fragment_export(empty.path()));
}

#[test]
fn boundary_export_requires_the_manifest() {
    let boundary = temp_dir_with(&["boundary_manifest.json", "encoder.onnx"]);
    assert!(boundary_export(boundary.path()));
    let fragments = temp_dir_with(&["encoder.onnx"]);
    assert!(!boundary_export(fragments.path()));
}

#[test]
fn detect_rejects_boundary_exports_with_a_specific_error() {
    let dir = temp_dir_with(&["boundary_manifest.json"]);
    let detector = detector_with(dir.path());
    match detector.detect("John Doe") {
        Ok(entities) => panic!("expected fail-closed error, got {entities:?}"),
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("boundary"), "{text}");
        }
    }
}

#[cfg(not(feature = "gliner2"))]
#[test]
fn fragment_export_without_feature_fails_closed() {
    let dir = temp_dir_with(&["encoder_fp32.onnx", "tokenizer.json"]);
    let detector = detector_with(dir.path());
    match detector.detect("John Doe") {
        Ok(entities) => panic!("expected fail-closed error, got {entities:?}"),
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("`gliner2` feature"), "{text}");
        }
    }
}

#[cfg(feature = "gliner2")]
#[test]
fn incomplete_fragment_export_fails_closed() {
    if std::env::var_os("ORT_DYLIB_PATH").is_none() {
        // The dynamic ONNX Runtime is only present in feature-build runs.
        return;
    }
    let dir = temp_dir_with(&["encoder_fp32.onnx"]);
    let detector = detector_with(dir.path());
    match detector.detect("John Doe") {
        Ok(entities) => panic!("expected fail-closed error, got {entities:?}"),
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("gliner2 fragment backend"), "{text}");
        }
    }
}
