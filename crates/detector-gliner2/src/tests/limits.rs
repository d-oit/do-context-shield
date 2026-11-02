//! Inference-limit, windowing, and readiness tests.

use super::temp_dir_with;
use crate::{
    DEFAULT_INTRA_THREADS, DEFAULT_MAX_TOKENS, Gliner2Config, MIN_MAX_TOKENS, ModelLayout,
    ReadinessCode, byte_windows, logits_shape_matches, probe, token_windows,
};
#[cfg(feature = "gliner2")]
use crate::{Gliner2Detector, onnx};
#[cfg(feature = "gliner2")]
use do_context_shield_plugin_api::Detector;
use std::path::PathBuf;

#[test]
fn limits_default_to_conservative_values_and_clamp_floor() {
    let config = Gliner2Config::default();
    assert_eq!(config.max_tokens, DEFAULT_MAX_TOKENS);
    assert_eq!(config.intra_threads, DEFAULT_INTRA_THREADS);
    let clamped = config.with_limits(0, 0);
    assert_eq!(clamped.max_tokens, MIN_MAX_TOKENS);
    assert_eq!(clamped.intra_threads, 1);
    let raised = Gliner2Config::default().with_limits(1024, 3);
    assert_eq!(raised.max_tokens, 1024);
    assert_eq!(raised.intra_threads, 3);
}

#[test]
fn byte_windows_cover_the_input_with_bounded_overlapping_ranges() {
    let input = "é".repeat(5_000);
    let windows = byte_windows(&input, 1_000, 125);
    assert!(windows.len() > 1);
    assert_eq!(windows[0].0, 0);
    assert_eq!(windows[windows.len() - 1].1, input.len());
    for &(start, end) in &windows {
        assert!(end > start, "{windows:?}");
        assert!(end - start <= 1_000, "window too wide: {start}..{end}");
        assert!(input.is_char_boundary(start), "bad start {start}");
        assert!(input.is_char_boundary(end), "bad end {end}");
    }
    for pair in windows.windows(2) {
        assert!(pair[0].1 > pair[1].0, "windows do not overlap: {pair:?}");
        assert!(
            pair[1].0 < pair[0].1 + 1_000,
            "window skipped input: {pair:?}"
        );
    }
    // Any entity of up to `overlap` bytes is fully inside at least one window.
    let overlap = 125;
    let mut start = 0;
    while start + overlap < input.len() {
        assert!(
            windows
                .iter()
                .any(|&(w_start, w_end)| w_start <= start && start + overlap <= w_end),
            "no window covers {start}..{}",
            start + overlap
        );
        start += 97;
    }
}

#[test]
fn token_windows_bound_inference_and_preserve_boundary_spans() {
    let windows = token_windows(10_000, 512, 64);
    assert!(windows.len() < 30, "too many windows: {}", windows.len());
    assert_eq!(windows[0], (0, 512));
    assert_eq!(windows[windows.len() - 1].1, 10_000);
    for &(start, end) in &windows {
        assert!(end - start <= 512, "{start}..{end}");
        assert!(end > start);
    }
    for pair in windows.windows(2) {
        assert!(pair[0].1 > pair[1].0, "windows do not overlap: {pair:?}");
    }
    // A span of up to the overlap length cannot fall between windows.
    for start in (0..9_000).step_by(37) {
        let span_end = (start + 64).min(10_000);
        assert!(
            windows
                .iter()
                .any(|&(w_start, w_end)| w_start <= start && span_end <= w_end),
            "no window covers {start}..{span_end}"
        );
    }
    assert!(token_windows(0, 512, 64).is_empty());
}

#[test]
fn logits_shape_accepts_only_expected_ranks_and_transposes() {
    assert!(logits_shape_matches(&[1, 8, 5], 8, 5));
    assert!(logits_shape_matches(&[8, 5], 8, 5));
    // A transposed tensor would decode class rows as token rows.
    assert!(!logits_shape_matches(&[5, 8], 8, 5));
    assert!(!logits_shape_matches(&[2, 8, 5], 8, 5));
    assert!(!logits_shape_matches(&[1, 8, 4], 8, 5));
    assert!(!logits_shape_matches(&[1, 8], 8, 5));
}

#[test]
fn readiness_reports_stable_categories() {
    let unconfigured = probe(&Gliner2Config::default());
    assert_eq!(unconfigured.code, ReadinessCode::NotConfigured);
    assert!(!unconfigured.available);
    assert_eq!(unconfigured.max_tokens, DEFAULT_MAX_TOKENS);

    let missing_dir = probe(&Gliner2Config::with_model_dir(PathBuf::from(
        "/nonexistent-gliner2-readiness",
    )));
    assert_eq!(missing_dir.code, ReadinessCode::MissingModelDir);

    let no_labels = probe(&Gliner2Config {
        labels: Vec::new(),
        ..Gliner2Config::with_model_dir(PathBuf::from("/nonexistent"))
    });
    assert_eq!(no_labels.code, ReadinessCode::MissingLabels);

    let boundary = temp_dir_with(&["boundary_manifest.json", "encoder.onnx"]);
    assert_eq!(
        probe(&Gliner2Config::with_model_dir(
            boundary.path().to_path_buf()
        ))
        .code,
        ReadinessCode::UnsupportedExport
    );

    let incomplete = temp_dir_with(&["encoder.onnx", "span_rep.onnx"]);
    let report = probe(&Gliner2Config::with_model_dir(
        incomplete.path().to_path_buf(),
    ));
    assert_eq!(report.code, ReadinessCode::IncompleteFragments);
    assert_eq!(report.layout, Some(ModelLayout::Fragments));

    let missing_model = temp_dir_with(&["tokenizer.json", "config.json"]);
    assert_eq!(
        probe(&Gliner2Config::with_model_dir(
            missing_model.path().to_path_buf()
        ))
        .code,
        ReadinessCode::MissingModelFile
    );

    let missing_tokenizer = temp_dir_with(&["model.onnx", "config.json"]);
    let report = probe(&Gliner2Config::with_model_dir(
        missing_tokenizer.path().to_path_buf(),
    ));
    assert_eq!(report.code, ReadinessCode::MissingTokenizer);
    assert_eq!(report.layout, Some(ModelLayout::SingleFile));

    let missing_labels = temp_dir_with(&["model.onnx", "tokenizer.json", "config.json"]);
    assert_eq!(
        probe(&Gliner2Config::with_model_dir(
            missing_labels.path().to_path_buf()
        ))
        .code,
        ReadinessCode::MissingLabels
    );
}

#[cfg(not(feature = "gliner2"))]
#[test]
fn readiness_reports_feature_disabled_for_a_complete_export() {
    let single = temp_dir_with(&["model.onnx", "tokenizer.json", "config.json"]);
    if let Err(error) = std::fs::write(
        single.path().join("config.json"),
        r#"{"id2label":{"0":"B-name","1":"O"}}"#,
    ) {
        panic!("cannot write config.json: {error}");
    }
    let report = probe(&Gliner2Config::with_model_dir(single.path().to_path_buf()));
    assert_eq!(report.code, ReadinessCode::FeatureDisabled);
    assert_eq!(report.layout, Some(ModelLayout::SingleFile));
}

#[cfg(feature = "gliner2")]
#[test]
fn readiness_reports_runtime_unavailable_for_a_broken_export() {
    // Complete file set with unusable contents: the probe must actually try to
    // load the backend and report a runtime failure, never `Ready`.
    let dir = temp_dir_with(&["model.onnx", "tokenizer.json", "config.json"]);
    if let Err(error) = std::fs::write(
        dir.path().join("config.json"),
        r#"{"id2label":{"0":"B-name","1":"O"}}"#,
    ) {
        panic!("cannot write config.json: {error}");
    }
    let report = probe(&Gliner2Config::with_model_dir(dir.path().to_path_buf()));
    assert_eq!(report.code, ReadinessCode::RuntimeUnavailable);
    assert!(!report.available);
}

/// The configured runtime and model directory, or `None` when the
/// model-backed tests should skip. Mirrors the CLI test helper: half a
/// configuration is a failure, not a skip.
#[cfg(feature = "gliner2")]
fn model_env() -> Option<PathBuf> {
    let ort = std::env::var_os("ORT_DYLIB_PATH");
    let model = std::env::var_os("DO_CONTEXT_SHIELD_E2E_MODEL_DIR");
    assert!(
        !(ort.is_none() && model.is_some()),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR is set but ORT_DYLIB_PATH is not; provide both or neither"
    );
    let required = std::env::var("DO_HARNESS_REQUIRE_ORT").is_ok_and(|value| value == "1");
    let Some(_ort) = ort else {
        assert!(
            !required,
            "DO_HARNESS_REQUIRE_ORT=1 but ORT_DYLIB_PATH is unset; CI must provision the pinned ONNX Runtime"
        );
        eprintln!(
            "skip: set ORT_DYLIB_PATH and DO_CONTEXT_SHIELD_E2E_MODEL_DIR to run the model-backed reasoning tests"
        );
        return None;
    };
    let Some(model) = model else {
        eprintln!(
            "skip: set DO_CONTEXT_SHIELD_E2E_MODEL_DIR to a local export to run the model-backed reasoning tests"
        );
        return None;
    };
    Some(PathBuf::from(model))
}

#[cfg(feature = "gliner2")]
#[test]
fn repeated_detections_reuse_the_loaded_engine() {
    let Some(model) = model_env() else {
        return;
    };
    let detector = Gliner2Detector::new(
        Gliner2Config::with_model_dir(model).with_limits(DEFAULT_MAX_TOKENS, 1),
    );
    let before = onnx::ENGINE_LOADS.load(std::sync::atomic::Ordering::SeqCst);
    let first = match detector.detect("Email Alice at alice@example.com") {
        Ok(entities) => entities,
        Err(error) => panic!("unexpected detection error: {error}"),
    };
    let second = match detector.detect("Email Alice at alice@example.com") {
        Ok(entities) => entities,
        Err(error) => panic!("unexpected detection error: {error}"),
    };
    let after = onnx::ENGINE_LOADS.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(after - before, 1, "the export was loaded more than once");
    assert_eq!(first, second, "repeated detection changed its result");
}

#[cfg(feature = "gliner2")]
#[test]
fn long_input_is_scanned_in_bounded_windows() {
    let Some(model) = model_env() else {
        return;
    };
    // A long input forces several byte/token windows; the call must complete
    // (an unevaluable window would fail closed instead).
    let detector = Gliner2Detector::new(Gliner2Config::with_model_dir(model).with_limits(128, 1));
    let input = "Alice alice@example.com ".repeat(400);
    match detector.detect(&input) {
        Ok(entities) => {
            for entity in entities {
                assert!(entity.end <= input.len());
                assert!(entity.start < entity.end);
            }
        }
        Err(error) => panic!("unexpected detection error: {error}"),
    }
}
