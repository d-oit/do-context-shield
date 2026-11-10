use super::{Counts, Mode, Span, char_to_byte, load_corpus, score_spans};

#[test]
fn character_offsets_convert_to_utf8_byte_offsets() {
    let text = "Aé🙂Z";
    assert_eq!(char_to_byte(text, 0), Some(0));
    assert_eq!(char_to_byte(text, 1), Some(1));
    assert_eq!(char_to_byte(text, 2), Some(3));
    assert_eq!(char_to_byte(text, 3), Some(7));
    assert_eq!(char_to_byte(text, 4), Some(8));
    assert_eq!(char_to_byte(text, 5), None);
}

#[test]
fn span_scoring_requires_exact_kind_and_counts_duplicate_predictions() {
    let expected = vec![
        Span {
            kind: String::from("email"),
            start_byte: 1,
            end_byte: 6,
        },
        Span {
            kind: String::from("secret"),
            start_byte: 10,
            end_byte: 16,
        },
    ];
    let predicted = vec![
        expected[0].clone(),
        Span {
            kind: String::from("api_key"),
            start_byte: 10,
            end_byte: 16,
        },
        expected[0].clone(),
    ];
    let scored = score_spans(&expected, &predicted);
    assert_eq!(
        scored.counts,
        Counts {
            true_positives: 1,
            false_positives: 2,
            false_negatives: 1,
        }
    );
    assert_eq!(scored.per_kind["secret"].false_negatives, 1);
    assert_eq!(scored.per_kind["api_key"].false_positives, 1);
    assert_eq!(scored.false_positives.len(), 2);
    assert_eq!(scored.false_negatives.len(), 1);
}

#[test]
fn metrics_are_micro_averaged_and_undefined_empty_ratios_are_null() {
    let counts = Counts {
        true_positives: 2,
        false_positives: 1,
        false_negatives: 1,
    };
    let metrics = counts.metrics();
    assert_eq!(metrics.precision, Some(2.0 / 3.0));
    assert_eq!(metrics.recall, Some(2.0 / 3.0));
    assert_eq!(metrics.f1, Some(2.0 / 3.0));
    assert_eq!(Counts::default().metrics().precision, None);
    assert_eq!(Counts::default().metrics().recall, None);
    assert_eq!(Counts::default().metrics().f1, None);
}

#[test]
fn versioned_corpus_annotations_parse_and_match_unicode_scalar_spans() {
    let corpus = match load_corpus() {
        Ok(value) => value,
        Err(error) => panic!("invalid quality corpus: {error}"),
    };
    assert_eq!(corpus.revision, "dcs-detector-quality-v1");
    assert_eq!(corpus.license, "CC0-1.0");
    assert!(corpus.cases.iter().any(|case| {
        case.id == "email_german_unicode_context"
            && case.entities.iter().any(|entity| {
                entity.modes.contains(&Mode::Regex) && entity.surface == "qa.person@example.com"
            })
    }));
}

#[cfg(feature = "gliner2")]
#[test]
fn model_identity_hashes_local_metadata_without_exposing_the_path() {
    use super::{Mode, ModelSetup, model_identity, sha256};

    let directory = match tempfile::tempdir() {
        Ok(value) => value,
        Err(error) => panic!("temporary model directory creation failed: {error}"),
    };
    let tokenizer_bytes = b"synthetic tokenizer metadata";
    let config_bytes = b"{\"model_type\":\"synthetic\"}";
    if let Err(error) = std::fs::write(directory.path().join("tokenizer.json"), tokenizer_bytes) {
        panic!("synthetic tokenizer metadata write failed: {error}");
    }
    if let Err(error) = std::fs::write(directory.path().join("config.json"), config_bytes) {
        panic!("synthetic model config write failed: {error}");
    }
    let setup = ModelSetup {
        model_dir: directory.path().to_path_buf(),
        version: String::from("synthetic-model@v1"),
    };
    let identity = match model_identity(Mode::Gliner2, &setup) {
        Ok(value) => value,
        Err(error) => panic!("synthetic model identity creation failed: {error}"),
    };
    assert_eq!(
        identity.tokenizer_sha256.as_deref(),
        Some(sha256(tokenizer_bytes).as_str())
    );
    assert_eq!(
        identity.model_config_sha256.as_deref(),
        Some(sha256(config_bytes).as_str())
    );
    assert_eq!(identity.model_config_source.as_deref(), Some("config.json"));
    assert!(identity.runtime_config_sha256.is_some());
    let serialized = match serde_json::to_string(&identity) {
        Ok(value) => value,
        Err(error) => panic!("synthetic model identity serialization failed: {error}"),
    };
    let local_path = directory.path().to_string_lossy().into_owned();
    assert!(!serialized.contains(&local_path));
}

#[cfg(feature = "gliner2")]
#[test]
fn model_identity_uses_backend_selected_tokenizer_for_dual_layout_exports() {
    use super::model_support::model_identity_with_backend_config;
    use super::{Mode, ModelSetup, model_identity, sha256};
    use gliner2_rs::{Precision, SpanConfig};

    let directory = match tempfile::tempdir() {
        Ok(value) => value,
        Err(error) => panic!("temporary model directory creation failed: {error}"),
    };
    write_model_fixture_file(
        directory.path(),
        "fp32_v2/encoder_fp32.onnx",
        b"fp32 encoder",
    );
    write_model_fixture_file(
        directory.path(),
        "fp16_v2/encoder_fp16.onnx",
        b"fp16 encoder",
    );
    write_model_fixture_file(
        directory.path(),
        "fp16_v2/encoder_fp16_iobinding.onnx",
        b"fp16 iobinding encoder",
    );
    write_model_fixture_file(
        directory.path(),
        "fp32_v2/tokenizer.json",
        b"fp32 tokenizer metadata",
    );
    write_model_fixture_file(
        directory.path(),
        "fp16_v2/tokenizer.json",
        b"fp16 tokenizer metadata",
    );
    write_model_fixture_file(
        directory.path(),
        "fp32_v2/config.json",
        b"fp32 model config",
    );
    write_model_fixture_file(
        directory.path(),
        "fp16_v2/config.json",
        b"fp16 model config",
    );
    let setup = ModelSetup {
        model_dir: directory.path().to_path_buf(),
        version: String::from("synthetic-dual-layout@v1"),
    };
    let backend_config = SpanConfig::new(setup.model_dir.clone()).with_intra_threads(1);
    let Some(expected_tokenizer_path) = gliner2_rs::runtime::resolve_tokenizer(
        &backend_config.models_dir,
        backend_config.precision,
    ) else {
        panic!("synthetic backend tokenizer resolution failed");
    };
    let expected_tokenizer = match std::fs::read(expected_tokenizer_path) {
        Ok(value) => value,
        Err(error) => panic!("selected synthetic tokenizer read failed: {error}"),
    };
    let identity = match model_identity(Mode::Gliner2, &setup) {
        Ok(value) => value,
        Err(error) => panic!("synthetic model identity creation failed: {error}"),
    };
    let resolved_identity =
        match model_identity_with_backend_config(Mode::Gliner2, &setup, &backend_config) {
            Ok(value) => value,
            Err(error) => panic!("resolved synthetic model identity creation failed: {error}"),
        };
    let alternate_precision = match backend_config.precision {
        Precision::Fp32 => Precision::Fp16,
        Precision::Fp16 | Precision::Fp16IoBinding => Precision::Fp32,
    };
    let alternate_config = SpanConfig::new(setup.model_dir.clone())
        .with_precision(alternate_precision)
        .with_intra_threads(1);
    let alternate_identity =
        match model_identity_with_backend_config(Mode::Gliner2, &setup, &alternate_config) {
            Ok(value) => value,
            Err(error) => panic!("alternate synthetic model identity creation failed: {error}"),
        };

    assert_eq!(identity, resolved_identity);
    assert_eq!(
        identity.model_config_source.as_deref(),
        Some("built_in_defaults")
    );
    assert_ne!(
        identity.runtime_config_sha256,
        alternate_identity.runtime_config_sha256
    );
    assert_ne!(
        identity.model_config_sha256,
        alternate_identity.model_config_sha256
    );

    assert_eq!(
        identity.tokenizer_sha256.as_deref(),
        Some(sha256(&expected_tokenizer).as_str())
    );
}

#[cfg(feature = "gliner2")]
fn write_model_fixture_file(root: &std::path::Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("synthetic model directory creation failed: {error}");
    }
    if let Err(error) = std::fs::write(path, bytes) {
        panic!("synthetic model fixture write failed: {error}");
    }
}
