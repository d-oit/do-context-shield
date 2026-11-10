//! Reproducible detector-quality reports over the synthetic versioned corpus.
#[path = "detection_quality/support.rs"]
mod support;

use do_context_shield_detector_regex::RegexDetector;
use support::{Mode, evaluate, load_corpus, print_report, regex_identity};

#[test]
fn regex_corpus_report_is_deterministic_and_gates_regressions() {
    let corpus = match load_corpus() {
        Ok(value) => value,
        Err(error) => panic!("invalid quality corpus: {error}"),
    };
    let detector = RegexDetector;
    let identity = regex_identity();
    let report = match evaluate(&detector, Mode::Regex, &corpus, identity) {
        Ok(value) => value,
        Err(error) => panic!("regex quality evaluation failed: {error}"),
    };
    let repeated = match evaluate(&detector, Mode::Regex, &corpus, regex_identity()) {
        Ok(value) => value,
        Err(error) => panic!("repeated regex quality evaluation failed: {error}"),
    };
    print_report(&report);
    assert_eq!(
        report, repeated,
        "same detector and corpus must be deterministic"
    );
    assert!(
        report.deterministic_gate_failures.is_empty(),
        "regex quality gate failed for cases: {:?}",
        report.deterministic_gate_failures
    );
    assert!(report.false_negatives.iter().any(|finding| {
        finding.case_id == "credential_glued_only_known_gap"
            && finding.manual_review_priority.as_deref() == Some("credential")
    }));
    let serialized = match serde_json::to_string(&report) {
        Ok(value) => value,
        Err(error) => panic!("quality report serialization failed: {error}"),
    };
    let value: serde_json::Value = match serde_json::from_str(&serialized) {
        Ok(value) => value,
        Err(error) => panic!("quality report JSON parsing failed: {error}"),
    };
    for case in &corpus.cases {
        assert!(
            !report_contains_string(&value, &case.text),
            "report leaked text from case {}",
            case.id
        );
        for entity in &case.entities {
            assert!(
                !report_contains_string(&value, &entity.surface),
                "report leaked an annotated surface from case {}",
                case.id
            );
        }
    }
    for field in ["text", "surface", "value"] {
        assert!(
            !report_contains_key(&value, field),
            "quality report must not contain a `{field}` field"
        );
    }
}

fn report_contains_string(value: &serde_json::Value, sought: &str) -> bool {
    match value {
        serde_json::Value::String(value) => value == sought,
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| report_contains_string(value, sought)),
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| report_contains_string(value, sought)),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            false
        }
    }
}

fn report_contains_key(value: &serde_json::Value, sought: &str) -> bool {
    match value {
        serde_json::Value::Object(values) => values
            .iter()
            .any(|(key, value)| key == sought || report_contains_key(value, sought)),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| report_contains_key(value, sought)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => false,
    }
}

#[cfg(feature = "gliner2")]
#[test]
fn local_model_reports_run_only_when_explicitly_configured() {
    use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
    use do_context_shield_detector_hybrid::HybridDetector;
    use support::{model_identity, optional_model_setup};

    let setup = match optional_model_setup() {
        Ok(Some(value)) => value,
        Ok(None) => {
            eprintln!(
                "model quality evaluation skipped; set DO_CONTEXT_SHIELD_QUALITY_MODEL_DIR, \
                 DO_CONTEXT_SHIELD_QUALITY_MODEL_VERSION, and ORT_DYLIB_PATH to use a local model"
            );
            return;
        }
        Err(error) => panic!("invalid local model quality setup: {error}"),
    };
    let corpus = match load_corpus() {
        Ok(value) => value,
        Err(error) => panic!("invalid quality corpus: {error}"),
    };
    let config = Gliner2Config::with_model_dir(setup.model_dir.clone())
        .with_limits(do_context_shield_detector_gliner2::DEFAULT_MAX_TOKENS, 1);
    let gliner = Gliner2Detector::new(config);
    let gliner_identity = match model_identity(Mode::Gliner2, &setup) {
        Ok(value) => value,
        Err(error) => panic!("cannot identify local model: {error}"),
    };
    let gliner_report = match evaluate(&gliner, Mode::Gliner2, &corpus, gliner_identity.clone()) {
        Ok(value) => value,
        Err(error) => panic!("GLiNER2 quality evaluation failed: {error}"),
    };
    let gliner_repeat = match evaluate(&gliner, Mode::Gliner2, &corpus, gliner_identity) {
        Ok(value) => value,
        Err(error) => panic!("repeated GLiNER2 quality evaluation failed: {error}"),
    };
    assert_eq!(
        gliner_report, gliner_repeat,
        "GLiNER2 evaluation must be deterministic"
    );
    print_report(&gliner_report);

    let hybrid = HybridDetector::new(Box::new(RegexDetector), Box::new(gliner));
    let hybrid_identity = match model_identity(Mode::Hybrid, &setup) {
        Ok(value) => value,
        Err(error) => panic!("cannot identify local model: {error}"),
    };
    let hybrid_report = match evaluate(&hybrid, Mode::Hybrid, &corpus, hybrid_identity.clone()) {
        Ok(value) => value,
        Err(error) => panic!("hybrid quality evaluation failed: {error}"),
    };
    let hybrid_repeat = match evaluate(&hybrid, Mode::Hybrid, &corpus, hybrid_identity) {
        Ok(value) => value,
        Err(error) => panic!("repeated hybrid quality evaluation failed: {error}"),
    };
    assert_eq!(
        hybrid_report, hybrid_repeat,
        "hybrid evaluation must be deterministic"
    );
    print_report(&hybrid_report);
}

#[cfg(not(feature = "gliner2"))]
#[test]
fn model_quality_requires_opt_in_feature() {
    assert!(
        std::env::var_os("DO_CONTEXT_SHIELD_QUALITY_MODEL_DIR").is_none(),
        "model evaluation needs `--features gliner2`; it never downloads a model"
    );
}
