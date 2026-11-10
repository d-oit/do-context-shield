use super::{DetectorIdentity, Mode, REGEX_PATTERNS, invalid_data, sha256};
use gliner2_rs::{ExecutionMode, Precision, SpanConfig};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};

pub struct ModelSetup {
    pub model_dir: PathBuf,
    pub version: String,
}

/// Build a reproducible model/config identity from an explicitly supplied local export.
///
/// Fragment tokenizer and runtime settings follow the same resolved backend
/// configuration used for inference; local paths are never included in the report.
///
/// # Errors
/// Returns an error if the selected tokenizer or configuration metadata is missing or unreadable.
pub fn model_identity(mode: Mode, setup: &ModelSetup) -> Result<DetectorIdentity, Box<dyn Error>> {
    let backend_config = SpanConfig::new(setup.model_dir.clone()).with_intra_threads(1);
    model_identity_with_backend_config(mode, setup, &backend_config)
}

/// Build an identity from a backend configuration already resolved for inference.
///
/// # Errors
/// Returns an error if the selected tokenizer or configuration metadata is missing or unreadable.
pub(super) fn model_identity_with_backend_config(
    mode: Mode,
    setup: &ModelSetup,
    backend_config: &SpanConfig,
) -> Result<DetectorIdentity, Box<dyn Error>> {
    let model_dir = &backend_config.models_dir;
    let fragment_export = has_fragment_encoder(model_dir);
    let tokenizer_path = if fragment_export {
        gliner2_rs::runtime::resolve_tokenizer(model_dir, backend_config.precision)
    } else {
        let candidate = model_dir.join("tokenizer.json");
        candidate.is_file().then_some(candidate)
    };
    let tokenizer_path =
        tokenizer_path.ok_or_else(|| invalid_data("local model has no tokenizer.json"))?;
    let tokenizer_sha256 = sha256_file(&tokenizer_path)?;
    let backend_selection = if fragment_export {
        serde_json::json!({
            "precision": precision_name(backend_config.precision),
            "execution": execution_name(backend_config.execution)
        })
    } else {
        serde_json::Value::Null
    };
    let runtime_config = serde_json::to_vec(&serde_json::json!({
        "backend": if fragment_export { "gliner2_fragments" } else { "single_file" },
        "labels": do_context_shield_detector_gliner2::PII_LABELS_42.as_slice(),
        "threshold": do_context_shield_detector_gliner2::DEFAULT_THRESHOLD,
        "max_tokens": do_context_shield_detector_gliner2::DEFAULT_MAX_TOKENS,
        "intra_threads": backend_config.intra_threads,
        "backend_selection": backend_selection
    }))?;
    let config_path = if fragment_export {
        None
    } else {
        let path = model_dir.join("config.json");
        path.is_file().then_some(path)
    };
    let (model_config_sha256, model_config_source) = if let Some(path) = config_path {
        (sha256_file(&path)?, String::from("config.json"))
    } else {
        (sha256(&runtime_config), String::from("built_in_defaults"))
    };
    Ok(DetectorIdentity {
        mode,
        detector_version: env!("CARGO_PKG_VERSION").to_owned(),
        model_version: Some(setup.version.clone()),
        tokenizer_sha256: Some(tokenizer_sha256),
        model_config_sha256: Some(model_config_sha256),
        model_config_source: Some(model_config_source),
        runtime_config_sha256: Some(sha256(&runtime_config)),
        regex_patterns_sha256: matches!(mode, Mode::Hybrid)
            .then(|| sha256(REGEX_PATTERNS.as_bytes())),
    })
}

/// Read the opt-in local model configuration; never downloads or discovers a model.
///
/// # Errors
/// Returns an error for a partial or invalid setup, or when the model version is not supplied.
pub fn optional_model_setup() -> Result<Option<ModelSetup>, Box<dyn Error>> {
    let Some(model_dir) = std::env::var_os("DO_CONTEXT_SHIELD_QUALITY_MODEL_DIR") else {
        return Ok(None);
    };
    let model_dir = PathBuf::from(model_dir);
    if !model_dir.is_absolute() || !model_dir.is_dir() {
        return Err(
            invalid_data("quality model directory must be an existing absolute path").into(),
        );
    }
    let ort_path = std::env::var_os("ORT_DYLIB_PATH")
        .ok_or_else(|| invalid_data("model evaluation requires ORT_DYLIB_PATH"))?;
    if !Path::new(&ort_path).is_file() {
        return Err(invalid_data("ORT_DYLIB_PATH must name a local runtime library").into());
    }
    let version = std::env::var("DO_CONTEXT_SHIELD_QUALITY_MODEL_VERSION").map_err(|_| {
        invalid_data("model evaluation requires DO_CONTEXT_SHIELD_QUALITY_MODEL_VERSION")
    })?;
    if version.trim().is_empty() {
        return Err(invalid_data("model version must not be empty").into());
    }
    Ok(Some(ModelSetup { model_dir, version }))
}

fn has_fragment_encoder(model_dir: &Path) -> bool {
    [Precision::Fp32, Precision::Fp16, Precision::Fp16IoBinding]
        .into_iter()
        .any(|precision| {
            gliner2_rs::runtime::resolve_fragment(model_dir, "encoder", precision).is_some()
        })
}

const fn precision_name(precision: Precision) -> &'static str {
    match precision {
        Precision::Fp32 => "fp32",
        Precision::Fp16 => "fp16",
        Precision::Fp16IoBinding => "fp16_iobinding",
    }
}

const fn execution_name(execution: ExecutionMode) -> &'static str {
    match execution {
        ExecutionMode::Standard => "standard",
        ExecutionMode::IoBinding => "iobinding",
        ExecutionMode::Auto => "auto",
    }
}

/// Hash one local model metadata file.
///
/// # Errors
/// Returns an error if the file cannot be read.
fn sha256_file(path: &Path) -> Result<String, io::Error> {
    let bytes = std::fs::read(path).map_err(|_| invalid_data("cannot read model metadata file"))?;
    Ok(sha256(&bytes))
}
