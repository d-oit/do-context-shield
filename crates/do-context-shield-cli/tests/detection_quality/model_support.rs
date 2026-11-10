use super::{DetectorIdentity, Mode, REGEX_PATTERNS, invalid_data, sha256};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};

pub struct ModelSetup {
    pub model_dir: PathBuf,
    pub version: String,
}

/// Build a reproducible model/config identity from an explicitly supplied local export.
///
/// # Errors
/// Returns an error if the local tokenizer or configuration metadata is missing or unreadable.
pub fn model_identity(mode: Mode, setup: &ModelSetup) -> Result<DetectorIdentity, Box<dyn Error>> {
    let tokenizer_path = find_metadata_file(&setup.model_dir, "tokenizer.json")
        .ok_or_else(|| invalid_data("local model has no tokenizer.json"))?;
    let tokenizer_sha256 = sha256_file(&tokenizer_path)?;
    let runtime_config = serde_json::to_vec(&serde_json::json!({
        "labels": do_context_shield_detector_gliner2::PII_LABELS_42.as_slice(),
        "threshold": do_context_shield_detector_gliner2::DEFAULT_THRESHOLD,
        "max_tokens": do_context_shield_detector_gliner2::DEFAULT_MAX_TOKENS,
        "intra_threads": 1
    }))?;
    let config_path = find_metadata_file(&setup.model_dir, "config.json");
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

fn find_metadata_file(model_dir: &Path, name: &str) -> Option<PathBuf> {
    for subdir in ["", "fp32_v2", "fp16_v2"] {
        let directory = if subdir.is_empty() {
            model_dir.to_path_buf()
        } else {
            model_dir.join(subdir)
        };
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Hash one local model metadata file.
///
/// # Errors
/// Returns an error if the file cannot be read.
fn sha256_file(path: &Path) -> Result<String, io::Error> {
    let bytes = std::fs::read(path).map_err(|_| invalid_data("cannot read model metadata file"))?;
    Ok(sha256(&bytes))
}
