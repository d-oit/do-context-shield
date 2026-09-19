//! `GLiNER2` local NER detector plugin.
//!
//! Rust-only inference path: an ONNX backend behind the `gliner2` Cargo
//! feature ([`ort`] + `tokenizers` for single-file exports, [`gliner2_rs`] for
//! fragment exports, CPU-first). The base build carries no model and no native
//! dependency; detection without a configured model fails closed instead of
//! silently returning no entities.
//!
//! Supported model layouts inside `model_dir`:
//!
//! - Single-file token-classification ONNX (`model.onnx` + `tokenizer.json`
//!   + `config.json` with `id2label`): executed directly.
//! - `GLiNER2` span exports (`encoder` + `span_rep` + `scorer` + `classifier`
//!   fragments, flat or under `fp16_v2/`/`fp32_v2/`): executed by `gliner2-rs`
//!   with [`Gliner2Config::labels`] as the label schema.
//! - `GLiNER2.5` boundary exports (`boundary_manifest.json`): rejected; the
//!   boundary architecture needs a different engine (see `docs/plugins.md`).

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use std::path::PathBuf;

#[cfg(feature = "gliner2")]
mod fragments;
#[cfg(feature = "gliner2")]
mod onnx;

/// The 42 PII entity types of the GLiNER2-PII taxonomy, grouped as
/// person / contact / government / financial / digital / secret / dates.
pub const PII_LABELS_42: [&str; 42] = [
    "person",
    "full_name",
    "first_name",
    "middle_name",
    "last_name",
    "date_of_birth",
    "email",
    "phone_number",
    "address",
    "street_address",
    "city",
    "state_or_region",
    "postal_code",
    "country",
    "government_id",
    "national_id_number",
    "passport_number",
    "drivers_license_number",
    "license_number",
    "tax_id",
    "tax_number",
    "bank_account",
    "account_number",
    "routing_number",
    "iban",
    "payment_card",
    "card_number",
    "card_expiry",
    "card_cvv",
    "username",
    "ip_address",
    "account_id",
    "sensitive_account_id",
    "password",
    "secret",
    "api_key",
    "access_token",
    "recovery_code",
    "sensitive_date",
    "document_date",
    "expiration_date",
    "transaction_date",
];

/// Default confidence threshold applied to model spans.
pub const DEFAULT_THRESHOLD: f32 = 0.5;

/// Configuration for [`Gliner2Detector`].
#[derive(Clone, Debug)]
pub struct Gliner2Config {
    /// Local directory holding the ONNX export (`model.onnx`,
    /// `tokenizer.json`, `config.json`). `None` means unconfigured.
    pub model_dir: Option<PathBuf>,
    /// Labels the model is asked to extract.
    pub labels: Vec<String>,
    /// Minimum score for a span to become an entity.
    pub threshold: f32,
}

impl Default for Gliner2Config {
    fn default() -> Self {
        Self {
            model_dir: None,
            labels: PII_LABELS_42.iter().map(ToString::to_string).collect(),
            threshold: DEFAULT_THRESHOLD,
        }
    }
}

impl Gliner2Config {
    /// Build a config for a local model directory with default labels.
    #[must_use]
    pub fn with_model_dir(model_dir: PathBuf) -> Self {
        Self {
            model_dir: Some(model_dir),
            ..Self::default()
        }
    }
}

/// A backend-agnostic detected span: what any `GLiNER2` inference engine
/// (in-process ONNX, process sidecar) hands to [`decode_spans`].
#[derive(Clone, Debug, PartialEq)]
pub struct RawSpan {
    /// Model label, e.g. `email` or `phone_number`.
    pub label: String,
    /// Byte offset of the span start.
    pub start: usize,
    /// Byte offset immediately after the span.
    pub end: usize,
    /// Model score in the range 0..=1.
    pub score: f32,
}

/// Normalize a model label to a stable entity kind.
#[must_use]
pub fn canonical_kind(label: &str) -> String {
    label.trim().to_ascii_lowercase().replace(' ', "_")
}

/// Convert backend spans to pipeline entities.
///
/// Applies the score threshold, drops spans outside the input or on
/// non-`char` boundaries, clamps confidence to 0..=1, and resolves overlaps
/// longest-span-wins (mirroring `detector-regex`).
#[must_use]
pub fn decode_spans(input: &str, spans: &[RawSpan], threshold: f32) -> Vec<Entity> {
    let mut entities: Vec<Entity> = spans
        .iter()
        .filter(|span| span.score >= threshold && span.start < span.end && span.end <= input.len())
        .filter_map(|span| {
            let value = input.get(span.start..span.end)?;
            Some(Entity {
                kind: canonical_kind(&span.label),
                start: span.start,
                end: span.end,
                value: value.to_owned(),
                confidence: span.score.clamp(0.0, 1.0),
            })
        })
        .collect();

    entities.sort_by_key(|entity| (entity.start, usize::MAX - entity.end));
    let mut deduped = Vec::with_capacity(entities.len());
    for entity in entities {
        if deduped
            .iter()
            .any(|saved: &Entity| entity.start < saved.end && saved.start < entity.end)
        {
            continue;
        }
        deduped.push(entity);
    }
    deduped.sort_by_key(|entity: &Entity| (entity.start, entity.end));
    deduped
}

/// Local NER detector backed by a `GLiNER2` ONNX export.
///
/// Without the `gliner2` feature or a configured `model_dir`, [`Detector::detect`]
/// fails closed with guidance instead of returning an empty entity list.
pub struct Gliner2Detector {
    config: Gliner2Config,
    #[cfg(feature = "gliner2")]
    fragment: std::sync::Mutex<Option<fragments::FragmentEngine>>,
}

impl Gliner2Detector {
    /// Build a detector from an explicit config.
    #[must_use]
    pub fn new(config: Gliner2Config) -> Self {
        Self {
            config,
            #[cfg(feature = "gliner2")]
            fragment: std::sync::Mutex::new(None),
        }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &Gliner2Config {
        &self.config
    }

    fn fail_closed(reason: &str) -> DetectorError {
        DetectorError::Message(format!(
            "gliner2 detector unavailable ({reason}); configure `model_dir` with a local ONNX export and rebuild with `--features gliner2`. No entities returned by design."
        ))
    }
}

impl Default for Gliner2Detector {
    fn default() -> Self {
        Self::new(Gliner2Config::default())
    }
}

impl Detector for Gliner2Detector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        let Some(model_dir) = self.config.model_dir.clone() else {
            return Err(Self::fail_closed("model_dir not configured"));
        };
        if !model_dir.is_dir() {
            return Err(Self::fail_closed("model_dir does not exist"));
        }
        if boundary_export(&model_dir) {
            return Err(DetectorError::Message(
                "gliner2.5 boundary export detected; the boundary architecture is not supported, use a GLiNER2 span export (encoder + span_rep + scorer fragments) or a single-file token-classification ONNX export"
                    .to_owned(),
            ));
        }
        if fragment_export(&model_dir) {
            #[cfg(feature = "gliner2")]
            {
                let spans = self.fragment_spans(&model_dir, input)?;
                return Ok(decode_spans(input, &spans, self.config.threshold));
            }
            #[cfg(not(feature = "gliner2"))]
            {
                let _ = input;
                return Err(Self::fail_closed(
                    "this export is a GLiNER2 fragment set, which needs a binary built with the `gliner2` feature",
                ));
            }
        }
        #[cfg(feature = "gliner2")]
        {
            let spans = onnx::detect(&model_dir, &self.config.labels, input)?;
            Ok(decode_spans(input, &spans, self.config.threshold))
        }
        #[cfg(not(feature = "gliner2"))]
        {
            let _ = &model_dir;
            let _ = input;
            Err(Self::fail_closed(
                "binary built without the `gliner2` feature",
            ))
        }
    }
}

impl Gliner2Detector {
    /// Fragment-export spans for `input`, loading the engine on first use.
    #[cfg(feature = "gliner2")]
    fn fragment_spans(
        &self,
        model_dir: &std::path::Path,
        input: &str,
    ) -> Result<Vec<RawSpan>, DetectorError> {
        let mut guard = self.fragment.lock().map_err(|_| {
            DetectorError::Message("gliner2 fragment backend: engine lock poisoned".to_owned())
        })?;
        let intra_threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        let engine = guard.get_or_insert_with(fragments::FragmentEngine::new);
        engine.extract(
            model_dir,
            intra_threads,
            &self.config.labels,
            self.config.threshold,
            input,
        )
    }
}

/// Whether `model_dir` holds a fragment export the backend can attempt.
///
/// Matches the flat layout (`encoder.onnx`, `encoder_fp32.onnx`,
/// `encoder_fp16.onnx`, plus their `_iobinding` variants) and the legacy
/// `fp16_v2/` / `fp32_v2/` subfolder layout. Presence only routes the call: an
/// incomplete set still fails closed when the engine loads it.
fn fragment_export(model_dir: &std::path::Path) -> bool {
    for subdir in ["", "fp32_v2", "fp16_v2"] {
        let dir = if subdir.is_empty() {
            model_dir.to_path_buf()
        } else {
            model_dir.join(subdir)
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let has_encoder = entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("encoder") && name.ends_with(".onnx")
        });
        if has_encoder {
            return true;
        }
    }
    false
}

/// Whether `model_dir` holds a `GLiNER2.5` boundary export (unsupported here).
fn boundary_export(model_dir: &std::path::Path) -> bool {
    model_dir.join("boundary_manifest.json").is_file()
}

#[cfg(test)]
mod tests;
