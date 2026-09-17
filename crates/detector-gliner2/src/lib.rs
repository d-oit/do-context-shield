//! `GLiNER2` local NER detector plugin.
//!
//! Rust-only inference path: an ONNX backend behind the `gliner2` Cargo
//! feature ([`ort`] + `tokenizers` + `ndarray`, CPU-first). The base build
//! carries no model and no native dependency; detection without a configured
//! model fails closed instead of silently returning no entities.
//!
//! Supported model layouts inside `model_dir`:
//!
//! - Single-file token-classification ONNX (`model.onnx` + `tokenizer.json`
//!   + `config.json` with `id2label`): executed directly.
//! - `GLiNER2` / `GLiNER2.5` multi-fragment boundary exports: detected and
//!   reported as unsupported until fragment orchestration lands (see
//!   `docs/plugins.md`); the span-decoding contract below already matches
//!   that pipeline's output shape.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use std::path::PathBuf;

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
}

impl Gliner2Detector {
    /// Build a detector from an explicit config.
    #[must_use]
    pub fn new(config: Gliner2Config) -> Self {
        Self { config }
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
        if has_boundary_fragments(&model_dir) {
            return Err(DetectorError::Message(
                "gliner2 boundary-fragment export detected; multi-fragment orchestration is not implemented yet, use a single-file token-classification ONNX export"
                    .to_owned(),
            ));
        }
        #[cfg(feature = "gliner2")]
        {
            let spans = onnx_detect(&model_dir, &self.config.labels, input)?;
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

/// Check for a `GLiNER2` / `GLiNER2.5` multi-fragment boundary export.
fn has_boundary_fragments(model_dir: &std::path::Path) -> bool {
    model_dir.join("boundary_manifest.json").is_file()
        || model_dir.join("encoder.onnx").is_file()
        || model_dir.join("onnx").is_dir()
}

/// Run a single-file token-classification ONNX model and BIO-decode logits.
///
/// Expected layout: `model.onnx`, `tokenizer.json`, `config.json` carrying an
/// `id2label` map. Only compiled with the `gliner2` feature.
#[cfg(feature = "gliner2")]
fn onnx_detect(
    model_dir: &std::path::Path,
    labels: &[String],
    input: &str,
) -> Result<Vec<RawSpan>, DetectorError> {
    use ort::session::builder::GraphOptimizationLevel;

    let map_err = |what: &str| DetectorError::Message(format!("gliner2 onnx backend: {what}"));
    let model_path = model_dir.join("model.onnx");
    let tokenizer_path = model_dir.join("tokenizer.json");
    let config_path = model_dir.join("config.json");
    if !model_path.is_file() {
        return Err(map_err("model.onnx not found in model_dir"));
    }
    if !tokenizer_path.is_file() {
        return Err(map_err("tokenizer.json not found in model_dir"));
    }

    let id2label: Vec<String> = if config_path.is_file() {
        let raw = std::fs::read_to_string(&config_path)
            .map_err(|_| map_err("cannot read config.json"))?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| map_err("config.json is not valid JSON"))?;
        let mut pairs: Vec<(usize, String)> = Vec::new();
        if let Some(map) = value.get("id2label").and_then(serde_json::Value::as_object) {
            for (id, label) in map {
                if let (Ok(index), Some(name)) =
                    (id.parse::<usize>(), label.as_str().map(ToString::to_string))
                {
                    pairs.push((index, name));
                }
            }
        }
        pairs.sort_by_key(|pair| pair.0);
        pairs.into_iter().map(|pair| pair.1).collect()
    } else {
        labels.to_vec()
    };

    let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path)
        .map_err(|_| map_err("cannot load tokenizer.json"))?;
    let encoding = tokenizer
        .encode(input, false)
        .map_err(|_| map_err("tokenization failed"))?;
    let ids: Vec<i64> = encoding.get_ids().iter().map(|id| i64::from(*id)).collect();
    let mask: Vec<i64> = encoding
        .get_attention_mask()
        .iter()
        .map(|bit| i64::from(*bit))
        .collect();
    let offsets = encoding.get_offsets().to_vec();
    let seq_len = ids.len();
    if seq_len == 0 {
        return Ok(Vec::new());
    }

    let intra_threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let builder = ort::session::Session::builder()
        .map_err(|_| map_err("cannot create ONNX session builder"))?;
    let mut session = builder
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|_| map_err("cannot set optimization level"))?
        .with_intra_threads(intra_threads)
        .map_err(|_| map_err("cannot set thread count"))?
        .commit_from_file(&model_path)
        .map_err(|_| map_err("cannot load model.onnx; check ORT_DYLIB_PATH with load-dynamic"))?;

    let id_value = ort::value::Value::from_array((vec![1_usize, seq_len], ids))
        .map_err(|_| map_err("bad input tensor"))?;
    let mask_value = ort::value::Value::from_array((vec![1_usize, seq_len], mask))
        .map_err(|_| map_err("bad mask tensor"))?;
    let outputs = session
        .run(ort::inputs!["input_ids" => id_value, "attention_mask" => mask_value])
        .map_err(|_| map_err("inference failed"))?;
    let Some((_name, value)) = outputs.into_iter().next() else {
        return Err(map_err("model returned no outputs"));
    };
    let (shape, flat) = value
        .try_extract_tensor::<f32>()
        .map_err(|_| map_err("logits are not an f32 tensor"))?;
    let num_labels = id2label.len();
    if num_labels == 0
        || shape.num_elements() != seq_len * num_labels
        || flat.len() != seq_len * num_labels
    {
        return Err(map_err("unexpected logits shape"));
    }

    Ok(bio_decode(seq_len, num_labels, flat, &offsets, &id2label))
}

/// Decode `[seq_len, num_labels]` logits with BIO tags into char spans.
///
/// Token offsets `(0, 0)` mark special tokens and are skipped. Scores use a
/// sigmoid of the winning logit as a bounded heuristic.
#[cfg(feature = "gliner2")]
fn bio_decode(
    seq_len: usize,
    num_labels: usize,
    flat: &[f32],
    offsets: &[(usize, usize)],
    id2label: &[String],
) -> Vec<RawSpan> {
    let seq_len = seq_len.min(offsets.len());
    let mut spans = Vec::new();
    let mut open: Option<(String, usize, f32)> = None;

    let close = |open: &mut Option<(String, usize, f32)>, spans: &mut Vec<RawSpan>, end: usize| {
        if let Some((label, start, score)) = open.take() {
            if end > start {
                spans.push(RawSpan {
                    label,
                    start,
                    end,
                    score,
                });
            }
        }
    };

    for (index, (start, end)) in offsets.iter().copied().enumerate().take(seq_len) {
        if start >= end {
            continue;
        }
        let row = index * num_labels;
        let mut best = 0usize;
        for label in 1..num_labels {
            if flat.get(row + label).copied().unwrap_or(f32::MIN)
                > flat.get(row + best).copied().unwrap_or(f32::MIN)
            {
                best = label;
            }
        }
        let raw_label = id2label.get(best).map_or("O", String::as_str);
        let score = 1.0 / (1.0 + (-flat.get(row + best).copied().unwrap_or(0.0)).exp());
        let (prefix, name) = raw_label
            .split_once('-')
            .map_or(("O", raw_label), |(prefix, name)| (prefix, name));
        if prefix == "B" {
            close(&mut open, &mut spans, start);
            open = Some((name.to_owned(), start, score));
        } else if prefix == "I" {
            if let Some((label, open_start, best_score)) = open.take() {
                if label == name {
                    open = Some((label, open_start, best_score.max(score)));
                } else {
                    close(&mut open, &mut spans, start);
                    open = Some((name.to_owned(), start, score));
                }
            } else {
                open = Some((name.to_owned(), start, score));
            }
        } else {
            close(&mut open, &mut spans, start);
        }
        if index + 1 == seq_len && open.is_some() {
            close(&mut open, &mut spans, end);
        }
    }
    spans
}

#[cfg(test)]
mod tests {
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
}
