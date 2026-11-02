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

use do_context_shield_plugin_api::{Detector, DetectorError, Entity, resolve_overlaps};
use std::path::{Path, PathBuf};

#[cfg(feature = "gliner2")]
mod fragments;
#[cfg(feature = "gliner2")]
mod onnx;
mod readiness;

pub use readiness::{ModelLayout, ReadinessCode, ReadinessReport, probe};

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

/// Default maximum token sequence length for one inference call.
///
/// Conservative on purpose: encoder attention and the input tensor grow with
/// the square/cube of sequence length, and the single-file backend chunks
/// longer input with overlap instead of raising this value.
pub const DEFAULT_MAX_TOKENS: usize = 512;

/// Smallest accepted inference sequence length.
pub const MIN_MAX_TOKENS: usize = 16;

/// Default ONNX Runtime intra-op threads.
///
/// Two threads keep a local CLI/MCP server from taking every core on a busy
/// machine; the value is configurable and never derived from the processor
/// count automatically.
pub const DEFAULT_INTRA_THREADS: usize = 2;

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
    /// Maximum tokens in one inference call, including the export's special
    /// tokens. Longer input is split into overlapping windows, never
    /// silently truncated.
    pub max_tokens: usize,
    /// ONNX Runtime intra-op threads per session.
    pub intra_threads: usize,
}

impl Default for Gliner2Config {
    fn default() -> Self {
        Self {
            model_dir: None,
            labels: PII_LABELS_42.iter().map(ToString::to_string).collect(),
            threshold: DEFAULT_THRESHOLD,
            max_tokens: DEFAULT_MAX_TOKENS,
            intra_threads: DEFAULT_INTRA_THREADS,
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

    /// Set the inference resource limits.
    ///
    /// Values below the supported floor are clamped (`MIN_MAX_TOKENS`, one
    /// thread) rather than accepted, so a misconfiguration cannot shrink a
    /// sequence below the export's special tokens or create zero threads.
    #[must_use]
    pub fn with_limits(mut self, max_tokens: usize, intra_threads: usize) -> Self {
        self.max_tokens = max_tokens.max(MIN_MAX_TOKENS);
        self.intra_threads = intra_threads.max(1);
        self
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
/// non-`char` boundaries, clamps confidence to 0..=1, and hands the survivors
/// to [`resolve_overlaps`] (longest-span-wins, mirroring `detector-regex`).
#[must_use]
pub fn decode_spans(input: &str, spans: &[RawSpan], threshold: f32) -> Vec<Entity> {
    let entities: Vec<Entity> = spans
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

    resolve_overlaps(entities)
}

/// Byte window plan for one detection pass.
///
/// Contiguous `window`-byte ranges stepping by `window - overlap`, each
/// aligned to a UTF-8 character boundary. Tokenizing one window at a time
/// bounds tokenizer memory to the window instead of the whole input; the
/// overlap keeps an entity that straddles a window edge visible in a
/// neighbouring window. Empty input yields no windows.
#[cfg_attr(not(feature = "gliner2"), allow(dead_code))]
pub(crate) fn byte_windows(input: &str, window: usize, overlap: usize) -> Vec<(usize, usize)> {
    let len = input.len();
    if len == 0 {
        return Vec::new();
    }
    let window = window.max(1);
    let overlap = overlap.min(window.saturating_sub(1));
    let step = window - overlap;
    let mut windows = Vec::new();
    let mut start = 0;
    loop {
        let mut end = (start + window).min(len);
        while end < len && !input.is_char_boundary(end) {
            end += 1;
        }
        windows.push((start, end));
        if end == len {
            return windows;
        }
        let mut next = (start + step).min(len);
        while next < len && !input.is_char_boundary(next) {
            next += 1;
        }
        if next <= start {
            return windows;
        }
        start = next;
    }
}

/// Token window plan for one tokenized slice.
///
/// Windows are `window` tokens wide and step by `window - overlap`, so the
/// same tokens appear in consecutive windows and a boundary-crossing span can
/// be decoded whole in at least one of them. The overlap is capped at half the
/// window so a misconfiguration cannot multiply the inference count.
#[cfg_attr(not(feature = "gliner2"), allow(dead_code))]
pub(crate) fn token_windows(tokens: usize, window: usize, overlap: usize) -> Vec<(usize, usize)> {
    if tokens == 0 {
        return Vec::new();
    }
    let window = window.max(1);
    let overlap = overlap.min(window / 2);
    let step = window - overlap;
    let mut windows = Vec::new();
    let mut start = 0;
    loop {
        let end = (start + window).min(tokens);
        windows.push((start, end));
        if end == tokens {
            return windows;
        }
        start += step;
    }
}

/// Whether a logits tensor has the expected `[1, seq, labels]` or
/// `[seq, labels]` shape.
///
/// Checking element count alone would accept a transposed tensor whose rows
/// are class scores instead of token scores, decoding garbage spans.
#[cfg_attr(not(feature = "gliner2"), allow(dead_code))]
pub(crate) fn logits_shape_matches(dims: &[i64], seq_len: usize, labels: usize) -> bool {
    let seq_len = i64::try_from(seq_len).ok();
    let labels = i64::try_from(labels).ok();
    match dims {
        [batch, seq, classes] => Some(*seq) == seq_len && Some(*classes) == labels && *batch == 1,
        [seq, classes] => Some(*seq) == seq_len && Some(*classes) == labels,
        _ => false,
    }
}

/// The directory that actually holds the fragment set: the export root or one
/// of the legacy `fp32_v2/` / `fp16_v2/` subfolders.
pub(crate) fn fragment_layout_dir(model_dir: &Path) -> Option<PathBuf> {
    for subdir in ["", "fp32_v2", "fp16_v2"] {
        let dir = if subdir.is_empty() {
            model_dir.to_path_buf()
        } else {
            model_dir.join(subdir)
        };
        if has_onnx_with_prefix(&dir, "encoder") {
            return Some(dir);
        }
    }
    None
}

/// Whether `dir` holds a file whose name starts with `prefix` and ends in `.onnx`.
pub(crate) fn has_onnx_with_prefix(dir: &Path, prefix: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        name.starts_with(prefix) && name.ends_with(".onnx")
    })
}

/// Entity labels of a single-file export, ordered by class index.
///
/// `config.json` is part of the layout and its `id2label` object is the only
/// source of tag names: decoding a model whose tags are unknown maps every
/// token to `O`, so a misconfigured export would report a clean scan with zero
/// entities instead of failing. Absent file, unreadable file, invalid JSON, or
/// a map without a single index/tag pair is therefore an error.
///
/// # Errors
///
/// Returns [`DetectorError`] when `config_path` does not exist, cannot be read,
/// is not valid JSON, or carries no usable `id2label` entry. The message names
/// the file and failure class only, never file contents.
pub(crate) fn load_id2label(config_path: &Path) -> Result<Vec<String>, DetectorError> {
    let label_error = |what: &str| DetectorError::Message(format!("gliner2 onnx backend: {what}"));
    if !config_path.is_file() {
        return Err(label_error("config.json not found in model_dir"));
    }
    let raw =
        std::fs::read_to_string(config_path).map_err(|_| label_error("cannot read config.json"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|_| label_error("config.json is not valid JSON"))?;
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
    if pairs.is_empty() {
        return Err(label_error(
            "config.json has no usable `id2label` map (class index -> BIO tag)",
        ));
    }
    pairs.sort_by_key(|pair| pair.0);
    Ok(pairs.into_iter().map(|pair| pair.1).collect())
}

/// Local NER detector backed by a `GLiNER2` ONNX export.
///
/// Without the `gliner2` feature or a configured `model_dir`, [`Detector::detect`]
/// fails closed with guidance instead of returning an empty entity list.
pub struct Gliner2Detector {
    config: Gliner2Config,
    #[cfg(feature = "gliner2")]
    fragment: std::sync::Mutex<Option<fragments::FragmentEngine>>,
    #[cfg(feature = "gliner2")]
    single: std::sync::Mutex<Option<onnx::SingleFileEngine>>,
}

impl Gliner2Detector {
    /// Build a detector from an explicit config.
    #[must_use]
    pub fn new(config: Gliner2Config) -> Self {
        Self {
            config,
            #[cfg(feature = "gliner2")]
            fragment: std::sync::Mutex::new(None),
            #[cfg(feature = "gliner2")]
            single: std::sync::Mutex::new(None),
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
            let spans = self.single_file_spans(&model_dir, input)?;
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
        let engine = guard.get_or_insert_with(fragments::FragmentEngine::new);
        engine.extract(
            model_dir,
            self.config.intra_threads,
            &self.config.labels,
            self.config.threshold,
            input,
        )
    }

    /// Single-file-export spans for `input`, reusing the loaded tokenizer and
    /// ONNX session across calls.
    #[cfg(feature = "gliner2")]
    fn single_file_spans(
        &self,
        model_dir: &std::path::Path,
        input: &str,
    ) -> Result<Vec<RawSpan>, DetectorError> {
        let mut guard = self.single.lock().map_err(|_| {
            DetectorError::Message("gliner2 onnx backend: engine lock poisoned".to_owned())
        })?;
        let engine = guard.get_or_insert_with(onnx::SingleFileEngine::new);
        engine.detect(model_dir, &self.config, input)
    }
}

/// Whether `model_dir` holds a fragment export the backend can attempt.
///
/// Matches the flat layout (`encoder.onnx`, `encoder_fp32.onnx`,
/// `encoder_fp16.onnx`, plus their `_iobinding` variants) and the legacy
/// `fp16_v2/` / `fp32_v2/` subfolder layout. Presence only routes the call: an
/// incomplete set still fails closed when the engine loads it.
fn fragment_export(model_dir: &std::path::Path) -> bool {
    fragment_layout_dir(model_dir).is_some()
}

/// Whether `model_dir` holds a `GLiNER2.5` boundary export (unsupported here).
///
/// Probes the same three locations as `gliner2-rs` 0.9.6 (`span.rs`): the
/// manifest at the export root and in its `fp32_25/`/`fp16_25/` subfolders.
/// Checking the root only would let a subfolder layout fall through to the
/// engine and surface its generic "fragment not found" instead of the specific
/// error below.
fn boundary_export(model_dir: &std::path::Path) -> bool {
    ["", "fp32_25", "fp16_25"].iter().any(|subdir| {
        let dir = if subdir.is_empty() {
            model_dir.to_path_buf()
        } else {
            model_dir.join(subdir)
        };
        dir.join("boundary_manifest.json").is_file()
    })
}

#[cfg(test)]
mod tests;
