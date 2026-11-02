//! Local, network-free readiness probe for a configured `GLiNER2` detector.
//!
//! The probe answers one question before any private text is routed through
//! the pipeline: is this detector configured *and* loadable right now? It
//! never downloads a model or runtime, never reads model file contents, and
//! never falls back to a different detector. Failures are reported as stable
//! categories with fixed guidance, so a script can distinguish "not
//! configured" from "configured but the runtime or export is broken".

use std::path::Path;

use crate::{
    Gliner2Config, boundary_export, fragment_layout_dir, has_onnx_with_prefix, load_id2label,
};

/// Fragment families a span export needs in addition to the encoder.
const FRAGMENT_FAMILIES: [&str; 7] = [
    "token_gather",
    "span_rep",
    "schema_gather",
    "count_pred_argmax",
    "count_lstm_fixed",
    "scorer",
    "classifier",
];

/// Stable readiness category, suitable for scripts (`code` in JSON output).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessCode {
    /// Configured and loadable.
    Ready,
    /// The export is valid but the binary lacks the `gliner2` feature.
    FeatureDisabled,
    /// No `model_dir` is configured.
    NotConfigured,
    /// `model_dir` does not exist or is not a directory.
    MissingModelDir,
    /// A required model file (`model.onnx`) is absent.
    MissingModelFile,
    /// `tokenizer.json` is absent for a single-file export.
    MissingTokenizer,
    /// `config.json`/`id2label` yields no class labels, or no labels are configured.
    MissingLabels,
    /// A `GLiNER2.5` boundary export, which this detector does not support.
    UnsupportedExport,
    /// The fragment set is missing one of its required files.
    IncompleteFragments,
    /// The ONNX Runtime or the model failed to load; check `ORT_DYLIB_PATH`
    /// and the export integrity.
    RuntimeUnavailable,
}

impl ReadinessCode {
    /// Stable lowercase name used in structured output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::FeatureDisabled => "feature_disabled",
            Self::NotConfigured => "not_configured",
            Self::MissingModelDir => "missing_model_dir",
            Self::MissingModelFile => "missing_model_file",
            Self::MissingTokenizer => "missing_tokenizer",
            Self::MissingLabels => "missing_labels",
            Self::UnsupportedExport => "unsupported_export",
            Self::IncompleteFragments => "incomplete_fragments",
            Self::RuntimeUnavailable => "runtime_unavailable",
        }
    }
}

/// Export layout the probe recognized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelLayout {
    /// Single-file token classification (`model.onnx` + `tokenizer.json` +
    /// `config.json`).
    SingleFile,
    /// `GLiNER2` span export (encoder plus the seven fragment files).
    Fragments,
}

impl ModelLayout {
    /// Stable lowercase name used in structured output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleFile => "single_file",
            Self::Fragments => "fragments",
        }
    }
}

/// Result of a readiness probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessReport {
    /// Whether detection can run with this configuration now.
    pub available: bool,
    /// Where the probe stopped.
    pub code: ReadinessCode,
    /// Fixed, path-free operator guidance for `code`.
    pub guidance: &'static str,
    /// Recognized export layout, when one was found.
    pub layout: Option<ModelLayout>,
    /// Configured maximum tokens per inference call.
    pub max_tokens: usize,
    /// Configured ONNX Runtime intra-op threads.
    pub intra_threads: usize,
}

impl ReadinessReport {
    fn unavailable(
        code: ReadinessCode,
        guidance: &'static str,
        layout: Option<ModelLayout>,
        config: &Gliner2Config,
    ) -> Self {
        Self {
            available: false,
            code,
            guidance,
            layout,
            max_tokens: config.max_tokens,
            intra_threads: config.intra_threads,
        }
    }
}

/// Probe the configured detector without sending private text anywhere.
///
/// Checks run in a fixed order: label schema, configuration, directory,
/// export layout, required files, feature support, then a real backend load
/// when the feature is enabled. File existence alone never reports `Ready`.
#[must_use]
pub fn probe(config: &Gliner2Config) -> ReadinessReport {
    if config.labels.is_empty() {
        return ReadinessReport::unavailable(
            ReadinessCode::MissingLabels,
            "configure at least one entity label (defaults cover the GLiNER2-PII taxonomy)",
            None,
            config,
        );
    }
    let Some(model_dir) = config.model_dir.as_deref() else {
        return ReadinessReport::unavailable(
            ReadinessCode::NotConfigured,
            "configure a local export directory with `--model-dir`; models are never downloaded",
            None,
            config,
        );
    };
    if !model_dir.is_dir() {
        return ReadinessReport::unavailable(
            ReadinessCode::MissingModelDir,
            "check `--model-dir`: the path is not an existing directory",
            None,
            config,
        );
    }
    if boundary_export(model_dir) {
        return ReadinessReport::unavailable(
            ReadinessCode::UnsupportedExport,
            "use a GLiNER2 span export (encoder plus fragment files) or a single-file token-classification export; GLiNER2.5 boundary exports are not supported",
            None,
            config,
        );
    }
    if let Some(dir) = fragment_layout_dir(model_dir) {
        return probe_fragments(config, &dir);
    }
    let model = model_dir.join("model.onnx");
    if !model.is_file() {
        return ReadinessReport::unavailable(
            ReadinessCode::MissingModelFile,
            "the export directory holds neither `model.onnx` nor an `encoder*.onnx` fragment set",
            None,
            config,
        );
    }
    if !model_dir.join("tokenizer.json").is_file() {
        return ReadinessReport::unavailable(
            ReadinessCode::MissingTokenizer,
            "a single-file export needs `tokenizer.json` next to `model.onnx`",
            Some(ModelLayout::SingleFile),
            config,
        );
    }
    if load_id2label(&model_dir.join("config.json")).is_err() {
        return ReadinessReport::unavailable(
            ReadinessCode::MissingLabels,
            "`config.json` must carry a usable `id2label` map (class index to BIO tag)",
            Some(ModelLayout::SingleFile),
            config,
        );
    }
    finish(config, ModelLayout::SingleFile, model_dir)
}

/// Fragment-export branch: required files, then the real engine load.
fn probe_fragments(config: &Gliner2Config, dir: &Path) -> ReadinessReport {
    let missing = FRAGMENT_FAMILIES
        .iter()
        .any(|family| !has_onnx_with_prefix(dir, family));
    if missing {
        return ReadinessReport::unavailable(
            ReadinessCode::IncompleteFragments,
            "the fragment export is missing one of token_gather, span_rep, schema_gather, count_pred_argmax, count_lstm_fixed, scorer, classifier",
            Some(ModelLayout::Fragments),
            config,
        );
    }
    finish(config, ModelLayout::Fragments, dir)
}

/// Shared tail: feature gate, then a real backend load.
fn finish(config: &Gliner2Config, layout: ModelLayout, dir: &Path) -> ReadinessReport {
    #[cfg(not(feature = "gliner2"))]
    {
        let _ = dir;
        ReadinessReport::unavailable(
            ReadinessCode::FeatureDisabled,
            "rebuild with `--features gliner2` to use a local ONNX model",
            Some(layout),
            config,
        )
    }
    #[cfg(feature = "gliner2")]
    {
        let loaded = match layout {
            ModelLayout::SingleFile => crate::onnx::probe(dir, config.intra_threads),
            ModelLayout::Fragments => crate::fragments::probe(dir, config.intra_threads),
        };
        match loaded {
            Ok(()) => ReadinessReport {
                available: true,
                code: ReadinessCode::Ready,
                guidance: "detector is configured and loadable; no network access was used",
                layout: Some(layout),
                max_tokens: config.max_tokens,
                intra_threads: config.intra_threads,
            },
            Err(_) => ReadinessReport::unavailable(
                ReadinessCode::RuntimeUnavailable,
                "the model or ONNX Runtime failed to load; check `ORT_DYLIB_PATH` (load-dynamic builds) and the export files",
                Some(layout),
                config,
            ),
        }
    }
}
