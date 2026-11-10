use do_context_shield_plugin_api::Detector;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::io;

const CORPUS_SOURCE: &str = include_str!("../../../../quality/corpus/v1.json");
const REGEX_PATTERNS: &str = include_str!("../../../detector-regex/src/patterns.rs");
#[cfg(feature = "gliner2")]
#[path = "model_support.rs"]
mod model_support;
#[cfg(feature = "gliner2")]
pub(super) use model_support::{ModelSetup, model_identity, optional_model_setup};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Mode {
    Regex,
    Gliner2,
    Hybrid,
}

#[derive(Debug, Deserialize)]
pub(super) struct Corpus {
    pub schema_version: u32,
    pub revision: String,
    pub license: String,
    pub provenance: String,
    pub span_unit: String,
    pub cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Case {
    pub id: String,
    pub category: String,
    pub text: String,
    #[serde(default)]
    pub gate_modes: Vec<Mode>,
    #[serde(default)]
    pub manual_review_priority: Option<String>,
    pub entities: Vec<Annotation>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Annotation {
    pub kind: String,
    pub surface: String,
    pub start_char: usize,
    pub end_char: usize,
    pub modes: Vec<Mode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Span {
    kind: String,
    start_byte: usize,
    end_byte: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Counts {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
}

impl Counts {
    fn add(&mut self, other: Self) {
        self.true_positives += other.true_positives;
        self.false_positives += other.false_positives;
        self.false_negatives += other.false_negatives;
    }

    fn metrics(self) -> MetricSet {
        let precision = ratio(
            self.true_positives,
            self.true_positives + self.false_positives,
        );
        let recall = ratio(
            self.true_positives,
            self.true_positives + self.false_negatives,
        );
        let f1_denominator = 2 * self.true_positives + self.false_positives + self.false_negatives;
        let f1 = ratio(2 * self.true_positives, f1_denominator);
        MetricSet {
            true_positives: self.true_positives,
            false_positives: self.false_positives,
            false_negatives: self.false_negatives,
            precision,
            recall,
            f1,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
struct MetricSet {
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
    precision: Option<f64>,
    recall: Option<f64>,
    f1: Option<f64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(super) struct Finding {
    pub(super) case_id: String,
    category: String,
    kind: String,
    start_byte: usize,
    end_byte: usize,
    pub(super) manual_review_priority: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(super) struct DetectorIdentity {
    pub(super) mode: Mode,
    pub(super) detector_version: String,
    pub(super) model_version: Option<String>,
    pub(super) tokenizer_sha256: Option<String>,
    pub(super) model_config_sha256: Option<String>,
    pub(super) model_config_source: Option<String>,
    pub(super) runtime_config_sha256: Option<String>,
    pub(super) regex_patterns_sha256: Option<String>,
}

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct Report {
    schema_version: u32,
    corpus_revision: String,
    corpus_sha256: String,
    corpus_license: String,
    span_unit: String,
    detector: DetectorIdentity,
    aggregate: MetricSet,
    per_kind: BTreeMap<String, MetricSet>,
    false_positives: Vec<Finding>,
    pub(super) false_negatives: Vec<Finding>,
    pub(super) deterministic_gate_failures: Vec<String>,
}

#[derive(Default)]
struct CaseScore {
    counts: Counts,
    per_kind: BTreeMap<String, Counts>,
    false_positives: Vec<Span>,
    false_negatives: Vec<Span>,
}

/// Load and validate the versioned synthetic corpus.
///
/// # Errors
/// Returns an error if the JSON is invalid, metadata is incomplete, case IDs
/// repeat, or an annotation does not map to its declared character span.
pub(super) fn load_corpus() -> Result<Corpus, Box<dyn Error>> {
    let corpus: Corpus = serde_json::from_str(CORPUS_SOURCE)?;
    validate_corpus(&corpus)?;
    Ok(corpus)
}

/// Validate corpus structure and verify every annotation against its Unicode span.
///
/// # Errors
/// Returns invalid data when metadata, case IDs, or annotated surfaces are inconsistent.
fn validate_corpus(corpus: &Corpus) -> Result<(), io::Error> {
    if corpus.schema_version != 1
        || corpus.revision.is_empty()
        || corpus.license != "CC0-1.0"
        || corpus.provenance.is_empty()
        || corpus.span_unit != "unicode_scalar_values_zero_based_half_open"
        || corpus.cases.is_empty()
    {
        return Err(invalid_data("quality corpus metadata is incomplete"));
    }

    let mut ids = HashSet::with_capacity(corpus.cases.len());
    for case in &corpus.cases {
        if case.id.is_empty() || case.category.is_empty() || case.text.is_empty() {
            return Err(invalid_data("quality corpus case is incomplete"));
        }
        if !ids.insert(case.id.as_str()) {
            return Err(invalid_data("quality corpus contains a duplicate case ID"));
        }
        for annotation in &case.entities {
            if annotation.kind.is_empty()
                || annotation.surface.is_empty()
                || annotation.modes.is_empty()
            {
                return Err(invalid_data("quality corpus annotation is incomplete"));
            }
            let start = char_to_byte(&case.text, annotation.start_char)
                .ok_or_else(|| invalid_data("annotation start is outside the case text"))?;
            let end = char_to_byte(&case.text, annotation.end_char)
                .ok_or_else(|| invalid_data("annotation end is outside the case text"))?;
            if start >= end || case.text.get(start..end) != Some(annotation.surface.as_str()) {
                return Err(invalid_data(
                    "annotation span does not match its declared surface",
                ));
            }
        }
    }
    Ok(())
}

/// Convert a Unicode scalar-value offset to a UTF-8 byte offset.
#[must_use]
pub(super) fn char_to_byte(text: &str, offset: usize) -> Option<usize> {
    let mut scalar_index = 0usize;
    for (byte_index, _) in text.char_indices() {
        if scalar_index == offset {
            return Some(byte_index);
        }
        scalar_index += 1;
    }
    (scalar_index == offset).then_some(text.len())
}

/// Score exact `(kind, byte span)` matches and preserve duplicate predictions as false positives.
fn score_spans(expected: &[Span], predicted: &[Span]) -> CaseScore {
    let mut result = CaseScore::default();
    let mut matched = vec![false; expected.len()];

    for prediction in predicted {
        let exact = expected.iter().enumerate().find_map(|(index, candidate)| {
            (!matched[index] && candidate == prediction).then_some(index)
        });
        if let Some(index) = exact {
            matched[index] = true;
            result.counts.true_positives += 1;
            result
                .per_kind
                .entry(prediction.kind.clone())
                .or_default()
                .true_positives += 1;
        } else {
            result.counts.false_positives += 1;
            result
                .per_kind
                .entry(prediction.kind.clone())
                .or_default()
                .false_positives += 1;
            result.false_positives.push(prediction.clone());
        }
    }

    for (index, annotation) in expected.iter().enumerate() {
        if !matched[index] {
            result.counts.false_negatives += 1;
            result
                .per_kind
                .entry(annotation.kind.clone())
                .or_default()
                .false_negatives += 1;
            result.false_negatives.push(annotation.clone());
        }
    }
    result
}

/// Evaluate one detector over the same corpus and produce a value-free JSON report.
///
/// # Errors
/// Returns an error if a detector fails on any corpus case or an annotation
/// cannot be converted to the detector's byte-span convention.
pub(super) fn evaluate<D: Detector>(
    detector: &D,
    mode: Mode,
    corpus: &Corpus,
    identity: DetectorIdentity,
) -> Result<Report, Box<dyn Error>> {
    let mut aggregate = Counts::default();
    let mut per_kind = BTreeMap::<String, Counts>::new();
    let mut false_positives = Vec::new();
    let mut false_negatives = Vec::new();
    let mut deterministic_gate_failures = Vec::new();

    for case in &corpus.cases {
        let mut expected = Vec::new();
        for annotation in case
            .entities
            .iter()
            .filter(|item| item.modes.contains(&mode))
        {
            let start_byte = char_to_byte(&case.text, annotation.start_char)
                .ok_or_else(|| invalid_data("annotation start is outside the case text"))?;
            let end_byte = char_to_byte(&case.text, annotation.end_char)
                .ok_or_else(|| invalid_data("annotation end is outside the case text"))?;
            expected.push(Span {
                kind: annotation.kind.clone(),
                start_byte,
                end_byte,
            });
        }
        let detected = detector.detect(&case.text).map_err(|_| {
            invalid_data_owned(format!("detector failed on synthetic case `{}`", case.id))
        })?;
        let predicted: Vec<Span> = detected
            .into_iter()
            .map(|entity| Span {
                kind: entity.kind,
                start_byte: entity.start,
                end_byte: entity.end,
            })
            .collect();
        let scored = score_spans(&expected, &predicted);

        if case.gate_modes.contains(&mode)
            && (scored.counts.false_positives > 0 || scored.counts.false_negatives > 0)
        {
            deterministic_gate_failures.push(case.id.clone());
        }
        aggregate.add(scored.counts);
        for (kind, counts) in scored.per_kind {
            per_kind.entry(kind).or_default().add(counts);
        }
        false_positives.extend(
            scored
                .false_positives
                .into_iter()
                .map(|span| finding(case, span)),
        );
        false_negatives.extend(
            scored
                .false_negatives
                .into_iter()
                .map(|span| finding(case, span)),
        );
    }

    false_positives.sort();
    false_negatives.sort();
    deterministic_gate_failures.sort();
    Ok(Report {
        schema_version: 1,
        corpus_revision: corpus.revision.clone(),
        corpus_sha256: sha256(CORPUS_SOURCE.as_bytes()),
        corpus_license: corpus.license.clone(),
        span_unit: String::from("utf8_bytes_zero_based_half_open"),
        detector: identity,
        aggregate: aggregate.metrics(),
        per_kind: per_kind
            .into_iter()
            .map(|(kind, counts)| (kind, counts.metrics()))
            .collect(),
        false_positives,
        false_negatives,
        deterministic_gate_failures,
    })
}

fn finding(case: &Case, span: Span) -> Finding {
    Finding {
        case_id: case.id.clone(),
        category: case.category.clone(),
        kind: span.kind,
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        manual_review_priority: case.manual_review_priority.clone(),
    }
}

/// Build the identity for the built-in regex patterns.
#[must_use]
pub(super) fn regex_identity() -> DetectorIdentity {
    DetectorIdentity {
        mode: Mode::Regex,
        detector_version: env!("CARGO_PKG_VERSION").to_owned(),
        model_version: None,
        tokenizer_sha256: None,
        model_config_sha256: None,
        model_config_source: None,
        runtime_config_sha256: None,
        regex_patterns_sha256: Some(sha256(REGEX_PATTERNS.as_bytes())),
    }
}

/// Print a structured JSON report without corpus text or detected values.
pub(super) fn print_report(report: &Report) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => println!("DETECTION_QUALITY_REPORT {json}"),
        Err(error) => panic!("could not serialize the detection-quality report: {error}"),
    }
}

fn sha256(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in &digest {
        let byte = *byte;
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

// Counts come from the small versioned corpus and stay within f64's exact-integer range.
#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_data_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[path = "support_tests.rs"]
mod tests;
