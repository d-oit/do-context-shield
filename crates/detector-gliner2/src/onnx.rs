//! Single-file token-classification ONNX backend, gated behind the `gliner2` feature.
//!
//! The engine owns the tokenizer, label map, and ONNX session for the lifetime
//! of one detector instance and executes on a dedicated worker thread
//! (`ort::Session` is not `Send`), mirroring the fragment worker. Input is
//! split into overlapping byte windows before tokenization and into token
//! windows before inference, so neither tokenization memory nor tensor shapes
//! grow without bound; a slice that cannot be evaluated fails the whole call
//! instead of returning a partial scan.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};

use crate::{
    Gliner2Config, RawSpan, byte_windows, load_id2label, logits_shape_matches, token_windows,
};
use do_context_shield_plugin_api::DetectorError;

/// Bytes of input budgeted per token when sizing a tokenization window.
///
/// Tokenizers emit at least one token per byte in the worst case, so this is a
/// heuristic sizing factor; the hard bound is enforced again after tokenizing,
/// by splitting the token stream into windows of at most `max_tokens`.
const BYTES_PER_TOKEN_BUDGET: usize = 8;

/// Smallest byte window, so a tiny `max_tokens` cannot produce per-word calls.
const MIN_BYTE_WINDOW: usize = 1024;

/// Counts export loads in tests, to pin that one detector instance loads the
/// tokenizer and session once and reuses them.
#[cfg(test)]
pub(crate) static ENGINE_LOADS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Error text for the single-file backend, never carrying input or model data.
fn backend_error(what: &str) -> DetectorError {
    DetectorError::Message(format!("gliner2 onnx backend: {what}"))
}

/// Engine that reuses one loaded tokenizer and ONNX session across calls.
///
/// The session is created on the worker thread that uses it and dropped when
/// the detector is dropped.
pub(crate) struct SingleFileEngine {
    worker: Option<Worker>,
}

struct Worker {
    requests: Sender<Request>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.requests.send(Request::Shutdown);
    }
}

enum Request {
    Detect {
        input: String,
        reply: Sender<Result<Vec<RawSpan>, String>>,
    },
    Shutdown,
}

impl SingleFileEngine {
    pub(crate) fn new() -> Self {
        Self { worker: None }
    }

    /// Detect spans in `input`, loading the export once per engine.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] when the worker cannot start, the export
    /// cannot be loaded, tokenization fails, inference fails, or the model
    /// output is malformed. The error names the failure class, never the
    /// input or model contents.
    pub(crate) fn detect(
        &mut self,
        model_dir: &Path,
        config: &Gliner2Config,
        input: &str,
    ) -> Result<Vec<RawSpan>, DetectorError> {
        if self.worker.is_none() {
            self.worker = Some(Worker::spawn(
                model_dir.to_path_buf(),
                config.max_tokens,
                config.intra_threads,
            )?);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or_else(|| backend_error("worker unavailable"))?;
        let (reply, answer) = channel();
        worker
            .requests
            .send(Request::Detect {
                input: input.to_owned(),
                reply,
            })
            .map_err(|_| backend_error("engine thread stopped"))?;
        answer
            .recv()
            .map_err(|_| backend_error("engine thread stopped before answering"))?
            .map_err(|reason| backend_error(&reason))
    }
}

impl Worker {
    fn spawn(
        model_dir: PathBuf,
        max_tokens: usize,
        intra_threads: usize,
    ) -> Result<Self, DetectorError> {
        let (requests, incoming) = channel();
        std::thread::Builder::new()
            .name("gliner2-onnx".to_owned())
            .spawn(move || serve(&incoming, &model_dir, max_tokens, intra_threads))
            .map_err(|_| backend_error("cannot start the engine thread"))?;
        Ok(Self { requests })
    }
}

/// Worker loop: load the export on first use, answer detect requests.
fn serve(incoming: &Receiver<Request>, model_dir: &Path, max_tokens: usize, intra_threads: usize) {
    let mut loaded_engine: Option<Loaded> = None;
    while let Ok(request) = incoming.recv() {
        match request {
            Request::Detect { input, reply } => {
                let result = match loaded_engine.take() {
                    Some(mut loaded) => {
                        let spans = detect_with(&mut loaded, &input);
                        loaded_engine = Some(loaded);
                        spans
                    }
                    None => {
                        Loaded::load(model_dir, max_tokens, intra_threads).and_then(|mut loaded| {
                            let spans = detect_with(&mut loaded, &input);
                            loaded_engine = Some(loaded);
                            spans
                        })
                    }
                };
                let _ = reply.send(result);
            }
            Request::Shutdown => return,
        }
    }
}

/// Loaded export: tokenizer, label map, special-token wrapping, and session.
struct Loaded {
    tokenizer: tokenizers::Tokenizer,
    session: ort::session::Session,
    id2label: Vec<String>,
    prefix: Vec<i64>,
    suffix: Vec<i64>,
    max_tokens: usize,
}

impl Loaded {
    fn load(model_dir: &Path, max_tokens: usize, intra_threads: usize) -> Result<Self, String> {
        #[cfg(test)]
        ENGINE_LOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id2label =
            load_id2label(&model_dir.join("config.json")).map_err(|error| error.to_string())?;
        let tokenizer = tokenizers::Tokenizer::from_file(model_dir.join("tokenizer.json"))
            .map_err(|_| "cannot load tokenizer.json".to_owned())?;
        let specials = tokenizer
            .encode("", true)
            .map_err(|_| "cannot tokenize special tokens".to_owned())?;
        let special_ids: Vec<i64> = specials.get_ids().iter().map(|id| i64::from(*id)).collect();
        // A BERT-style export adds one leading and one trailing special token;
        // model families without them contribute no wrapping.
        let (prefix, suffix) = match special_ids.as_slice() {
            [] => (Vec::new(), Vec::new()),
            [first, last] => (vec![*first], vec![*last]),
            other => (other.to_vec(), Vec::new()),
        };
        let session = load_session(&model_dir.join("model.onnx"), intra_threads)?;
        Ok(Self {
            tokenizer,
            session,
            id2label,
            prefix,
            suffix,
            max_tokens,
        })
    }
}

/// Build an ONNX session with explicit, conservative threading.
///
/// # Errors
///
/// Returns a scrubbed message when the session builder, optimization level,
/// thread settings, or model load fails (a load-dynamic build without a
/// usable `ORT_DYLIB_PATH` lands here).
fn load_session(model_path: &Path, intra_threads: usize) -> Result<ort::session::Session, String> {
    use ort::session::builder::GraphOptimizationLevel;

    ort::session::Session::builder()
        .map_err(|_| "cannot create ONNX session builder".to_owned())?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(|_| "cannot set optimization level".to_owned())?
        .with_intra_threads(intra_threads.max(1))
        .map_err(|_| "cannot set intra-op thread count".to_owned())?
        .with_inter_threads(1)
        .map_err(|_| "cannot set inter-op thread count".to_owned())?
        .commit_from_file(model_path)
        .map_err(|_| "cannot load model.onnx; check ORT_DYLIB_PATH with load-dynamic".to_owned())
}

/// Load the real backend once, for the readiness probe.
///
/// # Errors
///
/// Returns [`DetectorError`] when the label map, tokenizer, or session cannot
/// be loaded; the message never carries model contents.
pub(crate) fn probe(model_dir: &Path, intra_threads: usize) -> Result<(), DetectorError> {
    let _labels = load_id2label(&model_dir.join("config.json"))?;
    let _tokenizer = tokenizers::Tokenizer::from_file(model_dir.join("tokenizer.json"))
        .map_err(|_| backend_error("cannot load tokenizer.json"))?;
    let _session = load_session(&model_dir.join("model.onnx"), intra_threads)
        .map_err(|reason| backend_error(&reason))?;
    Ok(())
}

/// Detect spans across every bounded window of `input`.
fn detect_with(loaded: &mut Loaded, input: &str) -> Result<Vec<RawSpan>, String> {
    let budget = loaded
        .max_tokens
        .saturating_sub(loaded.prefix.len() + loaded.suffix.len())
        .max(1);
    let byte_window = loaded
        .max_tokens
        .saturating_mul(BYTES_PER_TOKEN_BUDGET)
        .max(MIN_BYTE_WINDOW);
    let byte_overlap = byte_window / 8;
    let token_overlap = budget / 8;

    let mut spans = Vec::new();
    for (slice_start, slice_end) in byte_windows(input, byte_window, byte_overlap) {
        let slice = &input[slice_start..slice_end];
        // Special tokens are added per chunk below, so the slice is tokenized
        // without them and its offsets index the slice exactly.
        let encoding = loaded
            .tokenizer
            .encode(slice, false)
            .map_err(|_| "tokenization failed".to_owned())?;
        let ids: Vec<i64> = encoding.get_ids().iter().map(|id| i64::from(*id)).collect();
        let offsets = encoding.get_offsets();
        for (start, end) in token_windows(ids.len(), budget, token_overlap) {
            let mut chunk_ids =
                Vec::with_capacity(loaded.prefix.len() + (end - start) + loaded.suffix.len());
            chunk_ids.extend_from_slice(&loaded.prefix);
            chunk_ids.extend_from_slice(&ids[start..end]);
            chunk_ids.extend_from_slice(&loaded.suffix);
            let mut chunk_offsets: Vec<(usize, usize)> =
                vec![(0, 0); loaded.prefix.len() + (end - start) + loaded.suffix.len()];
            chunk_offsets[loaded.prefix.len()..loaded.prefix.len() + (end - start)]
                .copy_from_slice(&offsets[start..end]);
            let mut chunk_spans = run_chunk(loaded, chunk_ids, &chunk_offsets)?;
            for span in &mut chunk_spans {
                span.start += slice_start;
                span.end += slice_start;
            }
            spans.extend(chunk_spans);
        }
    }
    Ok(spans)
}

/// One inference call over one token window.
fn run_chunk(
    loaded: &mut Loaded,
    ids: Vec<i64>,
    offsets: &[(usize, usize)],
) -> Result<Vec<RawSpan>, String> {
    let seq_len = ids.len();
    let mask = vec![1_i64; seq_len];
    let id_value = ort::value::Value::from_array((vec![1_usize, seq_len], ids))
        .map_err(|_| "bad input tensor".to_owned())?;
    let mask_value = ort::value::Value::from_array((vec![1_usize, seq_len], mask))
        .map_err(|_| "bad attention-mask tensor".to_owned())?;
    let outputs = loaded
        .session
        .run(ort::inputs!["input_ids" => id_value, "attention_mask" => mask_value])
        .map_err(|_| "inference failed".to_owned())?;
    let Some((_name, value)) = outputs.into_iter().next() else {
        return Err("model returned no outputs".to_owned());
    };
    let (shape, flat) = value
        .try_extract_tensor::<f32>()
        .map_err(|_| "logits are not an f32 tensor".to_owned())?;
    let num_labels = loaded.id2label.len();
    if num_labels == 0 || !logits_shape_matches(shape, seq_len, num_labels) {
        return Err("unexpected logits shape".to_owned());
    }
    bio_decode(seq_len, num_labels, flat, offsets, &loaded.id2label)
        .map_err(|error| error.to_string())
}

/// Decode `[seq_len, num_labels]` logits with BIO tags into char spans.
///
/// Token offsets `(0, 0)` mark special tokens and are skipped. Scores use a
/// sigmoid of the winning logit as a bounded heuristic; a non-finite logit or
/// score is an error rather than a misleading confidence. Adjacent same-kind
/// `B-`/`I-` tags extend the open span — the recommended exports tag every
/// subtoken of a word with `B-`, and splitting those into fragments would
/// break entities apart. A span still open after the final non-special token
/// closes at that token's end, so entities running to the end of the input
/// survive the trailing `[SEP]` row.
fn bio_decode(
    seq_len: usize,
    num_labels: usize,
    flat: &[f32],
    offsets: &[(usize, usize)],
    id2label: &[String],
) -> Result<Vec<RawSpan>, DetectorError> {
    let seq_len = seq_len.min(offsets.len());
    if num_labels == 0 {
        return Ok(Vec::new());
    }
    if flat.len() < seq_len * num_labels {
        return Err(backend_error("logits shorter than the declared shape"));
    }
    let mut spans = Vec::new();
    let mut open: Option<(String, usize, f32)> = None;
    let mut last_end = 0;

    let close = |open: &mut Option<(String, usize, f32)>, spans: &mut Vec<RawSpan>, end: usize| {
        if let Some((label, start, score)) = open.take() {
            push_span(spans, label, start, end, score);
        }
    };

    for (index, (start, end)) in offsets.iter().copied().enumerate().take(seq_len) {
        if start >= end {
            continue;
        }
        last_end = end;
        let row = index * num_labels;
        let mut best = 0usize;
        for label in 1..num_labels {
            if flat[row + label] > flat[row + best] {
                best = label;
            }
        }
        let best_logit = flat[row + best];
        if !best_logit.is_finite() {
            return Err(backend_error("model produced non-finite logits"));
        }
        let score = 1.0 / (1.0 + (-best_logit).exp());
        if !score.is_finite() {
            return Err(backend_error("model produced a non-finite score"));
        }
        let Some(raw_label) = id2label.get(best).map(String::as_str) else {
            return Err(backend_error("model label count does not match id2label"));
        };
        let (prefix, name) = raw_label
            .split_once('-')
            .map_or(("O", raw_label), |(prefix, name)| (prefix, name));
        if prefix == "B" || prefix == "I" {
            match open.take() {
                Some((label, open_start, best_score)) if label == name => {
                    open = Some((label, open_start, best_score.max(score)));
                }
                Some((label, open_start, best_score)) => {
                    push_span(&mut spans, label, open_start, start, best_score);
                    open = Some((name.to_owned(), start, score));
                }
                None => open = Some((name.to_owned(), start, score)),
            }
        } else {
            close(&mut open, &mut spans, start);
        }
    }
    close(&mut open, &mut spans, last_end);
    Ok(spans)
}

fn push_span(spans: &mut Vec<RawSpan>, label: String, start: usize, end: usize, score: f32) {
    if end > start {
        spans.push(RawSpan {
            label,
            start,
            end,
            score,
        });
    }
}

#[cfg(test)]
mod tests;
