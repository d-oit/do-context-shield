//! Multi-fragment `GLiNER2` span-export backend, gated behind the `gliner2`
//! feature and powered by [`gliner2_rs`].
//!
//! `GLiNER2` span checkpoints export as one encoder plus seven small fragments
//! (`token_gather`, `span_rep`, `schema_gather`, `count_pred_argmax`,
//! `count_lstm_fixed`, `scorer`, `classifier`), flat (`export_span_v3.py`) or
//! under the legacy `fp16_v2/` / `fp32_v2/` subfolders published on the Hub.
//! Label-conditioned schema handling, span enumeration, and count decoding
//! live in `gliner2-rs`; this module owns the worker that hosts the engine,
//! the detector-facing error surface, and the mapping into [`RawSpan`]s.

use crate::RawSpan;
use do_context_shield_plugin_api::DetectorError;
use gliner2_rs::chunker::Chunker;
use gliner2_rs::{InferenceParams, SchemaTask, SpanConfig, SpanEngine};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};

/// The fragment engine, hosted on a dedicated worker thread.
///
/// `ort::Session` is not `Send` in `ort` rc.13, so the eight sessions cannot
/// sit behind a mutex inside the `Sync` detector. A worker thread owns them
/// instead: [`FragmentEngine::extract`] sends one request over a channel and
/// waits for the spans. The export loads once per worker, on the thread that
/// runs inference; dropping the detector shuts the worker down.
pub(crate) struct FragmentEngine {
    worker: Option<Worker>,
}

struct Worker {
    requests: Sender<Request>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        drop(self.requests.send(Request::Shutdown));
    }
}

enum Request {
    Extract {
        labels: Vec<String>,
        threshold: f32,
        input: String,
        reply: Sender<Result<Vec<RawSpan>, String>>,
    },
    Shutdown,
}

impl FragmentEngine {
    pub(crate) fn new() -> Self {
        Self { worker: None }
    }

    /// Extract spans from `input` for the requested `labels`.
    ///
    /// # Errors
    ///
    /// Returns [`DetectorError`] when the worker cannot start, the export
    /// cannot be loaded, or inference fails; the error text names the failure
    /// class but never the input.
    pub(crate) fn extract(
        &mut self,
        models_dir: &Path,
        intra_threads: usize,
        labels: &[String],
        threshold: f32,
        input: &str,
    ) -> Result<Vec<RawSpan>, DetectorError> {
        if self.worker.is_none() {
            self.worker = Some(Worker::spawn(models_dir.to_path_buf(), intra_threads)?);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or_else(|| engine_error("worker unavailable"))?;
        let (reply, answer) = channel();
        worker
            .requests
            .send(Request::Extract {
                labels: labels.to_vec(),
                threshold,
                input: input.to_owned(),
                reply,
            })
            .map_err(|_| engine_error("engine thread stopped"))?;
        answer
            .recv()
            .map_err(|_| engine_error("engine thread stopped before answering"))?
            .map_err(|reason| engine_error(&reason))
    }
}

impl Worker {
    fn spawn(models_dir: PathBuf, intra_threads: usize) -> Result<Self, DetectorError> {
        let (requests, incoming) = channel();
        std::thread::Builder::new()
            .name("gliner2-fragments".to_owned())
            .spawn(move || serve(&incoming, &models_dir, intra_threads))
            .map_err(|error| engine_error(&format!("cannot start engine thread ({error})")))?;
        Ok(Self { requests })
    }
}

/// Worker loop: load the engine on first use, answer extract requests.
fn serve(incoming: &Receiver<Request>, models_dir: &Path, intra_threads: usize) {
    let mut engine: Option<SpanEngine> = None;
    while let Ok(request) = incoming.recv() {
        match request {
            Request::Extract {
                labels,
                threshold,
                input,
                reply,
            } => {
                let result = loaded(&mut engine, models_dir, intra_threads)
                    .and_then(|engine| extract_spans(engine, &labels, threshold, &input));
                drop(reply.send(result));
            }
            Request::Shutdown => break,
        }
    }
}

/// The engine, built on the worker thread the first time it is needed.
fn loaded<'a>(
    engine: &'a mut Option<SpanEngine>,
    models_dir: &Path,
    intra_threads: usize,
) -> Result<&'a mut SpanEngine, String> {
    if engine.is_none() {
        gliner2_rs::init("do-context-shield");
        let config = SpanConfig::new(models_dir).with_intra_threads(intra_threads);
        let built =
            SpanEngine::new(config).map_err(|error| format!("cannot load export ({error})"))?;
        *engine = Some(built);
    }
    engine
        .as_mut()
        .ok_or_else(|| "engine unavailable".to_owned())
}

/// One batched extraction; entities map 1:1 onto [`RawSpan`]s.
fn extract_spans(
    engine: &mut SpanEngine,
    labels: &[String],
    threshold: f32,
    input: &str,
) -> Result<Vec<RawSpan>, String> {
    let tasks = vec![SchemaTask::Entities(labels.to_vec())];
    let params = InferenceParams {
        threshold,
        ..InferenceParams::default()
    };
    let output = engine
        .extract_long_with(input, &tasks, &params, Chunker::default())
        .map_err(|error| format!("inference failed ({error})"))?;
    Ok(output
        .entities
        .into_iter()
        .map(|entity| RawSpan {
            label: entity.label,
            start: entity.char_start,
            end: entity.char_end,
            score: entity.score,
        })
        .collect())
}

fn engine_error(reason: &str) -> DetectorError {
    DetectorError::Message(format!("gliner2 fragment backend: {reason}"))
}

#[cfg(test)]
mod tests {
    //! Worker-lifecycle tests. None of them trigger the engine load, so the
    //! ONNX runtime is never required: only the first `Extract` request calls
    //! `gliner2_rs::init`, and these tests stop before that.

    use super::*;
    use std::time::Duration;

    #[test]
    fn worker_shutdown_on_drop_exits_the_serve_loop() {
        let (requests, incoming) = channel();
        let (stopped, confirmation) = channel();
        let thread = std::thread::spawn(move || {
            serve(&incoming, Path::new("/nonexistent-gliner2-model"), 1);
            let _ = stopped.send(());
        });
        drop(Worker { requests });
        match confirmation.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => {}
            Err(error) => panic!("serve loop did not stop after worker drop: {error}"),
        }
        match thread.join() {
            Ok(()) => {}
            Err(payload) => panic!("serve thread panicked: {payload:?}"),
        }
    }

    #[test]
    fn engine_thread_stopped_surfaces_error() {
        // A worker whose receiver is already gone: the send must fail with the
        // closed-channel error, never hang or panic.
        let (requests, incoming) = channel::<Request>();
        drop(incoming);
        let mut engine = FragmentEngine {
            worker: Some(Worker { requests }),
        };
        match engine.extract(Path::new("/nonexistent-gliner2-model"), 1, &[], 0.0, "text") {
            Ok(spans) => panic!("expected a closed-channel error, got {spans:?}"),
            Err(error) => {
                let text = error.to_string();
                assert!(text.contains("engine thread stopped"), "{text}");
            }
        }
    }
}
