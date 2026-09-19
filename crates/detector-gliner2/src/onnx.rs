//! Single-file token-classification ONNX backend, gated behind the `gliner2` feature.

use crate::RawSpan;
use do_context_shield_plugin_api::DetectorError;

/// Run a single-file token-classification ONNX model and BIO-decode logits.
///
/// Expected layout: `model.onnx`, `tokenizer.json`, `config.json` carrying an
/// `id2label` map.
pub(crate) fn detect(
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
    // Exported token-classification models expect their special tokens
    // (`[CLS]`/`[SEP]` and friends); omitting them shifts the encoder out of
    // its training distribution and produces misaligned spans. Special-token
    // offsets are `(0, 0)` and are skipped during decoding.
    let encoding = tokenizer
        .encode(input, true)
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
/// sigmoid of the winning logit as a bounded heuristic. Adjacent same-kind
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
) -> Vec<RawSpan> {
    let seq_len = seq_len.min(offsets.len());
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
    spans
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
mod tests {
    use super::bio_decode;

    fn labels() -> Vec<String> {
        ["B-name", "I-name", "B-city", "I-city", "O"]
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn spans(logits: &[f32], offsets: &[(usize, usize)]) -> Vec<(String, usize, usize)> {
        bio_decode(offsets.len(), 5, logits, offsets, &labels())
            .into_iter()
            .map(|span| (span.label, span.start, span.end))
            .collect()
    }

    #[test]
    fn closes_span_open_at_last_text_token_when_special_row_follows() {
        // [CLS](0,0) "John"(0,4) [SEP](0,0): the trailing special row is
        // skipped, so the open B-name span must close at end of input.
        let offsets = [(0, 0), (0, 4), (0, 0)];
        #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 9.0,
        ];
        assert_eq!(spans(&logits, &offsets), vec![("name".to_owned(), 0, 4)]);
    }

    #[test]
    fn special_and_o_rows_close_spans_without_shifting_alignment() {
        // [CLS](0,0) "John"(0,4) " Doe"(4,8) " "(8,9): a different kind closes
        // the first span and opens the second on the right offsets.
        let offsets = [(0, 0), (0, 4), (4, 8), (8, 9)];
        #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 9.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 9.0,
        ];
        assert_eq!(
            spans(&logits, &offsets),
            vec![("name".to_owned(), 0, 4), ("city".to_owned(), 4, 8)]
        );
    }

    #[test]
    fn merges_adjacent_tags_of_the_same_kind() {
        // Word-level exports repeat `B-` for every subtoken; fragments of one
        // entity must decode to a single span.
        let offsets = [(0, 0), (0, 4), (4, 8), (8, 12)];
        #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 9.0, 0.0, 0.0, 0.0,
        ];
        assert_eq!(spans(&logits, &offsets), vec![("name".to_owned(), 0, 12)]);
    }

    #[test]
    fn kind_change_on_i_tag_closes_the_open_span() {
        // B-name then I-city must emit the name span and start the city span;
        // dropping the open span would silently lose a detected entity.
        let offsets = [(0, 0), (0, 4), (4, 8)];
        #[rustfmt::skip]
        let logits = [
            0.0, 0.0, 0.0, 0.0, 9.0,
            9.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 9.0, 0.0,
        ];
        assert_eq!(
            spans(&logits, &offsets),
            vec![("name".to_owned(), 0, 4), ("city".to_owned(), 4, 8)]
        );
    }
}
