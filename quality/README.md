# Detection-quality corpus

`corpus/v1.json` is a versioned, maintainer-authored synthetic evaluation corpus.
It is released under CC0-1.0. No external dataset, real person, customer record,
issued credential, or production secret is included. Email domains use
`example.com`; database credentials and hosts are fake and use `example.test`;
account-shaped values and government identifiers are explicit test-only
placeholders.

## Annotation contract

- `schema_version` describes the JSON shape; `revision` identifies the corpus
  contents. Change the revision when changing examples, annotations, or gates.
- `start_char` and `end_char` are zero-based, half-open Unicode scalar-value
  offsets. The runner converts them to UTF-8 byte offsets before comparing
  detector spans.
- `surface` lets corpus validation reject stale or off-by-one annotations. It
  is never included in the generated report.
- `modes` selects expected labels for `regex`, `gliner2`, and `hybrid` runs.
  Matching requires the exact entity kind and byte span; duplicate predictions
  count as false positives.
- `gate_modes` selects modes whose case-level false positives or false
  negatives fail CI. The checked-in corpus gates deterministic regex cases;
  model-only categories and known boundary gaps still contribute findings and
  metrics but are not silently treated as regression-free.
- `manual_review_priority` marks sensitive misses, especially credential
  false negatives, for review.

## Running and reading reports

The CI-gated regex report is produced by:

```bash
cargo test -p do-context-shield --test detection_quality -- --nocapture
```

CI runs this integration test as part of `cargo test --workspace --all-features`.
It prints a structured JSON report prefixed by `DETECTION_QUALITY_REPORT`.
Aggregate and per-kind precision, recall, and F1 are computed from summed
true-positive, false-positive, and false-negative counts (micro-averaging).
Undefined ratios are JSON `null`. Findings contain only case IDs, categories,
entity kinds, UTF-8 byte spans, and review priorities; the report contains no
case text or entity values. Corpus revision and SHA-256 plus detector and regex
pattern identities make a report traceable to its inputs.

A local GLiNER2 and hybrid report is opt-in. It requires an existing local ONNX
model, its matching ONNX Runtime library, and an explicit model version; no
model is discovered or downloaded:

```bash
export ORT_DYLIB_PATH=/absolute/path/to/libonnxruntime.so
export DO_CONTEXT_SHIELD_QUALITY_MODEL_DIR=/absolute/path/to/local-model
export DO_CONTEXT_SHIELD_QUALITY_MODEL_VERSION='model-name@revision'
cargo test -p do-context-shield --features gliner2 \
  --test detection_quality -- --nocapture
```

The model report identifies the supplied model version, tokenizer SHA-256,
`config.json` SHA-256 (or the built-in GLiNER2 fragment config identity), and
runtime-config SHA-256. It does not include the local model path. With the model
directory unset, the model test skips; an incomplete explicit setup fails.
Each configured model mode runs twice and must produce the same structured report for identical inputs.

## Interpretation and updates

These scores describe this synthetic corpus, not production detection
reliability or privacy guarantees. Aggregate scores can conceal per-kind
failures. Review false positives and false negatives individually; credential
false negatives require manual review. Do not change detector patterns solely
to increase a score. Any boundary change needs false-positive review and a
security regression.

When updating the corpus, keep all examples synthetic, verify every declared
surface against its Unicode-scalar span, add both positive and negative cases
for the boundary under review, and explicitly choose whether that case is a CI
gate. Bump `revision`, review the report for new false positives and false
negatives, and never add real PII or usable credentials.
