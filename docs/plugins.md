# Plugin model

The core does not know which detector, judge, policy, transformer, or vault is used.

| Capability | Contract | Initial plugin | Future replacements |
| --- | --- | --- | --- |
| detection | `Detector` | regex, `detector-gliner2` (local ONNX NER), `detector-hybrid` (regex + model), `plugin-process` (`detect`) | custom local NER, rules |
| judging | `SemanticJudge` | `judge-heuristics` (local rules), `plugin-process` (`judge`) | local model, hosted judge via process |
| policy | `Policy` | default, matrix (opt-in jurisdiction adequacy + purpose mapping), `plugin-process` (`plan`) | project policy, enterprise DLP |
| transformation | `Transformer` | pseudonymize, generalize, mask, `plugin-process` (`transform`) | redact, encrypt, format-preserving |
| storage | `Vault` | memory, JSON file (`registry::json_vault(path, key_file)`, optionally encrypted at rest), `plugin-process` (`vault_get_or_insert`, `vault_resolve`) | SQLite, OS keychain, encrypted local DB |

Transformers decide how a pseudonymization target is replaced. `pseudonymize`
(the default) mints a stable, vault-resolvable token per value, so repeated
values keep their identity and `restore` can resolve them. `generalize`
replaces every value of a kind with one kind-only token
(`__DO_PRIVATE_EMAIL__`), and `mask` keeps only the last four characters
(`*************.com`); neither writes to the vault nor returns mappings, so
their output cannot be restored and equal values of one kind become
indistinguishable. Secrets are redacted under all three.

Implementations are selected by logical plugin name. The JSON vault is the one implementation whose name is not enough: it is file-backed, so it is built with `plugin_registry::json_vault(path, key_file)` from the resolved `vault_file`/`--vault-file` and the optional `vault_key_file`/`--vault-key-file` (calling `vault("json")` reports that argument requirement instead of an unknown plugin). Every capability can also run behind a process boundary: `crates/plugin-process` speaks newline-delimited JSON to a user-configured local executable (`docs/process-plugin.md`), so an implementation written in another language needs no Rust dynamic-library ABI. Compiled-in plugins remain the default; the process boundary is opt-in per capability (`--detector`/`--judge`/`--policy`/`--transformer`/`--vault process` with the matching `--*-command` flag, on the subcommands that expose that capability: `sanitize` and `mcp-stdio` carry the pipeline selection, `inspect` the detector, `restore`/`forget` the vault — `--process-timeout-ms` is available on all five). Semantic judging is optional and off by default: the judge is selected with `--judge heuristics` or `--judge process --judge-command <program>`, and the pipeline composes as `Detector -> SemanticJudge (optional) -> Policy -> Transformer -> Vault`.

Every selection can also come from `do-context-shield.toml` (`docs/configuration.md`); an explicit CLI flag overrides the file value. For `mcp-stdio` the file applies only through `--config <path>`: a project directory cannot configure the server that runs in it.

### Detector quality evaluation

The versioned, maintainer-authored synthetic corpus is
[`quality/corpus/v1.json`](../quality/corpus/v1.json); its schema, provenance,
span convention, and update rules are in [`quality/README.md`](../quality/README.md).
It contains no real PII or issued credentials. Annotation offsets are
zero-based, half-open Unicode scalar-value spans; the runner converts them to
UTF-8 byte spans before exact `(kind, span)` scoring.

Run the deterministic regex gate and print its structured JSON report:

```bash
cargo test -p do-context-shield --test detection_quality -- --nocapture
```

CI runs the same integration test with `cargo test --workspace --all-features`.
Only cases that list `regex` in `gate_modes` fail CI on a false positive or
false negative. The report still scores every corpus case and includes
aggregate and per-kind precision, recall, F1, TP/FP/FN counts, finding case IDs
and byte spans, corpus revision and SHA-256, detector version, and regex
pattern identity. It never prints source text or detected values. Non-gated
credential misses remain visible with `manual_review_priority: "credential"`.

GLiNER2 and hybrid reports are opt-in and use only an already-local ONNX export;
the runner never downloads a model. Set all three variables to run both model
modes (the test skips when the model directory is unset and fails on a partial
setup):

```bash
export ORT_DYLIB_PATH=/absolute/path/to/libonnxruntime.so
export DO_CONTEXT_SHIELD_QUALITY_MODEL_DIR=/absolute/path/to/local-model
export DO_CONTEXT_SHIELD_QUALITY_MODEL_VERSION='model-name@revision'
cargo test -p do-context-shield --features gliner2 \
  --test detection_quality -- --nocapture
```

Model reports include the supplied model version, tokenizer and model-config
SHA-256 identities (or the built-in fragment-export config identity), and the
effective runtime-config hash. The model path and corpus values are not
included.

Each configured model mode runs twice and must produce the same structured report for identical inputs.

Metrics describe this synthetic corpus, not production guarantees. Aggregate
scores can hide per-kind misses; inspect the per-kind counts and findings.
Credential false negatives require manual review. A score alone is not a reason
to change a detector pattern: review false positives and add a security
regression before any boundary change.

#### Seeded regex-pattern benchmark

The regex crate also carries a repeatable generated benchmark
(`crates/detector-regex/tests/quality`), built in-process from a fixed seed —
no fixture literals, no network, no model:

```bash
cargo test -p do-context-shield-detector-regex --test quality -- --nocapture
```

It measures three corpora and fails on any deviation:

- **generated** — every kind declared by the pattern table gets 25 values with
  the shape and checksum that kind requires (Luhn, ABA, IBAN mod-97, IPv6
  forms, PEM blocks, …), and each must be detected at its exact span with that
  kind (606/606 across 24 kinds today: 600 generated values plus six
  separator-tail boundary cases);
- **adversarial** — values shaped like a kind but invalid by its own rule
  (checksum, octet range, length) must not produce that kind;
- **benign** — prose, code, and numbers must produce no entities at all.

The kind list is read from `patterns.rs`, so a new spec that lacks a generator
fails the benchmark instead of passing silently. The credential patterns pin
the right edge without dropping secret material: a value ending in `-` stays
inside its declared alphabet, so the full value is reported — a floor-satisfying
`glpat-…-` is one complete secret span, not a trimmed one, and a value one
character below the floor followed by `-` is still detected instead of missed.
GitLab routable and versioned routable tokens (`glpat-<payload>.<routing>`) are
detected across their full span without swallowing prose sentence periods.
The exact-width Google-key pattern accepts every allowed word character at the
tail end, including `_`, next to its hyphen branch. The benchmark pins these
spans by generating word-final values, including separator tails (`-` and `_`)
for the token kinds whose alphabets admit them. Quoted generic secrets
(`password="pass phrase!"`) capture the full quoted literal including spaces,
punctuation, and closing quotes, while unquoted assignments preserve the
8-character floor and boundary.

## ONNX detector models

`--detector gliner2 --model-dir <dir>` runs a local ONNX export in-process: no Python, no network. Build the CLI with the backend enabled:

```bash
cargo build -p do-context-shield --features gliner2
```

ONNX Runtime is loaded dynamically at run time: provide `libonnxruntime.so` on the loader path, or set `ORT_DYLIB_PATH` to one (an ONNX Runtime release archive or an installed `onnxruntime-node` package both ship a usable library). The runtime must match the `ort` release the binary was built with — **1.28.x** for the current `ort 2.0.0-rc.13`. The official 1.28.0 archive is verified end-to-end with the recommended fragment export's `fp16_v2/` set at revision `e594898` (x64 Linux, 2026-09-20: `inspect`/`sanitize`, chunked and multibyte input):

```bash
curl -L -o ort.tgz https://github.com/microsoft/onnxruntime/releases/download/v1.28.0/onnxruntime-linux-x64-1.28.0.tgz
tar -xzf ort.tgz
export ORT_DYLIB_PATH="$PWD/onnxruntime-linux-x64-1.28.0/lib/libonnxruntime.so"
```

Model-backed end-to-end tests pick up a local export and runtime from the environment and skip with a note when either is unset: `cli_model_e2e` drives the CLI path, `mcp_model_e2e` the MCP stdio path with a config-selected hybrid detector.

```bash
ORT_DYLIB_PATH="$PWD/onnxruntime-linux-x64-1.28.0/lib/libonnxruntime.so" \
DO_CONTEXT_SHIELD_E2E_MODEL_DIR="$PWD/models/gliner2-pii" \
cargo test -p do-context-shield --features gliner2 --test cli_model_e2e --test mcp_model_e2e
```

CI provisions the same archive in the Linux `Test` job (cached per version) and sets `DO_HARNESS_REQUIRE_ORT=1`, which turns an unset `ORT_DYLIB_PATH` into a failure instead of a skip — so the runtime-backed tests (`incomplete_fragment_export_fails_closed` and friends) really run there, and a broken download or a version bump that forgets this pin is red rather than quietly skipped. Local runs keep skipping without the environment variable.

### Preflight (`doctor`)

Check that the selected detector is configured and loadable **before** routing
private text through it:

```bash
do-context-shield doctor --detector gliner2 --model-dir ~/.local/share/do-context-shield/gliner2-onnx
do-context-shield doctor --detector hybrid --model-dir ~/.local/share/do-context-shield/gliner2-onnx --format json
```

The probe is local-only: it never downloads a model or runtime, never prints
model contents or raw metadata, and never falls back to regex. It reports the
recognized layout, the effective `max_tokens`/`intra_threads`, and one stable
`reason_code`:

| `reason_code` | Meaning |
| --- | --- |
| `ready` | configured and loadable |
| `feature_disabled` | valid export, but the binary lacks the `gliner2` feature |
| `not_configured` | no `--model-dir` (or no `--detector-command` for a process detector) |
| `missing_model_dir` | the directory does not exist |
| `missing_model_file` | neither `model.onnx` nor an `encoder*.onnx` fragment set |
| `missing_tokenizer` | single-file export without `tokenizer.json` |
| `missing_labels` | `config.json` has no usable `id2label`, or no labels are configured |
| `unsupported_export` | a GLiNER2.5 boundary export |
| `incomplete_fragments` | the fragment set misses one of its seven files |
| `runtime_unavailable` | the ONNX Runtime or the model failed to load (check `ORT_DYLIB_PATH`) |

`doctor` exits 0 when the detector is ready and 1 when it is not; `--format json`
emits `{"detector", "available", "reason_code", "guidance", "layout",
"max_tokens", "intra_threads"}` for scripts. A `hybrid` selection reports
readiness through its GLiNER2 half: an unavailable model is an unavailable
hybrid, never a silent regex-only success. A `process` detector is
configuration-only — the probe checks that a command is configured and never
runs it.

Inference limits are explicit flags on `sanitize`, `inspect`, and `mcp-stdio`:
`--model-max-tokens <TOKENS>` (default 512) and `--model-threads <THREADS>`
(default 2). Longer input is scanned in overlapping windows — the backend never
silently truncates it — and the thread count is never derived from the machine
automatically.

The trade-off is deliberate: encoder attention cost grows faster than linearly
in the token window, so a large `max_tokens` raises the per-call memory and CPU
peak for every request, while a small one adds windows (and a little duplicated
inference in the overlap). 512 tokens keeps a single CPU call predictable on a
laptop, and reusing the loaded session removes the cold-start cost from every
call after the first. Raise the window only when a corpus regularly produces
entities longer than the overlap, and keep `--model-threads` low when the host
also runs the coding client. The model-backed tests
(`ORT_DYLIB_PATH` + `DO_CONTEXT_SHIELD_E2E_MODEL_DIR`) exercise warm reuse and
multi-window input on a real export; they skip when no local model is
configured.

### Supported export layouts

**Fragment sets (primary)** — GLiNER2 span exports: `model_dir` holds an `encoder*.onnx` fragment, either flat (`encoder.onnx`, `encoder_fp32.onnx`, `encoder_fp16.onnx`, plus the `_iobinding` variants, as `export_span_v3.py` produces them) or under the legacy `fp16_v2/`/`fp32_v2/` subfolders, together with the other seven fragments (`token_gather`, `span_rep`, `schema_gather`, `count_pred_argmax`, `count_lstm_fixed`, `scorer`, `classifier`) and the export's `tokenizer.json`. The `gliner2-rs` engine (local, Apache-2.0, same `ort` stack) runs the pipeline: label-conditioned schema handling, span enumeration, and count decoding are its job. The engine owns eight ONNX sessions and is hosted on a dedicated worker thread that starts on the first detection (`ort::Session` is not `Send`); the detector talks to it over a channel, so the sessions live as long as that thread, `gliner2_rs` initializes there, and dropping and reconstructing the detector loads them again. The detector feeds `Gliner2Config::labels` (default `PII_LABELS_42`) as the schema and maps the returned entities. The eight ONNX sessions load lazily on the first fragment detect (seconds cold on CPU) and stay cached for that thread's lifetime; long inputs are chunked by the engine (384-token windows, 64 overlapping).

**Single-file token-classification (lightweight alternative)** — `model_dir` contains exactly:

- `model.onnx`: graph inputs `input_ids` and `attention_mask` (`int64`, batch 1), returning per-token logits shaped `[1, seq_len, num_labels]` as its first output and requiring no further inputs such as `token_type_ids`.
- `tokenizer.json`: tokenization adds the export's special tokens; their `(0, 0)` offsets are skipped while decoding.
- `config.json`: `id2label` defines the entity kinds and is required for this layout — the map's keys are class indices, its values BIO tags (`B-`/`I-`/`O`), canonicalized to snake_case kinds (`B-first_name` → `first_name`). A missing `config.json`, invalid JSON, or a map without a single index/tag pair fails closed: decoding without tag names maps every token to `O`, which would report a clean scan instead of an error. (The `PII_LABELS_42` default covers the fragment layout above, where the labels are the schema.)

Adjacent same-kind tags merge into one span (word-level exports tag every subtoken with `B-`), scores are a sigmoid of the winning logit, and spans below the default 0.5 threshold or overlapping a longer span are dropped.

Everything else fails closed with an error and zero entities — an unconfigured or missing `model_dir`, a missing or incomplete model file set, or a `GLiNER2.5` boundary export (`boundary_manifest.json`); detection never silently returns nothing.

### Recommended models

| Model | Layout | Params | On-disk size | PII types | License | Export |
| --- | --- | ---: | ---: | ---: | --- | --- |
| `fastino/gliner2-privacy-filter-PII-multi` | fragment set | 300M | ~590 MB fp16 / ~1.2 GB fp32 | 42 | Apache-2.0 | `jugaadsrl/gliner2-privacy-filter-PII-multi-onnx` |
| `kalyan-ks/ettin-32m-nemotron-pii` | single file | 32M | ~128 MB | 55 | MIT | `rulesentry-io/ettin-32m-nemotron-pii-onnx` |
| `kalyan-ks/ettin-68m-nemotron-pii` | single file | 68M | ~274 MB | 55 | MIT | `rulesentry-io/ettin-68m-nemotron-pii-onnx` |

The fragment set is the primary choice: highest published span F1 on the [SPY benchmark](https://aclanthology.org/2025.naacl-srw.23/) with recall-first trade-offs (0.477 avg F1, 0.750/0.686 recall on the legal/medical splits), label-conditioned so custom schemas work without retraining, and multilingual (EN/FR/ES/DE/IT/PT/NL). The Ettin pair is the lightweight single-file alternative: ModernBERT encoders fine-tuned on NVIDIA's synthetic Nemotron-PII dataset, tagged to complement deterministic rules — use them for linguistic PII (names, locations, demographics, dates, employment) and leave structured identifiers (SSN, cards, IPs, keys) to `detector-regex`, whose format matching is more reliable. English only.

Fragment set (fp32 for CPU; `fp16_v2/` holds the same fragment names with an `_fp16` suffix):

```bash
# Pinned export revision: `main` moves, this hash does not.
rev=e594898629d452e8311796f5f329c7edbeda907c
repo=https://huggingface.co/jugaadsrl/gliner2-privacy-filter-PII-multi-onnx/resolve/$rev/fp32_v2
mkdir -p models/gliner2-pii/fp32_v2
for f in encoder_fp32.onnx token_gather_fp32.onnx span_rep_fp32.onnx \
         schema_gather_fp32.onnx count_pred_argmax_fp32.onnx \
         count_lstm_fixed_fp32.onnx scorer_fp32.onnx classifier_fp32.onnx tokenizer.json; do
  curl -L -o "models/gliner2-pii/fp32_v2/$f" "$repo/$f"
done

# Verify each file against the Hub's LFS object id (its sha256; needs jq):
curl -s "https://huggingface.co/api/models/jugaadsrl/gliner2-privacy-filter-PII-multi-onnx/tree/$rev/fp32_v2?recursive=1" \
  | jq -r '.[] | select(.lfs) | "\(.lfs.oid)  models/gliner2-pii/fp32_v2/\(.path | split("/")[-1])"' \
  | sha256sum -c -

printf 'Contact Jane Doe at jane@example.com.' |
  do-context-shield sanitize --session s1 --detector gliner2 --model-dir models/gliner2-pii
```

Single-file alternative:

```bash
# Pinned export revision, as above.
rev=a7564cc972723bd22ccb3c7a248aadb456adb267
repo=https://huggingface.co/rulesentry-io/ettin-32m-nemotron-pii-onnx/resolve/$rev
mkdir -p models/ettin-32m
curl -L -o models/ettin-32m/model.onnx     "$repo/model.onnx"
curl -L -o models/ettin-32m/tokenizer.json "$repo/tokenizer.json"
curl -L -o models/ettin-32m/config.json    "$repo/config.json"

printf 'Contact Jane Doe at jane@example.com.' |
  do-context-shield sanitize --session s1 --detector gliner2 --model-dir models/ettin-32m
```

### Hybrid detector (regex + model)

`--detector hybrid --model-dir <dir>` runs `detector-regex` and the GLiNER2 model over the same input and merges their entities: regex owns the structured identifiers (cards, SSNs, keys, tokens) and the model the linguistic PII (names, addresses, demographics). When the two disagree, regex wins: any model entity overlapping a regex entity is dropped before the pipeline's longest-span-wins pass, so a noisy model fragment can never displace — and fragment — an authoritative regex span. Overlaps among model entities themselves resolve in two stages before that merge: the `gliner2-rs` engine's own decoder suppresses overlapping candidates *within one label* (score-descending greedy NMS; `flat_ner` stays at its default, so different-label overlaps survive), and the detector's `decode_spans` then applies longest-span-wins across the surviving spans (equal lengths keep the earlier-returned span). The merged list is therefore stable before the pipeline's own dedup pass — the practical consequence being that two overlapping candidates of the *same* kind resolve by score, not by length. This is the recommended production stack — the [REDACT benchmark](https://arxiv.org/abs/2606.19881) shows rule-based detectors collapsing on high-sensitivity, non-verbatim PII while combining rules with a model lifts recall over either alone.

The hybrid fails closed when either half fails: a missing or unusable `model_dir` errors the call even when regex finds nothing, so "model not checked" can never look like "nothing sensitive found". It is selectable from the CLI (`--detector hybrid --model-dir <dir>`), the configuration file (`[plugins] detector = "hybrid"` with `model_dir`), and the MCP server's detector field; there is no process-plugin variant.

```bash
printf 'Contact Jane Doe in Boston: 123-45-6789' |
  do-context-shield sanitize --session s1 --detector hybrid --model-dir models/gliner2-pii
```

### Unsupported model families

- **GLiNER2.5** (`fastino/gliner2.5-multi-v1`): boundary-prediction successor with no PII-specific checkpoint yet; exports carrying a `boundary_manifest.json` — at the export root or in its `fp32_25/`/`fp16_25/` subfolders — are rejected with a specific error. Revisit when a PII checkpoint ships — `gliner25-rs` is the candidate engine.
- **Laya** (`convaiinnovations/laya`): not a detector — it answers typed `choice`/`score`/`bool` questions and never returns spans. It belongs to the `SemanticJudge` stage as a process sidecar, not to this backend.
