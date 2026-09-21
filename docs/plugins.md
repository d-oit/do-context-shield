# Plugin model

The core does not know which detector, judge, policy, transformer, or vault is used.

| Capability | Contract | Initial plugin | Future replacements |
| --- | --- | --- | --- |
| detection | `Detector` | regex, `detector-gliner2` (local ONNX NER), `detector-hybrid` (regex + model), `plugin-process` (`detect`) | custom local NER, rules |
| judging | `SemanticJudge` | `judge-heuristics` (local rules), `plugin-process` (`judge`) | local model, hosted judge via process |
| policy | `Policy` | default, `plugin-process` (`plan`) | project policy, enterprise DLP |
| transformation | `Transformer` | pseudonymize, `plugin-process` (`transform`) | redact, generalize, encrypt, format-preserving |
| storage | `Vault` | memory / JSON file, `plugin-process` (`vault_get_or_insert`, `vault_resolve`) | SQLite, OS keychain, encrypted local DB |

Implementations are selected by logical plugin name. Every capability can also run behind a process boundary: `crates/plugin-process` speaks newline-delimited JSON to a user-configured local executable (`docs/process-plugin.md`), so an implementation written in another language needs no Rust dynamic-library ABI. Compiled-in plugins remain the default; the process boundary is opt-in per capability (`--detector`/`--judge`/`--policy`/`--transformer`/`--vault process` with the matching `--*-command` flag). Semantic judging is optional and off by default: the judge is selected with `--judge heuristics` or `--judge process --judge-command <program>`, and the pipeline composes as `Detector -> SemanticJudge (optional) -> Policy -> Transformer -> Vault`.

Every selection can also come from `do-context-shield.toml` (`docs/configuration.md`); an explicit CLI flag overrides the file value.

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

### Supported export layouts

**Fragment sets (primary)** — GLiNER2 span exports: `model_dir` holds an `encoder*.onnx` fragment, either flat (`encoder.onnx`, `encoder_fp32.onnx`, `encoder_fp16.onnx`, plus the `_iobinding` variants, as `export_span_v3.py` produces them) or under the legacy `fp16_v2/`/`fp32_v2/` subfolders, together with the other seven fragments (`token_gather`, `span_rep`, `schema_gather`, `count_pred_argmax`, `count_lstm_fixed`, `scorer`, `classifier`) and the export's `tokenizer.json`. The `gliner2-rs` engine (local, Apache-2.0, same `ort` stack) runs the pipeline: label-conditioned schema handling, span enumeration, and count decoding are its job. The detector feeds `Gliner2Config::labels` (default `PII_LABELS_42`) as the schema and maps the returned entities. The eight ONNX sessions load lazily on the first fragment detect (seconds cold on CPU) and stay cached for the detector's lifetime; long inputs are chunked by the engine (384-token windows, 64 overlapping).

**Single-file token-classification (lightweight alternative)** — `model_dir` contains exactly:

- `model.onnx`: graph inputs `input_ids` and `attention_mask` (`int64`, batch 1), returning per-token logits shaped `[1, seq_len, num_labels]` as its first output and requiring no further inputs such as `token_type_ids`.
- `tokenizer.json`: tokenization adds the export's special tokens; their `(0, 0)` offsets are skipped while decoding.
- `config.json`: `id2label` defines the entity kinds. Tags are BIO (`B-`/`I-`/`O`) and are canonicalized to snake_case kinds (`B-first_name` → `first_name`). Without an `id2label` map the built-in 42-type GLiNER2-PII taxonomy (`PII_LABELS_42`) is assumed.

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

`--detector hybrid --model-dir <dir>` runs `detector-regex` and the GLiNER2 model over the same input and merges their entities: regex owns the structured identifiers (cards, SSNs, keys, tokens) and the model the linguistic PII (names, addresses, demographics). When the two disagree, regex wins: any model entity overlapping a regex entity is dropped before the pipeline's longest-span-wins pass, so a noisy model fragment can never displace — and fragment — an authoritative regex span. Overlaps among model entities themselves resolve longest-span-wins too (equal lengths keep the earlier-returned span), so the merged list is stable before the pipeline's own dedup pass. This is the recommended production stack — the [REDACT benchmark](https://arxiv.org/abs/2606.19881) shows rule-based detectors collapsing on high-sensitivity, non-verbatim PII while combining rules with a model lifts recall over either alone.

The hybrid fails closed when either half fails: a missing or unusable `model_dir` errors the call even when regex finds nothing, so "model not checked" can never look like "nothing sensitive found". It is selectable from the CLI (`--detector hybrid --model-dir <dir>`), the configuration file (`[plugins] detector = "hybrid"` with `model_dir`), and the MCP server's detector field; there is no process-plugin variant.

```bash
printf 'Contact Jane Doe in Boston: 123-45-6789' |
  do-context-shield sanitize --session s1 --detector hybrid --model-dir models/gliner2-pii
```

### Unsupported model families

- **GLiNER2.5** (`fastino/gliner2.5-multi-v1`): boundary-prediction successor with no PII-specific checkpoint yet; exports carrying a `boundary_manifest.json` are rejected with a specific error. Revisit when a PII checkpoint ships — `gliner25-rs` is the candidate engine.
- **Laya** (`convaiinnovations/laya`): not a detector — it answers typed `choice`/`score`/`bool` questions and never returns spans. It belongs to the `SemanticJudge` stage as a process sidecar, not to this backend.
