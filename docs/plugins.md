# Plugin model

The core does not know which detector, judge, policy, transformer, or vault is used.

| Capability | Contract | Initial plugin | Future replacements |
| --- | --- | --- | --- |
| detection | `Detector` | regex, `detector-gliner2` (local ONNX NER), `plugin-process` (`detect`) | custom local NER, rules |
| judging | `SemanticJudge` | `judge-heuristics` (local rules), `plugin-process` (`judge`) | local model, hosted judge via process |
| policy | `Policy` | default, `plugin-process` (`plan`) | project policy, enterprise DLP |
| transformation | `Transformer` | pseudonymize, `plugin-process` (`transform`) | redact, generalize, encrypt, format-preserving |
| storage | `Vault` | memory / JSON file, `plugin-process` (`vault_get_or_insert`, `vault_resolve`) | SQLite, OS keychain, encrypted local DB |

Implementations are selected by logical plugin name. Every capability can also run behind a process boundary: `crates/plugin-process` speaks newline-delimited JSON to a user-configured local executable (`docs/process-plugin.md`), so an implementation written in another language needs no Rust dynamic-library ABI. Compiled-in plugins remain the default; the process boundary is opt-in per capability (`--detector`/`--judge`/`--policy`/`--transformer`/`--vault process` with the matching `--*-command` flag). Semantic judging is optional and off by default: the judge is selected with `--judge heuristics` or `--judge process --judge-command <program>`, and the pipeline composes as `Detector -> SemanticJudge (optional) -> Policy -> Transformer -> Vault`.

Every selection can also come from `do-context-shield.toml` (`docs/configuration.md`); an explicit CLI flag overrides the file value.

## ONNX detector models

`--detector gliner2 --model-dir <dir>` runs a local ONNX export in-process: no Python, no network. Build the CLI with the backend enabled:

```bash
cargo build -p do-context-shield --features do-context-shield-detector-gliner2/gliner2
```

ONNX Runtime is loaded dynamically at run time: provide `libonnxruntime.so` on the loader path, or set `ORT_DYLIB_PATH` to one (an ONNX Runtime release archive or an installed `onnxruntime-node` package both ship a usable library).

### Supported export layout

`model_dir` must contain exactly:

- `model.onnx`: graph inputs `input_ids` and `attention_mask` (`int64`, batch 1), returning per-token logits shaped `[1, seq_len, num_labels]` as its first output and requiring no further inputs such as `token_type_ids`.
- `tokenizer.json`: tokenization adds the export's special tokens; their `(0, 0)` offsets are skipped while decoding.
- `config.json`: `id2label` defines the entity kinds. Tags are BIO (`B-`/`I-`/`O`) and are canonicalized to snake_case kinds (`B-first_name` → `first_name`). Without an `id2label` map the built-in 42-type GLiNER2-PII taxonomy (`PII_LABELS_42`) is assumed.

Adjacent same-kind tags merge into one span (word-level exports tag every subtoken with `B-`), scores are a sigmoid of the winning logit, and spans below the default 0.5 threshold or overlapping a longer span are dropped. `optimum-cli` token-classification exports of the models below match this layout.

Everything else fails closed with an error and zero entities — an unconfigured or missing `model_dir`, a missing model file, or a multi-fragment export (an `onnx/` directory, `encoder.onnx`, or `boundary_manifest.json`); detection never silently returns nothing.

### Recommended models

| Model | Params | ONNX fp32 | PII types | License | ONNX export |
| --- | ---: | ---: | ---: | --- | --- |
| `kalyan-ks/ettin-32m-nemotron-pii` | 32M | ~128 MB | 55 | MIT | `rulesentry-io/ettin-32m-nemotron-pii-onnx` |
| `kalyan-ks/ettin-68m-nemotron-pii` | 68M | ~274 MB | 55 | MIT | `rulesentry-io/ettin-68m-nemotron-pii-onnx` |

ModernBERT encoders fine-tuned on NVIDIA's synthetic Nemotron-PII dataset, tagged to complement deterministic rules: use them for linguistic PII (names, locations, demographics, dates, employment) and leave structured identifiers (SSN, cards, IPs, keys) to `detector-regex`, whose format matching is more reliable. English only.

```bash
repo=https://huggingface.co/rulesentry-io/ettin-32m-nemotron-pii-onnx/resolve/main
mkdir -p models/ettin-32m
curl -L -o models/ettin-32m/model.onnx     "$repo/model.onnx"
curl -L -o models/ettin-32m/tokenizer.json "$repo/tokenizer.json"
curl -L -o models/ettin-32m/config.json    "$repo/config.json"

printf 'Contact Jane Doe at jane@example.com.' |
  do-context-shield sanitize --detector gliner2 --model-dir models/ettin-32m
```

### Known-incompatible model families

- **GLiNER2-PII** (`fastino/gliner2-privacy-filter-PII-multi`): the model the built-in 42-type labels mirror, with the highest published span-level PII recall, but published as PyTorch weights; its community ONNX conversions are fragmented span-enumeration graphs (encoder/span_rep/scorer/classifier files, usually under `onnx/`) that this single-file backend rejects. Multi-fragment orchestration is the planned path to support it.
- **GLiNER2.5** (`fastino/gliner2.5-multi-v1`): boundary-prediction successor with no PII-specific checkpoint yet; its exports are detected as boundary/fragment layouts and rejected. Revisit when a PII checkpoint ships and the boundary decoding pipeline is implemented.
- **Laya** (`convaiinnovations/laya`): not a detector — it answers typed `choice`/`score`/`bool` questions and never returns spans. It belongs to the `SemanticJudge` stage as a process sidecar, not to this backend.
