# Process plugin protocol

Status: implemented for all five capabilities (`crates/plugin-process`, registry name `process` per capability, CLI/MCP flags `--detector process`, `--judge process`, `--policy process`, `--transformer process`, `--vault process`).

Transport: newline-delimited JSON on the child's stdin/stdout. One child process is started per operation: the request is written as a single line, exactly one response line is read, and the child is terminated as soon as its answer has been read. A long-lived server mode is not part of this version.

Every method shares the same driver:

- One response line, capped at 8 MiB.
- `--process-timeout-ms` (default 30 000) bounds the wait for that line; the child is killed and reaped on timeout, on every other error path, and after it has answered.
- A non-zero exit fails even when a response line was printed.
- stderr is discarded and never logged, and error messages never echo input values. The pipeline additionally scrubs the input and detected values from any stage error text before it reaches a caller, so a backend cannot leak a value through an error.
- A command line is split on whitespace; quoting and shell expansion are not supported. Point the flag at a wrapper script for anything more elaborate. A missing or blank command fails at startup, not on the first call.

Common rules:

- `scope` is the caller's session scope string.
- `start` / `end` are UTF-8 byte offsets into the exact input named in the request; `start < end` is required and both offsets must fall on character boundaries.
- Kind labels are trimmed, lowercased, and have spaces replaced by underscores (`API Key` becomes `api_key`); the default policy matches kinds by lowercase substring.
- Placeholders must have the pipeline shape `__DO_PRIVATE_<INNER>__` with a non-empty ASCII alphanumeric/underscore `<INNER>`; anything else cannot be resolved by `restore`.

## detect

Request:

```json
{"method":"detect","input":"email alice@example.com"}
```

Response:

```json
{"entities":[{"kind":"email","start":6,"end":23,"value":"alice@example.com","confidence":0.99}]}
```

- `value` is optional and must equal `input[start..end]`; the pipeline always takes the value from the input, never from the child.
- `confidence` is optional, defaults to `1.0`, and must be within `0..=1`.
- Fails closed on an empty kind, an invalid span, a value mismatch, or an out-of-range confidence.
- Overlaps are resolved longest-span-wins; the first reported entity wins on identical spans.
- The pipeline re-validates every report (character boundaries, bounds, value equality, a non-empty kind, confidence in `0..=1`) and resolves overlaps before the judge, policy, and transformer run, so a misbehaving detector fails the call either way.

## judge

Request:

```json
{"method":"judge","input":"email alice@example.com","entities":[{"kind":"email","start":6,"end":23,"value":"alice@example.com","confidence":0.99}]}
```

Response:

```json
{"judgments":[{"index":0,"label":"business","confidence":0.95},{"index":1,"label":null}]}
```

- `label` is `personal`, `business`, `test`, or `secret`; a null or omitted `label` is an abstention, and so is a candidate the child did not mention (`{"judgments":[]}` abstains for every candidate). The policy falls back to the kind rules for abstentions and missing judgments.
- `confidence` must be within `0..=1` for a label and is omitted or ignored for abstentions.
- A judge classifies existing candidates only: it cannot invent spans or rewrite text, and the policy redacts secret-like kinds before any label is consulted, so a `test` label can never weaken redaction.
- Fails closed on an out-of-range or duplicate index, an unknown label name, a missing index, a confidence outside `0..=1`, a malformed response, or a non-zero exit.
- A hosted judge (e.g. TypeSafe) is a local wrapper executable implementing this method; the runtime crates stay network-free.

## plan

Request:

```json
{"method":"plan","recipient":"external","data_category":"personal","entities":[{"kind":"email","start":0,"end":5,"value":"alice","confidence":0.99}],"judgments":[{"index":0,"label":"business","confidence":0.95}]}
```

`recipient` is `local`, `trusted`, `external`, or `unknown`; `data_category` is `non_personal`, `personal`, or `special_category`. `purpose` and `jurisdiction` are top-level fields too and are omitted when unset. The pipeline defaults to `recipient: external` and `data_category: personal`, the same behavior as a policy that ignores the context.

`judgments` carries the semantic judge's decisions (empty when no judge is configured); an abstention appears as `{"index":0,"label":null}`.

Response:

```json
{"plan":[{"index":0,"action":"pseudonymize"}]}
```

- `action` is `keep`, `pseudonymize`, `redact`, `block`, or `review`. `pseudonymize` must stay reversible through the vault; `redact` means irreversible removal (a mask or any other literal is a redact). `block` rejects the entire input and `review` flags it for a human; the pipeline fails the call for either, before any transformation, until a review flow exists.
- Fails closed on an index that is repeated, out of range, or missing for any entity, and on an unknown action.

## transform

Request:

```json
{"method":"transform","scope":"s1","input":"alice@example.com","plan":[{"index":0,"kind":"email","start":0,"end":17,"value":"alice@example.com","action":"pseudonymize"}]}
```

Response:

```json
{"text":"__DO_PRIVATE_EMAIL_1__","mappings":[{"kind":"email","original":"alice@example.com","token":"__DO_PRIVATE_EMAIL_1__"}]}
```

The child may rewrite the text, but the pipeline enforces the plan and fails closed on any violation:

- every `keep` value must still appear in the returned `text`;
- every `pseudonymize` value must be gone and covered by exactly one mapping per distinct `(kind, value)`, and the mapping's token must appear in the `text`;
- every `redact` value must be gone and must not have a mapping;
- tokens must be unique and have the placeholder shape;
- every mapping must resolve through the configured vault (`vault_resolve`) to the same kind and original.

Text outside the planned entities is trusted: the checks above cover planned values and emitted placeholders, not the child's other edits. Placeholder tokens are matched by substring, not by offset.

Reversibility therefore depends on the configured vault: a process transformer must be paired with a vault that can resolve the tokens it emits — typically a process vault over the same store. The memory and JSON vaults can only resolve tokens they issued themselves, so those combinations fail with `which the configured vault cannot resolve`. `restore` works exactly for tokens the configured vault resolves.

## vault

Requests and responses:

```json
{"method":"vault_get_or_insert","scope":"s1","kind":"email","original":"alice"}
```

```json
{"token":"__DO_PRIVATE_EMAIL_1__"}
```

```json
{"method":"vault_resolve","scope":"s1","token":"__DO_PRIVATE_EMAIL_1__"}
```

```json
{"mapping":{"kind":"email","original":"alice","token":"__DO_PRIVATE_EMAIL_1__"}}
```

A miss is `{"mapping":null}`.

```json
{"method":"vault_delete_scope","scope":"s1"}
```

```json
{"deleted":true}
```

- The child owns the mapping store. The pipeline keeps no vault state and starts one child per operation, so token stability across calls is whatever that store provides; a stateless child re-issues tokens per call and breaks `restore`.
- `get_or_insert` must return a token `restore` can resolve, and `vault_resolve` hits must echo the requested token and carry kind and original.
- `vault_delete_scope` backs `forget` (MCP `context.forget`, CLI `forget`) and must answer `{"deleted":true}` after removing every mapping and counter for that scope; any other answer (including `{"deleted":false}`) fails the call closed. `expire` stays a no-op for a process vault — retention is the child's policy.

## Selection

```bash
FIX="python3 detector.py"
printf '%s' 'email alice@example.com' \
  | do-context-shield sanitize --session s1 \
      --detector process --detector-command "$FIX" \
      --judge process --judge-command "python3 judge.py" \
      --policy process --policy-command "python3 policy.py" \
      --transformer process --transformer-command "python3 transformer.py" \
      --vault process --vault-command "python3 vault.py" \
      --process-timeout-ms 60000
```

`mcp-stdio` takes the same flags. Each capability is selected independently, so a process detector can run next to the built-in policy, transformer, and vault, and `restore` accepts the same `--vault`/`--vault-command` flags as `sanitize`.

The same contract can carry future capabilities. A Python CPU model, a Rust model, or another executable can therefore replace an implementation without changing `do-context-shield-core`.

## Local-model judge example (Laya)

[Laya](https://huggingface.co/convaiinnovations/laya) is a local calibrated decision model: given a state and typed `choice`/`score` questions, it returns answers with probabilities in a single forward pass (33 ms) and never generates text, so nothing needs parsing — exactly the judge contract above. `examples/laya-judge.py` implements the method in one stdlib-only file: one `choice` question per detected candidate with the criteria `personal`/`business`/`test`/`secret`/`none`, answered as one judgment line. Spans, policy, transformation, and restoration stay with the deterministic pipeline; a model failure or malformed answer fails the call closed, and an abstention falls back to the policy's kind rules.

Why this pairing (September 2026): hybrid detection is the converged best practice — the [REDACT benchmark](https://arxiv.org/abs/2606.19881) shows rule-based detectors collapsing on high-sensitivity, non-verbatim PII (Presidio HIGH-sensitivity recall 0.07, macro-F1 0.063) while model detectors hold up, and regex plus model lifts recall over either alone, so `detector-regex` (default) with a GLiNER2 model (opt-in, `docs/plugins.md`) is the recommended detector stack; sending raw PII to a hosted LLM "to redact it" means the provider sees the value before any redaction; and GLiNER2-PII (`fastino/gliner2-privacy-filter-PII-multi`) reports the highest span F1 on the [SPY benchmark](https://aclanthology.org/2025.naacl-srw.23/) (0.477 avg, best recall of the compared systems at 0.718 avg) with the 42-type taxonomy already in `PII_LABELS_42`. Laya is the optional judge on top — zero-shot it is near chance on typed decisions (0.362 accuracy against a 0.461 majority-class baseline; only the fine-tuned `typed-decisions` checkpoint reaches 0.766), so validate a checkpoint on your own data before trusting its keep decisions.

Setup: `pip install laya` (torch/transformers; no TensorFlow). Environment: `LAYA_MODEL` (default `convaiinnovations/laya`) and `LAYA_SUBFOLDER` — recommended `typed-decisions`, which downloads that one checkpoint (~0.8 GB); without a subfolder the whole multi-checkpoint repo is fetched (~2.2 GB: 803 MB root weights + `multilingual/` + `typed-decisions/` + `eval/`). A cold checkpoint build costs seconds (7.4 s median on CPU) and one child is started per operation, so raise the timeout:

```bash
do-context-shield sanitize --session work-1 \
    --detector gliner2 --model-dir <dir> \
    --judge process --judge-command "python3 examples/laya-judge.py" \
    --process-timeout-ms 120000
```

The `gliner2` pairing needs a binary built with the `gliner2` Cargo feature (`docs/plugins.md`); `--detector regex --judge process --judge-command "python3 examples/laya-judge.py"` works in every build.

Offline checks need no model: `python3 examples/laya-judge.py --self-test` runs canned assertions, and `--stub` swaps in a deterministic agent (reserved domains → `test`, role addresses → `business`, otherwise abstain) for local smoke tests and CI:

```bash
printf '%s' 'meet alice@personalmail.net' \
  | do-context-shield sanitize --session s1 \
      --judge process --judge-command "python3 examples/laya-judge.py --stub"
# -> meet __DO_PRIVATE_EMAIL_1__
```

Trust and quality notes: the sidecar sees raw candidate values by design (same as `judge-heuristics`), so point `LAYA_MODEL` only at a local, trusted checkpoint — inference is offline CPU. The model card warns that Laya ships over-confident (mean ECE 0.466; refitting temperatures on your own data brings it to 0.081) and that `choice` questions should stay under ~20 options (five criteria here). The policy keeps `test`/`business` values at ≥ 0.90 confidence, so treat keep decisions as provisional until the checkpoint is validated on your data. With an older `transformers` plus TensorFlow installed in the same environment, its import-time probe can deadlock — run with `USE_TF=0` in that case.
