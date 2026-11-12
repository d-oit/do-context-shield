# Reproducible performance benchmarks

The isolated, unpublished `do-context-shield-benchmarks` package measures the
pipeline's local stages with Criterion. It adds no runtime dependencies to the
product crates. Every fixture is generated in `crates/benchmarks/src/corpus.rs`
from fixed templates and indexes; the corpus revision (`synthetic-v1`), exact
UTF-8 byte lengths, entity counts, Rust compiler version, OS, architecture,
logical CPU count, and (when available) Linux CPU model are printed before the
measurements. The benchmark output contains no original user data, credentials,
or model contents.

## Coverage

| Criterion group | Measurement |
| --- | --- |
| `detection` | Regex detection and real regex-primary/regex-secondary hybrid merge over small (about 4 KiB), medium (64 KiB), large (512 KiB), and bounded adversarial (about 64 KiB) inputs. The adversarial case contains repeated near-miss credential, IPv4, and checksum-shaped values. |
| `policy-plan` | Default policy planning over the same synthetic entity counts. |
| `transformation` | Pseudonymization with a persistent in-memory vault and irreversible masking over the same input sizes. |
| `vault` | Repeated memory and local JSON vault get-or-insert and resolve operations on one synthetic mapping. The JSON vault uses a temporary directory that is removed after the benchmark process exits. |
| `process-plugin-detect-clean` | One child process spawn plus the process plugin's NDJSON request/response and validation path over all four input sizes. The response is empty; the checked-in test fixture contains no sensitive data. This measures the complete `sh` + process-driver overhead, not an isolated syscall cost. |
| `local-gliner2` (optional) | First-detect cold load, warm inference, and warm regex+GLiNER2 hybrid inference over all four input sizes, using the explicitly supplied local export and ONNX Runtime. |

Regex and hybrid are warmed by Criterion before measurement; regex's lazy
pattern compilation is process-global and is intentionally not labeled a
repeatable cold-start result. The GLiNER2 cold measurement constructs a fresh
detector and includes its first `detect` call, which loads the model. Warm
measurements reuse one already-loaded detector. Policy, transformation, and
vault operations are direct stage measurements; they do not include pipeline
validation unless the stage itself performs it. Vault benchmarks intentionally
reuse one mapping, avoiding unbounded fixture growth across Criterion samples.

## Deterministic benchmarks

Run from the repository root, with the repository's Rust toolchain installed:

```sh
cargo bench -p do-context-shield-benchmarks
```

Criterion HTML reports and raw estimates are written under
`target/criterion/`. Capture a named baseline:

```sh
cargo bench -p do-context-shield-benchmarks -- --save-baseline local-baseline
```

After changing code or switching revisions in the same checkout/target
(directory), compare against it:

```sh
cargo bench -p do-context-shield-benchmarks -- --baseline local-baseline
```

To refresh rather than compare, repeat the save command with the same baseline
name. Criterion's report includes estimates and confidence intervals; review the
full output and reports instead of treating a single run as conclusive. For a
focused group or case, append Criterion's filter after `--`, for example:

```sh
cargo bench -p do-context-shield-benchmarks -- detection/regex/small
```

For best repeatability, use the same machine, power mode, OS, Rust toolchain,
compiler flags, and otherwise-idle system. The metadata line records compiler,
platform, logical thread count, and corpus details; Linux runs also report the
CPU model. Keep the same `target/criterion` baseline directory when comparing.
Criterion reports distributions and confidence intervals; no CI timing
thresholds or pass/fail performance assertions are configured.

## Resource notes

Criterion reports latency estimates, sample distributions, and throughput; it
does not collect peak RSS, allocation counts, or per-stage memory profiles.
Inputs and plans are prepared outside timed loops except for the documented
GLiNER2 cold-load case. The process-plugin measurement includes child startup,
serialization, and validation; the JSON vault uses a temporary directory and
reuses one mapping. Use an external profiler for memory comparisons and record
its version and settings separately. No profiler output or model contents are
included in benchmark reports.

## Manual CI baseline workflow

The repository's **Performance benchmarks** workflow is dispatched manually
from GitHub Actions. Select `save` to run the deterministic suite and upload the
Criterion baseline artifact named `criterion-baseline`. To compare another
revision, dispatch the workflow again with `compare` and the run ID of that
baseline-producing run; the workflow restores the artifact and invokes
Criterion's `--baseline manual` comparison. The current comparison output is
uploaded as `criterion-comparison`. This workflow reports measurements only:
it has no timing threshold and does not fail based on a regression percentage.

The workflow runs on a shared hosted runner, so its measurements are useful for
rough comparisons rather than stable hardware-level claims. For higher-quality
comparisons, use the local procedure above on the same otherwise-idle machine.


## Optional local GLiNER2 benchmarks

The GLiNER2 target is build-time opt-in and never downloads a model or runtime.
The target is omitted unless the `gliner2` package feature is explicitly
requested. At runtime, set `DO_CONTEXT_SHIELD_BENCH_MODEL_DIR` to a supported
local export directory, `DO_CONTEXT_SHIELD_BENCH_MODEL_ID` to the exact stable
model/revision identity for that export (for example `org/model@revision`), and
`ORT_DYLIB_PATH` to the local ONNX Runtime shared library (see [plugin setup](plugins.md#onnx-detector-models)). For example:

```sh
DO_CONTEXT_SHIELD_BENCH_MODEL_DIR=/models/gliner2-pii \
DO_CONTEXT_SHIELD_BENCH_MODEL_ID=org/model@revision \
ORT_DYLIB_PATH=/usr/lib/libonnxruntime.so \
cargo bench -p do-context-shield-benchmarks --features gliner2 --bench gliner2
```

The explicit model path is checked by the detector's network-free readiness
probe before timing begins. The caller-supplied model identity is required and
is printed with the detected export layout, maximum token count, and ONNX
intra-op thread count. It is not derived from or verified against model
contents, so provide an immutable revision that identifies the exact local
artifact; do not use credentials or private URLs as the identity. If the
model-directory variable is absent, the optional target prints `SKIP` and
registers no model benchmarks. If it is set but the identity, directory,
export, ONNX Runtime path, or runtime is unavailable, the run stops with a
clear configuration error. No model file contents are read for reporting.
Never put private or production text in benchmark inputs.
