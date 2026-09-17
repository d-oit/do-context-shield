#!/usr/bin/env bash
# spike-runner walkthrough: proves the trace workflow records and lists
# findings, hermetically inside the eval sandbox.
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"
bin="${DO_HARNESS_BIN:-do-harness}"
cd "$root"

"$bin" --root "$root" trace add \
  --session spike-walkthrough \
  --command "cargo test -p do-context-shield-plugin-process" \
  --error-diff "E0425 cannot find value" \
  --resolution-steps "propagated a typed error instead of unwrap" \
  > "$root/spike_trace.txt"
"$bin" --root "$root" trace list --session spike-walkthrough > "$root/spike_traces.txt"
grep -q 'spike-walkthrough' "$root/spike_traces.txt"

printf 'trace recorded and listed\n' > "$root/spike_receipt.txt"
