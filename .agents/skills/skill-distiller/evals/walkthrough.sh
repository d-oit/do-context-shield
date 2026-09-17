#!/usr/bin/env bash
# skill-distiller walkthrough: records a resolved trace, records an ok sensor
# beat (the evidence gate distill enforces), and proves distill produces a plan
# from that trace — hermetically inside the eval sandbox.
#
# The sandbox does not mirror do-harness.toml, so a minimal generic config with
# one trivially passing sensor stands in for the real suite.
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"
bin="${DO_HARNESS_BIN:-do-harness}"
cd "$root"

cat > "$root/do-harness.toml" << 'TOML'
language = "generic"

[signal-sets]
verification = ["probe"]

[[sensors]]
name = "probe"
argv = ["true"]
TOML

"$bin" --root "$root" trace add \
  --session distill-walkthrough \
  --command "cargo clippy --workspace --all-targets" \
  --error-diff "clippy::unwrap_used" \
  --resolution-steps "propagated a typed error" \
  > "$root/distill_trace.txt"
"$bin" --root "$root" trace list --session distill-walkthrough > "$root/distill_traces.txt"
grep -q 'distill-walkthrough' "$root/distill_traces.txt"

"$bin" --root "$root" verify --record --only probe > "$root/distill_verify.txt"
"$bin" --root "$root" distill \
  --skill skill-distiller \
  --pattern "walkthrough probe pattern" \
  --description "hermetic probe" \
  --from-trace 1 \
  --dry-run > "$root/distill_out.txt"
grep -q 'would distill heuristic for skill-distiller' "$root/distill_out.txt"

printf 'trace recorded and distill plan produced\n' > "$root/distill_receipt.txt"
