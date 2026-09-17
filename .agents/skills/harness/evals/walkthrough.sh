#!/usr/bin/env bash
# harness walkthrough: proves the structure gate accepts this skill and that the
# documented config -> list -> verify path works — hermetically inside the eval
# sandbox.
#
# The eval sandbox contains only this skill directory (plus skill-creator's
# scripts), so this walkthrough writes its own minimal config and never depends
# on mirrored repository files. Repo-path claims in the sensor map are checked
# by scripts/check-skills.sh, which runs against the real workspace.
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"
bin="${DO_HARNESS_BIN:-do-harness}"
receipt="$root/harness_receipt.txt"

python3 "$root/.agents/skills/skill-creator/scripts/quick_validate.py" \
  "$root/.agents/skills/harness" > "$root/harness_validate.txt"

cat > "$root/do-harness.toml" << 'TOML'
language = "generic"

[signal-sets]
verification = ["probe"]

[[sensors]]
name = "probe"
argv = ["true"]
TOML

"$bin" --root "$root" list > "$root/harness_sensors.txt"
grep -qx probe "$root/harness_sensors.txt"
"$bin" --root "$root" verify --set verification > "$root/harness_verify.txt"
grep -q 'All sensors passed' "$root/harness_verify.txt"

printf 'sensor contract: gate passes and CLI config->list->verify works\n' > "$receipt"

cat > "$root/harness_negative.txt" << 'TXT'
negative: general-knowledge question — no workspace touched, no sensors run
TXT
