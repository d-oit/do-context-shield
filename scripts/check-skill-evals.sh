#!/usr/bin/env bash
# check-skill-evals.sh — graded-verdict gate for the skill eval fixtures.
#
# Sensor: scripts/check-skill-evals.sh (do-harness.toml name: skill-evals)
#
# `do-harness eval --strict-fixtures` exits nonzero on fixture-quality gaps and
# broken structure, but a *failed graded assertion* only changes its pass-rate
# column: the command still exits 0, so the raw command would be a sensor that
# cannot fire on the failure it exists to catch. This wrapper parses the
# per-skill verdict line and fails whenever a skill does not report
# `structure=ok` with `evals=<n>/<n>` and `fixture=ok`.
# `do-harness eval --format json` (0.1.1) produced no output here, so the text
# verdict lines are the machine contract.
#
# python3 parses the output; a missing interpreter WARN-skips locally and
# fails closed when CI=true or DO_HARNESS_REQUIRE_TOOLS=1.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v do-harness >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: do-harness is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "SKIP: do-harness not installed; skill eval gate unavailable."
    exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: python3 is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "SKIP: python3 not installed; skill eval verdict gate unavailable."
    exit 0
fi

# The eval is attempted at most twice, and only when the first attempt printed
# no per-skill verdict line at all. Every graded or structural outcome carries
# a `<skill>: structure=… evals=…` line (`evals=skipped` when the structure
# gate rejected the skill), so an empty verdict set means the evaluation never
# ran — an infrastructure hiccup, not a grade. One observed local run failed
# this way and 11 replays plus four CI runs did not reproduce it; retrying
# cannot turn a graded failure green, and a deterministic breakage produces the
# same empty output on the second attempt and still fails.
attempt=1
while :; do
    output="$(do-harness eval --strict-fixtures 2>&1)" && eval_rc=0 || eval_rc=$?
    if printf '%s\n' "$output" | grep -qE '^[a-z0-9-]+: structure='; then
        break
    fi
    if (( attempt == 1 )); then
        printf '%s\n' "$output"
        printf 'NOTICE: do-harness eval exited %s without a per-skill verdict; retrying once.\n' "$eval_rc"
        attempt=2
        continue
    fi
    printf '%s\n' "$output"
    printf 'skill-evals FAILED: do-harness eval exited %s without a per-skill verdict twice.\n' "$eval_rc"
    exit 1
done
printf '%s\n' "$output"

# A heredoc replaces python3's stdin, so the verdicts go through a temp file.
verdict_log="$(mktemp)"
trap 'rm -f "$verdict_log"' EXIT
printf '%s\n' "$output" >"$verdict_log"

status=0
python3 - "$verdict_log" <<'PY' || status=$?
import re
import sys

verdict = re.compile(r"^[a-z0-9-]+: structure=")
failures = []
checked = 0
with open(sys.argv[1], encoding="utf-8") as log:
    for line in log:
        if not verdict.match(line):
            continue
        checked += 1
        name = line.split(":", 1)[0]
        if "structure=ok" not in line:
            failures.append(f"{name}: structure is not ok")
        if "fixture=ok" not in line:
            failures.append(f"{name}: fixture is not ok")
        match = re.search(r"evals=(\d+)/(\d+)", line)
        if not match:
            failures.append(f"{name}: no graded eval verdict")
        elif match.group(1) != match.group(2):
            failures.append(
                f"{name}: {match.group(1)}/{match.group(2)} graded assertions passed"
            )
if checked == 0:
    failures.append("no skill verdict lines in `do-harness eval` output")
for failure in failures:
    print(f"FAIL: {failure}")
sys.exit(1 if failures else 0)
PY

if (( status != 0 || eval_rc != 0 )); then
    if (( eval_rc != 0 )); then
        printf 'FAIL: do-harness eval exited %s\n' "$eval_rc"
    fi
    echo "skill-evals FAILED."
    exit 1
fi
echo "skill-evals OK."
