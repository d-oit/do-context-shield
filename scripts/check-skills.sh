#!/usr/bin/env bash
# check-skills.sh — structure and fixture gate for .agents/skills plus the
# machine-readable planning catalogs.
#
# Sensor: scripts/check-skills.sh (do-harness.toml name: skills)
# Checks:
#   1. every skill passes skill-creator's quick_validate.py structure gate
#   2. every skill has evals/evals.json with graded assertions and a negative case
#   3. plans/methods.json subtask sensors exist in do-harness.toml
#   4. every plans/invariants.json entry carries invariant/rationale/sensor/category
#   5. the harness skill's sensor table matches do-harness.toml: every sensor has
#      a row, and a row may only claim a stage the sensor is wired into
#
# python3 is required for the gate; a missing interpreter WARN-skips locally and
# fails closed when CI=true or DO_HARNESS_REQUIRE_TOOLS=1.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FAIL=0
VALIDATOR=".agents/skills/skill-creator/scripts/quick_validate.py"

if ! command -v python3 >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: python3 is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "SKIP: python3 not installed; skill structure gate unavailable."
    exit 0
fi

if [[ ! -f "$VALIDATOR" ]]; then
    echo "FAIL: missing skill structure gate: $VALIDATOR"
    exit 1
fi

for dir in .agents/skills/*/; do
    name="$(basename "$dir")"
    if ! python3 "$VALIDATOR" "$dir" >/dev/null; then
        echo "FAIL: structure gate rejected $name (run: python3 $VALIDATOR $dir)"
        FAIL=1
    fi
done

if ! python3 - <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(".")
failures = []

skills = sorted(p for p in (root / ".agents/skills").iterdir() if p.is_dir())
graded_prefixes = ("exists:", "absent:", "contains:", "not-contains:", "db:", "cli:", "walk:")
for skill in skills:
    fixture = skill / "evals" / "evals.json"
    if not fixture.is_file():
        failures.append(f"{skill.name}: missing evals/evals.json")
        continue
    try:
        data = json.loads(fixture.read_text())
    except json.JSONDecodeError as error:
        failures.append(f"{skill.name}: evals.json is not valid JSON: {error}")
        continue
    if data.get("skill_name") != skill.name:
        failures.append(f"{skill.name}: skill_name does not match the directory")
    cases = data.get("evals") or []
    if not cases:
        failures.append(f"{skill.name}: no eval cases")
    if not any(case.get("kind") == "negative" for case in cases):
        failures.append(f"{skill.name}: no negative (out-of-scope) case")
    for case in cases:
        assertions = case.get("assertions") or []
        if not any(a.startswith(graded_prefixes) for a in assertions):
            failures.append(f"{skill.name}: case {case.get('id')} has no graded assertions")

config = (root / "do-harness.toml").read_text()
sensor_names = set(re.findall(r'^name = "([a-z0-9-]+)"', config, re.M))
methods = json.loads((root / "plans/methods.json").read_text())["methods"]
for method in methods:
    for subtask in method["subtasks"]:
        sensor = subtask.get("sensor")
        if sensor and sensor not in sensor_names:
            failures.append(
                f"methods.json: method {method['name']} subtask {subtask['name']} names unknown sensor {sensor}"
            )

# The harness skill's sensor table is the map agents read before touching the
# suite. A sensor missing from the table, or a row claiming a stage the sensor
# is not wired into, sends the next agent to the wrong gate.
def toml_list(key):
    match = re.search(rf"^{re.escape(key)}\s*=\s*\[(.*?)\]", config, re.M)
    if not match:
        failures.append(f"do-harness.toml: no `{key}` list found")
        return set()
    return {item.strip().strip('"') for item in match.group(1).split(",") if item.strip()}

pre_commit = toml_list("pre-commit")
pre_push = toml_list("pre-push")
ci_set = toml_list("ci")
verification_set = toml_list("verification")
commit_msg_hook = (root / ".githooks/commit-msg").read_text()

harness_skill = root / ".agents/skills/harness/SKILL.md"
lines = harness_skill.read_text().splitlines()
header = next((i for i, line in enumerate(lines) if line.startswith("| Sensor | Command | Stage")), None)
if header is None:
    failures.append("harness SKILL.md: no `| Sensor | Command | Stage |` table found")
    rows = {}
else:
    rows = {}
    for line in lines[header + 1 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3 or set(cells[0]) <= set("- ") or not cells[0]:
            continue
        rows[cells[0]] = cells[2].lower()

missing = sorted(sensor_names - set(rows))
if missing:
    failures.append(f"harness SKILL.md: sensor table has no row for {', '.join(missing)}")
suite_stages = ("pre-commit", "pre-push", "verification", "commit-msg")
for name, stage in rows.items():
    tokens = [part.strip(" `") for part in stage.split(",") if part.strip(" `")]
    if name not in sensor_names:
        # The table also documents CI-only gates that are not do-harness
        # sensors (structure, deny, publish-check, secret-scan). They may claim
        # CI, but never a stage of the harness suite.
        claimed = [token for token in tokens if any(marker in token for marker in suite_stages)]
        if claimed:
            failures.append(
                f"harness SKILL.md: row `{name}` is not a do-harness sensor but claims {', '.join(claimed)}"
            )
        continue
    for token in tokens:
        if "commit-msg" in token:
            if f"scripts/check-{name}.sh" not in commit_msg_hook:
                failures.append(f"harness SKILL.md: {name} claims the commit-msg hook, which does not run it")
        elif "pre-commit" in token and name not in pre_commit:
            failures.append(f"harness SKILL.md: {name} claims the pre-commit hook, which does not run it")
        elif "pre-push" in token and name not in pre_push:
            failures.append(f"harness SKILL.md: {name} claims the pre-push hook, which does not run it")
        elif token == "ci" and name not in ci_set:
            failures.append(f"harness SKILL.md: {name} claims CI, which does not run it")
        elif "verification" in token and name not in verification_set:
            failures.append(f"harness SKILL.md: {name} claims the verification set, which does not run it")
        elif not any(
            marker in token for marker in ("pre-commit", "pre-push", "ci", "verification", "commit-msg")
        ):
            failures.append(f"harness SKILL.md: {name} names unrecognized stage `{token}`")

invariants = json.loads((root / "plans/invariants.json").read_text())
for entry in invariants:
    for field in ("invariant", "rationale", "sensor", "category"):
        if not entry.get(field):
            failures.append(
                f"invariants.json: entry missing {field}: {entry.get('invariant', '<no invariant>')}"
            )

# Repo paths a skill names (scripts/..., docs/..., .github/...) must exist: the
# eval sandbox cannot mirror them in harness 0.1.1, so this is the only place
# the sensor map's file claims are enforced.
token_re = re.compile(r"(?<![\w./-])((?:scripts|docs|\.github)/[A-Za-z0-9._/-]+)")
for skill in skills:
    for path in sorted(skill.rglob("*")):
        if not path.is_file() or path.suffix not in {".md", ".sh", ".py", ".json"}:
            continue
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for match in token_re.finditer(text):
            token = match.group(1).rstrip(".,;:`'\")")
            if not (root / token).exists():
                failures.append(
                    f"{skill.name}: {path.relative_to(skill)} names missing repo path {token}"
                )

for failure in failures:
    print(f"FAIL: {failure}")
print(f"skills gate: {len(skills)} skills, {len(methods)} methods, {len(invariants)} invariants checked")
sys.exit(1 if failures else 0)
PY
then
    FAIL=1
fi

if (( FAIL )); then
    echo "check-skills FAILED."
    exit 1
fi
echo "check-skills OK."
