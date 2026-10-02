#!/usr/bin/env bash
# check-publish-order.sh — the publish script's ORDER must match the workspace.
#
# Sensor: scripts/check-publish-order.sh
# scripts/publish-crates.sh publishes bottom-up through a hardcoded ORDER
# array, and `cargo publish` resolves sibling path deps via the crates.io
# index — so a crate missing from ORDER, or listed before one of its normal
# workspace dependencies, fails mid-release with crates.io as the oracle.
# This sensor uses `cargo metadata` as the single source of truth and asserts
# completeness (every workspace crate is listed) and topological validity
# (every normal, non-optional workspace dependency appears earlier).
# Missing python3 fails closed when CI=true or DO_HARNESS_REQUIRE_TOOLS=1 and
# is a WARN skip otherwise — the same policy as check-shellcheck.sh.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: python3 is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "WARN: python3 not installed; skipping publish-order check."
    exit 0
fi

PUBLISH_SCRIPT="scripts/publish-crates.sh"
if [[ ! -f "$PUBLISH_SCRIPT" ]]; then
    echo "FAIL: ${PUBLISH_SCRIPT} is missing."
    exit 1
fi

# The ORDER array entries, one crate per line: lines between `ORDER=(` and the
# closing `)`, with comments and whitespace stripped.
order="$(awk '/^ORDER=\(/{inside=1; next} inside && /^\)/{exit} inside{print}' "$PUBLISH_SCRIPT" \
    | sed 's/#.*//; s/[[:space:]]//g' | sed '/^$/d')"
if [[ -z "$order" ]]; then
    echo "FAIL: no ORDER array entries found in ${PUBLISH_SCRIPT}."
    exit 1
fi

# cargo metadata drives both assertions; the ORDER list arrives via the
# environment because the heredoc already occupies stdin.
ORDER_CRATES="$order" python3 - <<'PYEOF'
import json, os, subprocess, sys

order = [line.strip() for line in os.environ['ORDER_CRATES'].splitlines() if line.strip()]

result = subprocess.run(
    ['cargo', 'metadata', '--format-version', '1', '--no-deps'],
    capture_output=True, text=True)
if result.returncode != 0:
    print('FAIL: cargo metadata failed:\n' + result.stderr.strip())
    sys.exit(1)
meta = json.loads(result.stdout)

crates = {p['name']: p for p in meta['packages'] if '/crates/' in p['manifest_path']}
if not crates:
    print('FAIL: cargo metadata reports no workspace crates under crates/.')
    sys.exit(1)

pos = {}
dupes = set()
for i, name in enumerate(order):
    if name in pos:
        dupes.add(name)
    pos[name] = i

problems = []
unknown = sorted(set(order) - set(crates))
if unknown:
    problems.append('ORDER lists crates that are not workspace members: ' + ', '.join(unknown))
if dupes:
    problems.append('duplicate ORDER entries: ' + ', '.join(sorted(dupes)))
missing = sorted(set(crates) - set(order))
if missing:
    problems.append('workspace crates missing from ORDER: ' + ', '.join(missing))

# Normal, non-optional dependencies are what `cargo publish` rewrites to
# registry versions; dev-deps on workspace members are stripped from the
# packaged manifest and build-deps do not gate the index lookup.
for name in order:
    if name not in crates:
        continue
    for dep in crates[name]['dependencies']:
        if dep.get('kind') is not None or dep.get('optional', False):
            continue
        if dep['name'] not in crates or dep['name'] not in pos:
            continue
        if pos[dep['name']] > pos[name]:
            problems.append(f'{name} is ordered before its dependency {dep["name"]}')

if problems:
    print('\n'.join('FAIL: ' + p for p in problems))
    sys.exit(1)
print(f'publish-order: {len(order)} crates, complete and topological.')
PYEOF

echo "check-publish-order OK."
