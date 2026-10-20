#!/usr/bin/env bash
# check-release-preflight.sh — release preflight checks.
#
# Sensor: scripts/check-release-preflight.sh
# Verifies:
#   1. Workspace version agreement (Cargo.toml workspace.package.version matches member crates).
#   2. Tag agreement (if RELEASE_TAG or $1 is supplied, e.g. v0.1.0 or 0.1.0).
#   3. Package metadata completeness (description, license, repository).
#   4. Publish order array completeness and topological sorting (via check-publish-order.sh).
#   5. Package surface hygiene (cargo package --list for every workspace crate).
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: python3 is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "WARN: python3 not installed; skipping release preflight check."
    exit 0
fi

TARGET_TAG="${1:-${RELEASE_TAG:-}}"

echo "--- 1. Checking publish order completeness and topology ---"
bash scripts/check-publish-order.sh

echo "--- 2. Checking package versions, tag agreement, and metadata ---"
TARGET_TAG="$TARGET_TAG" python3 - <<'PYEOF'
import json, os, subprocess, sys

target_tag = os.environ.get('TARGET_TAG', '').strip()
if target_tag.startswith('v'):
    target_tag = target_tag[1:]

result = subprocess.run(
    ['cargo', 'metadata', '--format-version', '1', '--no-deps'],
    capture_output=True, text=True)
if result.returncode != 0:
    print('FAIL: cargo metadata failed:\n' + result.stderr.strip())
    sys.exit(1)
meta = json.loads(result.stdout)

workspace_version = None
if 'workspace_default_members' in meta or True:
    # Read workspace root package version from Cargo.toml metadata
    root_pkg = next((p for p in meta['packages'] if p['manifest_path'].replace('\\', '/').endswith('/Cargo.toml')), None)
    if root_pkg:
        workspace_version = root_pkg['version']

crates = {p['name']: p for p in meta['packages']
          if '/crates/' in p['manifest_path'].replace('\\', '/')}

if not crates:
    print('FAIL: cargo metadata reports no workspace crates under crates/.')
    sys.exit(1)

if not workspace_version:
    workspace_version = next(iter(crates.values()))['version']

problems = []

# 1. Tag matching check
if target_tag:
    if target_tag != workspace_version:
        problems.append(f"Release tag version '{target_tag}' does not match workspace version '{workspace_version}'")
    else:
        print(f"OK: Release tag matches workspace version '{workspace_version}'")

# 2. Workspace member version agreement
for name, pkg in crates.items():
    if pkg['version'] != workspace_version:
        problems.append(f"Crate '{name}' version ({pkg['version']}) does not match workspace version ({workspace_version})")

# 3. Package metadata check
for name, pkg in sorted(crates.items()):
    for field in ('description', 'license', 'repository'):
        if not pkg.get(field):
            problems.append(f"Crate '{name}' missing required release metadata field '{field}'")

if problems:
    print('\n'.join('FAIL: ' + p for p in problems))
    sys.exit(1)

print(f"release-preflight: {len(crates)} crates verified at version {workspace_version}.")
PYEOF

echo "--- 3. Verifying include whitelists / package surfaces ---"
for crate in $(cargo metadata --format-version 1 --no-deps \
  | python3 -c "import json,sys; print(' '.join(sorted(p['name'] for p in json.load(sys.stdin)['packages'] if '/crates/' in p['manifest_path'])))"); do
    cargo package --list -p "$crate" > /dev/null
done
echo "OK: All package surfaces listed successfully."

echo "check-release-preflight OK."
