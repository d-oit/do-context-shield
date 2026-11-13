#!/usr/bin/env bash
# check-release-preflight.sh — release preflight checks.
#
# Sensor: scripts/check-release-preflight.sh
# Verifies:
#   1. Workspace version agreement (Cargo.toml workspace.package.version matches member crates).
#   2. Tag agreement (if RELEASE_TAG or $1 is supplied, e.g. v0.1.0 or 0.1.0).
#   3. Package metadata completeness (description, license, repository).
#   4. Publish order array completeness and topological sorting (via check-publish-order.sh).
#   5. Package surface hygiene and README inclusion (cargo package --list for every workspace crate).
#   6. Optional crates.io verification for each package/version in publish order.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CHECK_REGISTRY=0
TARGET_TAG=""
while (($# > 0)); do
    case "$1" in
        --check-registry) CHECK_REGISTRY=1 ;;
        --help)
            printf '%s\n' "Usage: $0 [--check-registry] [release-tag]"
            exit 0
            ;;
        --*)
            printf 'FAIL: unknown option: %s\n' "$1" >&2
            exit 2
            ;;
        *)
            if [[ -n "$TARGET_TAG" ]]; then
                echo "FAIL: only one release tag may be supplied." >&2
                exit 2
            fi
            TARGET_TAG="$1"
            ;;
    esac
    shift
done
if [[ -z "$TARGET_TAG" ]]; then
    TARGET_TAG="${RELEASE_TAG:-}"
fi

if ! command -v python3 >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: python3 is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "WARN: python3 not installed; skipping release preflight check."
    exit 0
fi
python3 tests/test_crates_io_versions.py


echo "--- 1. Checking publish order completeness and topology ---"
bash scripts/check-publish-order.sh

echo "--- 2. Checking package versions, tag agreement, and metadata ---"
TARGET_TAG="$TARGET_TAG" python3 - <<'PYEOF'
import json, os, subprocess, sys
from pathlib import Path

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

# 3. Package metadata and README archive check
for name, pkg in sorted(crates.items()):
    for field in ('description', 'license', 'repository'):
        if not pkg.get(field):
            problems.append(f"Crate '{name}' missing required release metadata field '{field}'")

    readme = pkg.get('readme')
    if not readme:
        problems.append(f"Crate '{name}' missing package README metadata ('readme')")
        continue

    package_root = Path(pkg['manifest_path']).resolve().parent
    readme_path = Path(readme)
    if not readme_path.is_absolute():
        readme_path = package_root / readme_path
    readme_path = readme_path.resolve()
    try:
        relative_readme = readme_path.relative_to(package_root).as_posix()
    except ValueError:
        problems.append(f"Crate '{name}' README must be inside its package root")
        continue

    if not readme_path.is_file():
        problems.append(f"Crate '{name}' README does not exist: '{relative_readme}'")
        continue

    package_list = subprocess.run(
        ['cargo', 'package', '--list', '--allow-dirty', '-p', name],
        capture_output=True, text=True)
    if package_list.returncode != 0:
        problems.append(f"Crate '{name}' cargo package --list failed:\n{package_list.stderr.strip()}")
    elif relative_readme not in package_list.stdout.splitlines():
        problems.append(f"Crate '{name}' README '{relative_readme}' is not in the package archive (check package.include)")

if problems:
    print('\n'.join('FAIL: ' + p for p in problems))
    sys.exit(1)

print(f"release-preflight: {len(crates)} crates verified at version {workspace_version}; declared READMEs are included.")
PYEOF
if [[ "$CHECK_REGISTRY" == "1" ]]; then
    echo "--- 3. Verifying published package versions on crates.io ---"
    bash scripts/publish-crates.sh --verify-published
fi


echo "check-release-preflight OK."
