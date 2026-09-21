#!/usr/bin/env bash
# check-shellcheck.sh — shell lint for the repository's shell surfaces.
#
# Sensor: scripts/check-shellcheck.sh
# Covers the git hooks and the scripts/ helpers: they run in contributor
# environments and CI, so quoting and printf defects are load-bearing.
# Missing shellcheck fails closed when CI=true or DO_HARNESS_REQUIRE_TOOLS=1,
# and is a WARN skip otherwise so offline local runs stay usable — the same
# policy as check-deps.sh and check-audit.sh.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v shellcheck >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: shellcheck is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "WARN: shellcheck not installed; skipping shell lint."
    exit 0
fi

shellcheck .githooks/pre-commit .githooks/pre-push .githooks/commit-msg scripts/*.sh
echo "check-shellcheck OK."
