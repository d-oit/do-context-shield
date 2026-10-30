#!/usr/bin/env bash
# Publish workspace crates to crates.io bottom-up in dependency order.
#
# `cargo publish` resolves sibling path deps via the crates.io index, so
# downstream crates can only publish after their dependencies are live.
#
# Idempotency & Resumption:
#   Before publishing each crate, this script queries crates.io to check if
#   the current workspace version is already published. If present, it skips
#   the publish step and moves to the next crate. If publishing fails, a
#   detailed status summary reports which crates succeeded and where resumption
#   begins.
#
# Usage:
#   scripts/publish-crates.sh --dry-run   # rehearse package surfaces and check status
#   scripts/publish-crates.sh --needs-publish  # exit 0 when a version is missing
#   scripts/publish-crates.sh             # uses the credentials from `cargo login`
#   CARGO_REGISTRY_TOKEN=... scripts/publish-crates.sh  # explicit token
set -euo pipefail

ORDER=(
    # Tier 0 — no workspace dependencies
    do-context-shield-plugin-api
    # Tier 1 — depends only on plugin-api (dev-deps stripped by cargo publish)
    do-context-shield-audit-file
    do-context-shield-core
    do-context-shield-detector-gliner2
    do-context-shield-detector-hybrid
    do-context-shield-detector-regex
    do-context-shield-judge-heuristics
    do-context-shield-plugin-process
    do-context-shield-policy-default
    do-context-shield-policy-matrix
    do-context-shield-transformer-generalize
    do-context-shield-transformer-mask
    do-context-shield-transformer-pseudonymize
    do-context-shield-vault-json
    do-context-shield-vault-memory
    # Tier 2 — depends on the tier-1 plugin crates
    do-context-shield-plugin-registry
    # Tier 3+4 — depend on plugin-registry and core
    do-context-shield-mcp-server
    do-context-shield
)

MODE="publish"
case "${1:-}" in
    --dry-run | --check) MODE="dry-run" ;;
    --needs-publish) MODE="needs-publish" ;;
esac

get_crate_version() {
    local crate="$1"
    cargo metadata --format-version 1 --no-deps | python3 -c "
import json, sys
meta = json.load(sys.stdin)
for pkg in meta['packages']:
    if pkg['name'] == '$crate':
        print(pkg['version'])
        sys.exit(0)
sys.exit(1)
"
}

is_crate_published() {
    local crate="$1"
    local version="$2"
    # Query crates.io API with a User-Agent header (required by crates.io terms)
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -A "do-context-shield-release-automation/1.0" "https://crates.io/api/v1/crates/${crate}/${version}" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        return 0
    fi
    return 1
}

# Exit 0 when at least one crate version is missing from crates.io (publish is
# needed), 1 when every version is already present. The release workflow uses
# this to skip the trusted-publishing exchange when re-running a release whose
# crates were already published.
if [ "$MODE" = "needs-publish" ]; then
    for crate in "${ORDER[@]}"; do
        version=$(get_crate_version "$crate")
        if ! is_crate_published "$crate" "$version"; then
            echo "publish needed: $crate@$version is not on crates.io" >&2
            exit 0
        fi
    done
    echo "all crate versions are already published" >&2
    exit 1
fi

# Rehearsal validates package surfaces and queries current index status
if [ "$MODE" = "dry-run" ]; then
    echo "=== Rehearsing package surfaces and checking crates.io status ==="
    for crate in "${ORDER[@]}"; do
        version=$(get_crate_version "$crate")
        echo -n "--- $crate@$version: "
        cargo package --list -p "$crate" > /dev/null
        if is_crate_published "$crate" "$version"; then
            echo "ALREADY PUBLISHED on crates.io"
        else
            echo "NOT PUBLISHED on crates.io (ready to publish)"
        fi
    done
    echo "publish rehearsal ok"
    exit 0
fi

# `cargo publish` reads CARGO_REGISTRY_TOKEN when it is set, otherwise the
# credentials stored by `cargo login` ($CARGO_HOME/credentials.toml, or the
# legacy `credentials` file). Fail early only when neither is configured.
if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    if [ ! -f "$cargo_home/credentials.toml" ] && [ ! -f "$cargo_home/credentials" ]; then
        echo "error: no crates.io credentials: set CARGO_REGISTRY_TOKEN or run cargo login" >&2
        exit 1
    fi
fi

PUBLISHED_CRATES=()
SKIPPED_CRATES=()
FAILED_CRATE=""

echo "=== Starting bottom-up publishing to crates.io ==="

for crate in "${ORDER[@]}"; do
    version=$(get_crate_version "$crate")
    echo "Checking status for $crate@$version..."

    if is_crate_published "$crate" "$version"; then
        echo "[SKIP] $crate@$version is already published on crates.io."
        SKIPPED_CRATES+=("$crate@$version")
        continue
    fi

    echo "--- [PUBLISH] Publishing $crate@$version ---"
    if cargo publish -p "$crate"; then
        echo "[SUCCESS] $crate@$version published."
        PUBLISHED_CRATES+=("$crate@$version")
        # Allow crates.io index to catch up before dependent crates
        echo "Waiting 30 seconds for index update..."
        sleep 30
    else
        echo "ERROR: Failed to publish $crate@$version." >&2
        FAILED_CRATE="$crate@$version"
        break
    fi
done

echo ""
echo "=========================================="
echo "          PUBLISH STATUS REPORT           "
echo "=========================================="
if [ ${#SKIPPED_CRATES[@]} -gt 0 ]; then
    echo "Already published (skipped):"
    for item in "${SKIPPED_CRATES[@]}"; do
        echo "  - $item"
    done
fi

if [ ${#PUBLISHED_CRATES[@]} -gt 0 ]; then
    echo "Newly published in this run:"
    for item in "${PUBLISHED_CRATES[@]}"; do
        echo "  - $item"
    done
fi

if [ -n "$FAILED_CRATE" ]; then
    echo "FAILURE occurred at: $FAILED_CRATE"
    echo "Resumption point: Fix the issue with $FAILED_CRATE and re-run scripts/publish-crates.sh."
    echo "Already published crates will be skipped automatically."
    exit 1
fi

echo "Publish process completed successfully."
