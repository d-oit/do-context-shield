#!/usr/bin/env bash
# Publish workspace crates to crates.io bottom-up in dependency order.
#
# `cargo publish` resolves sibling path deps via the crates.io index, so
# downstream crates can only publish after their dependencies are live.
# Usage:
#   scripts/publish-crates.sh --dry-run   # rehearse (package surface only)
#   CARGO_REGISTRY_TOKEN=... scripts/publish-crates.sh
set -euo pipefail

ORDER=(
    do-context-shield-plugin-api
    do-context-shield-detector-regex
    do-context-shield-detector-gliner2
    do-context-shield-detector-process
    do-context-shield-policy-default
    do-context-shield-transformer-pseudonymize
    do-context-shield-vault-memory
    do-context-shield-vault-json
    do-context-shield-plugin-registry
    do-context-shield-core
    do-context-shield-mcp-server
    do-context-shield
)

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

# Rehearsal validates the package surface without touching the registry.
# (Full `cargo publish --dry-run` fails for crates whose siblings are not
# yet published, so it is not a valid gate here.)
if [ "$DRY_RUN" = "1" ]; then
    for crate in "${ORDER[@]}"; do
        echo "--- $crate ---"
        cargo package --list -p "$crate" > /dev/null
    done
    echo "publish rehearsal ok"
    exit 0
fi

if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
    echo "error: CARGO_REGISTRY_TOKEN is not set" >&2
    exit 1
fi

for crate in "${ORDER[@]}"; do
    echo "--- publishing $crate ---"
    cargo publish -p "$crate"
    # Allow the index to catch up before the next dependent crate.
    sleep 30
done
