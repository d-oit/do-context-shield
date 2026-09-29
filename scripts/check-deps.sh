#!/usr/bin/env bash
# check-deps.sh — dependency-direction + cargo-deny policy check.
#
# Sensor: scripts/check-deps.sh
# Rules:
#   1. The conventional schema crate (`crates/types/Cargo.toml`, checked only
#      when present) must not depend on storage, adapter, or CLI layers.
#      Layers are recognized by package-name suffix (db, storage,
#      adapters/adapter, cli), which generalizes the do-harness types-manifest
#      rule without hardcoding project crate names. Override the suffix ERE
#      with DO_HARNESS_FORBIDDEN_LAYERS.
#   2. `cargo deny check` runs when deny.toml is configured and covers the
#      transitive closure; without deny.toml the policy is unconfigured, so
#      the sensor WARN-skips rather than failing a greenfield scaffold.
#   3. The dependency closure stays offline: Cargo.lock must contain no network
#      client, TLS stack, or hosted-model SDK, because the core's privacy claim
#      is that nothing leaves the process. Cargo.lock lists every feature's
#      dependencies, so this also covers feature-gated trees (`gliner2`) that
#      `cargo deny check` does not compile. Override the ERE with
#      DO_HARNESS_FORBIDDEN_DEPS (used by the sensor's own negative tests).
# Missing cargo-deny fails closed when CI=true or DO_HARNESS_REQUIRE_TOOLS=1.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FAIL=0

TYPES_MANIFEST="$ROOT/crates/types/Cargo.toml"
FORBIDDEN_LAYERS="${DO_HARNESS_FORBIDDEN_LAYERS:-(^|[-_])(db|storage|adapters?|cli)$}"
if [[ -f "$TYPES_MANIFEST" ]]; then
    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        if [[ "$dep" =~ $FORBIDDEN_LAYERS ]]; then
            echo "FAIL: schema crate must not depend on a storage/adapter layer: $dep"
            FAIL=1
        fi
    done < <(
        awk '/^\[/ { in_deps = ($0 ~ /dependencies\]$/) } in_deps { print }' "$TYPES_MANIFEST" \
            | grep -oE '^[[:space:]]*"?[A-Za-z0-9_.-]+' \
            | tr -d ' "'
    )
fi

LOCK="$ROOT/Cargo.lock"
if [[ ! -f "$LOCK" ]]; then
    echo "FAIL: Cargo.lock is missing; the dependency closure cannot be checked."
    FAIL=1
else
    FORBIDDEN_DEPS="${DO_HARNESS_FORBIDDEN_DEPS:-^(reqwest|reqwest-[a-z0-9-]+|ureq|hyper|hyper-[a-z0-9-]+|h2|quinn|tonic|isahc|surf|curl|curl-sys|tungstenite|rustls|rustls-[a-z0-9-]+|native-tls|openssl|openssl-sys|webpki|webpki-roots|aws-sdk-[a-z0-9-]+|aws-config|google-cloud-[a-z0-9-]+|azure_[a-z0-9_-]+|azure-sdk-[a-z0-9-]+|openai[a-z0-9-]*|anthropic[a-z0-9-]*|cohere[a-z0-9-]*|mistral[a-z0-9-]*|ollama[a-z0-9-]*|bedrock[a-z0-9-]*)$}"
    while IFS= read -r crate; do
        [[ -z "$crate" ]] && continue
        if [[ "$crate" =~ $FORBIDDEN_DEPS ]]; then
            printf "FAIL: the privacy boundary must stay offline, but Cargo.lock pulls in '%s' (network client, TLS stack, or hosted-model SDK).\n" "$crate"
            FAIL=1
        fi
    done < <(sed -n 's/^name = "\(.*\)"/\1/p' "$LOCK" | sort -u)
fi

if [[ -f "$ROOT/deny.toml" ]]; then
    if ! command -v cargo-deny >/dev/null 2>&1; then
        if require_tools; then
            echo "FAIL: cargo-deny is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
            FAIL=1
        else
            echo "WARN: cargo-deny not installed; skipping deny check."
        fi
    else
        cargo deny check || FAIL=1
    fi
else
    echo "WARN: deny.toml not found; skipping cargo-deny policy check."
fi

if (( FAIL )); then
    exit 1
fi

echo "check-deps OK."
