#!/usr/bin/env bash
# Install the published CLI into an isolated Cargo home and smoke-test it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG_NAME="${1:-}"
RELEASE_VERSION="${TAG_NAME#v}"

if [[ -z "$TAG_NAME" || -z "$RELEASE_VERSION" ]]; then
    echo "usage: $0 <release-tag>" >&2
    exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export CARGO_HOME="$TMP_DIR/cargo-home"
export CARGO_TARGET_DIR="$TMP_DIR/cargo-target"
export XDG_CONFIG_HOME="$TMP_DIR/xdg-config"
export XDG_DATA_HOME="$TMP_DIR/xdg-data"
export XDG_CACHE_HOME="$TMP_DIR/xdg-cache"
mkdir -p "$TMP_DIR/work" "$CARGO_HOME" "$CARGO_TARGET_DIR" \
    "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"

(
    cd "$TMP_DIR/work"
    cargo install --version "$RELEASE_VERSION" do-context-shield
)

BIN_PATH="$CARGO_HOME/bin/do-context-shield"
if [[ ! -x "$BIN_PATH" ]]; then
    echo "FAIL: cargo install did not create '$BIN_PATH'." >&2
    exit 1
fi

VERSION_OUTPUT="$("$BIN_PATH" --version)"
EXPECTED_VERSION_OUTPUT="do-context-shield $RELEASE_VERSION"
if [[ "$VERSION_OUTPUT" != "$EXPECTED_VERSION_OUTPUT" ]]; then
    echo "FAIL: expected '$EXPECTED_VERSION_OUTPUT', got '$VERSION_OUTPUT'." >&2
    exit 1
fi
printf 'Installed %s from crates.io.\n' "$VERSION_OUTPUT"

echo "=== Installed CLI doctor ==="
DOCTOR_OUTPUT="$("$BIN_PATH" doctor)"
printf '%s\n' "$DOCTOR_OUTPUT"
if ! grep -qx 'available: true' <<< "$DOCTOR_OUTPUT"; then
    echo "FAIL: the installed CLI doctor did not report a ready default detector." >&2
    exit 1
fi

echo "=== Installed CLI synthetic release smoke ==="
bash "$ROOT/scripts/smoke-test-release.sh" "$BIN_PATH"
