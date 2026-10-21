#!/usr/bin/env bash
# smoke-test-release.sh — release smoke test for do-context-shield CLI and MCP server.
#
# Verifies:
#   1. Binary exists and answers --version.
#   2. inspect command processes synthetic input without crashing.
#   3. sanitize command replaces sensitive data with tokens and DOES NOT LEAK
#      raw sensitive input to stdout, stderr, or logs.
#   4. restore command recovers original text from the vault file.
#   5. mcp-stdio command handles JSON-RPC tool calls (context.inspect, context.sanitize).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN_PATH="${1:-${DO_CONTEXT_SHIELD_BIN:-}}"

if [[ -z "$BIN_PATH" ]]; then
    if [[ -f "target/release/do-context-shield" ]]; then
        BIN_PATH="target/release/do-context-shield"
    elif [[ -f "target/debug/do-context-shield" ]]; then
        BIN_PATH="target/debug/do-context-shield"
    else
        echo "Building do-context-shield binary for smoke test..."
        cargo build -p do-context-shield
        BIN_PATH="target/debug/do-context-shield"
    fi
fi

if [[ ! -x "$BIN_PATH" ]]; then
    echo "FAIL: Binary at '$BIN_PATH' is missing or not executable." >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

VAULT_FILE="$TMP_DIR/vault.json"
STDOUT_FILE="$TMP_DIR/stdout.log"
STDERR_FILE="$TMP_DIR/stderr.log"

SYNTHETIC_EMAIL="synthetic_alice_12345@example.com"
SYNTHETIC_AWS_KEY="AKIAIOSFODNN7EXAMPLE"
SYNTHETIC_INPUT="Contact email: $SYNTHETIC_EMAIL with AWS key $SYNTHETIC_AWS_KEY"

echo "=== Smoke Test 1: --version ==="
"$BIN_PATH" --version

echo "=== Smoke Test 2: inspect ==="
printf '%s' "$SYNTHETIC_INPUT" | "$BIN_PATH" inspect > "$STDOUT_FILE" 2> "$STDERR_FILE"
if ! grep -q "email" "$STDOUT_FILE"; then
    echo "FAIL: inspect did not detect email entity in synthetic input." >&2
    exit 1
fi

echo "=== Smoke Test 3: sanitize with vault ==="
printf '%s' "$SYNTHETIC_INPUT" | "$BIN_PATH" sanitize --session smoke-session --vault-file "$VAULT_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"

SANITIZED_TEXT="$(cat "$STDOUT_FILE")"

# PRIVACY ASSERTION: Verify raw inputs are NOT leaked in stdout or stderr
if grep -q "$SYNTHETIC_EMAIL" "$STDOUT_FILE" "$STDERR_FILE"; then
    echo "FAIL: Raw email '$SYNTHETIC_EMAIL' leaked in sanitize output/stderr!" >&2
    exit 1
fi
if grep -q "$SYNTHETIC_AWS_KEY" "$STDOUT_FILE" "$STDERR_FILE"; then
    echo "FAIL: Raw AWS key '$SYNTHETIC_AWS_KEY' leaked in sanitize output/stderr!" >&2
    exit 1
fi

# Verify tokens or placeholders were generated
if ! echo "$SANITIZED_TEXT" | grep -q "__DO_PRIVATE_EMAIL_"; then
    echo "FAIL: Sanitize output does not contain expected pseudonymization placeholders." >&2
    exit 1
fi
if ! echo "$SANITIZED_TEXT" | grep -q "__DO_PRIVATE_REDACTED__"; then
    echo "FAIL: Sanitize output does not contain expected secret redaction placeholder." >&2
    exit 1
fi

echo "=== Smoke Test 4: restore from vault ==="
RESTORED_TEXT="$(printf '%s' "$SANITIZED_TEXT" | "$BIN_PATH" restore --session smoke-session --vault-file "$VAULT_FILE" 2> "$STDERR_FILE")"

if ! echo "$RESTORED_TEXT" | grep -q "$SYNTHETIC_EMAIL"; then
    echo "FAIL: Restore did not recover original email '$SYNTHETIC_EMAIL'." >&2
    exit 1
fi

echo "=== Smoke Test 5: mcp-stdio JSON-RPC adapter ==="
MCP_REQ_INSPECT='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"context.inspect","arguments":{"text":"test user@example.com"}}}'
MCP_REQ_SANITIZE='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"context.sanitize","arguments":{"text":"my email is test_mcp_user@example.com","session":"mcp-smoke"}}}'

MCP_RESP="$(printf '%s\n%s\n' "$MCP_REQ_INSPECT" "$MCP_REQ_SANITIZE" | "$BIN_PATH" mcp-stdio --vault-file "$VAULT_FILE" 2> "$STDERR_FILE")"

# PRIVACY ASSERTION: Verify raw input was not leaked in stderr logs
if grep -q "test_mcp_user@example.com" "$STDERR_FILE"; then
    echo "FAIL: MCP server leaked raw input 'test_mcp_user@example.com' to stderr log!" >&2
    exit 1
fi

if ! echo "$MCP_RESP" | grep -q '"jsonrpc":"2.0"'; then
    echo "FAIL: MCP stdio response is not valid JSON-RPC." >&2
    exit 1
fi

echo "smoke-test-release OK."
