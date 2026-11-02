#!/usr/bin/env bash
# MCP conformance gate for the stdio server.
#
# What this runs:
#   1. The MCP Inspector CLI (pinned) over stdio for each advertised revision:
#      `--protocol-era modern` exercises the 2026-07-28 stateless flow
#      (`server/discover` is performed by the client itself), `legacy`
#      exercises the 2025-11-25 `initialize` handshake. For each revision it
#      checks tool listing, a benign inspect, a synthetic PII sanitize, and
#      default-denied restore.
#   2. The per-revision stdio protocol fixtures in
#      crates/do-context-shield-cli/tests/mcp_stdio_revisions.rs, which assert
#      discovery/initialize, batching rejection, and the no-raw-value egress
#      contract directly against the compiled binary.
#
# What this cannot run: the official @modelcontextprotocol/conformance server
# runner accepts only an HTTP `--url`; stdio server support is still an open
# upstream request (modelcontextprotocol/conformance#258). HTTP-only scenarios
# are therefore NOT run and NOT scored here — a recorded limitation, not a
# silent pass. The Inspector CLI also has no `server/discover` method, so
# discovery is verified by the Rust fixtures and implicitly by the modern
# Inspector run; it is never marked as an HTTP scenario pass.
#
# Node and the Inspector package are pinned: no latest-at-runtime dependency.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

NODE_MAJOR="22"
INSPECTOR_VERSION="2.13.0"
RESULTS="${MCP_CONFORMANCE_RESULTS:-$ROOT/target/mcp-conformance}"
BIN="$ROOT/target/debug/do-context-shield"
# A synthetic value, never a real secret; it must never appear in a
# model-facing response.
SYNTHETIC="alice@example.com"

mkdir -p "$RESULTS"
CHECKS="$RESULTS/checks.jsonl"
: > "$CHECKS"

failures=0
total=0
check_ok=0
check_detail=""
payload_path=""

record() { # record <name> <revision> <status> <detail>
    python3 - "$CHECKS" "$1" "$2" "$3" "$4" <<'PY'
import json
import sys

path, name, revision, status, detail = sys.argv[1:6]
with open(path, "a", encoding="utf-8") as handle:
    handle.write(
        json.dumps(
            {"name": name, "revision": revision, "status": status, "detail": detail}
        )
        + "\n"
    )
PY
}

verdict() { # verdict <name> <revision> <ok:0|1> <detail>
    total=$((total + 1))
    if [ "$3" -eq 0 ]; then
        record "$1" "$2" "passed" "$4"
        printf 'PASS %s [%s]\n' "$1" "$2"
    else
        failures=$((failures + 1))
        record "$1" "$2" "failed" "$4"
        printf 'FAIL %s [%s]: %s\n' "$1" "$2" "$4" >&2
    fi
}

node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
if [ "$node_major" != "$NODE_MAJOR" ]; then
    printf 'error: the MCP conformance gate pins Node %s.x, found %s\n' \
        "$NODE_MAJOR" "$(node --version)" >&2
    exit 1
fi

printf 'Building the stdio server...\n'
cargo build --locked -p do-context-shield --bin do-context-shield

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
server_home="$work/home"
mkdir -p "$server_home"

run_inspector() { # run_inspector <era> <inspector args...>
    local era="$1"
    shift
    (
        cd "$work"
        HOME="$server_home" npx --yes "@modelcontextprotocol/inspector@${INSPECTOR_VERSION}" \
            --cli --protocol-era "$era" "$BIN" mcp-stdio "$@" --format json
    )
}

# Run one Inspector check. Sets check_ok (0/1), payload_path, and check_detail
# in the caller's shell: no subshell, so the pass/fail counters and the
# recorded verdict stay in the main shell.
inspector_check() { # inspector_check <name> <era> <expected-exit> <args...>
    local name="$1"
    local era="$2"
    local expected="$3"
    shift 3
    local out="$RESULTS/$name.$era.json"
    local err="$RESULTS/$name.$era.err"
    local status=0
    payload_path="$out"
    run_inspector "$era" "$@" >"$out" 2>"$err" || status=$?
    if [ "$status" -ne "$expected" ]; then
        check_ok=1
        check_detail="expected exit $expected, got $status (payload: $(head -c 300 "$out"))"
        return
    fi
    check_ok=0
    check_detail=""
}

expect_tool_surface() { # expect_tool_surface <payload-file>
    python3 - "$1" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
result = data.get("result") or {}
names = [tool.get("name") for tool in result.get("tools", [])]
expected = ["context.sanitize", "context.inspect"]
if names != expected:
    raise SystemExit(f"unexpected tool surface: {names}")
PY
}

expect_inspect() { # expect_inspect <payload-file> <synthetic>
    python3 - "$1" "$2" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
text = data["result"]["content"][0]["text"]
if sys.argv[2] in text:
    raise SystemExit("inspect returned the raw value")
entities = json.loads(text)
if not any(entity.get("kind") == "email" for entity in entities):
    raise SystemExit(f"inspect reported no email entity: {text}")
PY
}

expect_sanitize() { # expect_sanitize <payload-file> <synthetic>
    python3 - "$1" "$2" <<'PY'
import json
import re
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
text = data["result"]["content"][0]["text"]
if sys.argv[2] in text:
    raise SystemExit("sanitize returned the raw value")
if not re.fullmatch(r"__DO_PRIVATE_EMAIL_\d+_[0-9A-Fa-f]{16}__", text):
    raise SystemExit(f"sanitize returned an unexpected token: {text!r}")
PY
}

expect_default_denied() { # expect_default_denied <payload-file> <err-file>
    python3 - "$1" "$2" <<'PY'
import sys

payload = open(sys.argv[1], encoding="utf-8").read()
diagnostics = open(sys.argv[2], encoding="utf-8").read()
combined = payload + diagnostics
if "tool_not_found" not in combined and "not enabled on this server" not in combined:
    raise SystemExit(f"restore was not default-denied: {combined[:300]!r}")
PY
}

assert_and_verdict() { # assert_and_verdict <name> <era> <success-detail> <assert-fn> [args...]
    local name="$1"
    local era="$2"
    local success="$3"
    local assertion="$4"
    shift 4
    local detail
    if detail="$("$assertion" "$@" 2>&1)"; then
        verdict "$name" "$era" 0 "$success"
    else
        verdict "$name" "$era" 1 "$detail"
    fi
}

for era in modern legacy; do
    if [ "$era" = modern ]; then
        revision="2026-07-28"
    else
        revision="2025-11-25"
    fi
    printf '\n== revision %s (%s) ==\n' "$era" "$revision"

    inspector_check tools_list "$era" 0 --method tools/list
    if [ "$check_ok" -eq 0 ]; then
        assert_and_verdict tools_list "$era" "sanitize+inspect only" expect_tool_surface "$payload_path"
    else
        verdict tools_list "$era" 1 "$check_detail"
    fi

    inspector_check inspect "$era" 0 \
        --method tools/call --tool-name context.inspect --tool-arg "text=$SYNTHETIC"
    if [ "$check_ok" -eq 0 ]; then
        assert_and_verdict inspect "$era" "kind email, no raw value" expect_inspect "$payload_path" "$SYNTHETIC"
    else
        verdict inspect "$era" 1 "$check_detail"
    fi

    inspector_check sanitize "$era" 0 \
        --method tools/call --tool-name context.sanitize \
        --tool-arg "text=$SYNTHETIC" --tool-arg session=conformance
    if [ "$check_ok" -eq 0 ]; then
        assert_and_verdict sanitize "$era" "minted placeholder" expect_sanitize "$payload_path" "$SYNTHETIC"
    else
        verdict sanitize "$era" 1 "$check_detail"
    fi

    inspector_check restore_denied "$era" 5 \
        --method tools/call --tool-name context.restore \
        --tool-arg "text=__DO_PRIVATE_EMAIL_1_0000000000000000__" \
        --tool-arg session=conformance
    if [ "$check_ok" -eq 0 ]; then
        assert_and_verdict restore_denied "$era" "not exposed on the default surface" \
            expect_default_denied "$payload_path" "$RESULTS/restore_denied.$era.err"
    else
        verdict restore_denied "$era" 1 "$check_detail"
    fi
done

printf '\n== stdio protocol fixtures ==\n'
if cargo test --locked -p do-context-shield --test mcp_stdio_revisions >"$RESULTS/stdio_fixtures.log" 2>&1; then
    verdict stdio_fixtures all 0 "discovery, initialize, batching, no raw-value egress"
else
    verdict stdio_fixtures all 1 "see $RESULTS/stdio_fixtures.log"
fi

python3 - "$CHECKS" "$RESULTS/summary.json" "$INSPECTOR_VERSION" "$total" "$failures" <<'PY'
import json
import sys

checks_path, summary_path, inspector, total, failures = sys.argv[1:6]
checks = [json.loads(line) for line in open(checks_path, encoding="utf-8") if line.strip()]
summary = {
    "tool": "@modelcontextprotocol/inspector",
    "tool_version": inspector,
    "checks": checks,
    "total": int(total),
    "failed": int(failures),
    "official_conformance_runner": {
        "stdio_server_support": False,
        "upstream": "modelcontextprotocol/conformance#258",
        "scored": False,
        "note": (
            "The official server runner accepts only an HTTP --url, so HTTP-only "
            "scenarios are not run or scored. Stdio coverage is the Inspector "
            "smoke checks plus crates/do-context-shield-cli/tests/mcp_stdio_revisions.rs."
        ),
    },
}
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2)
    handle.write("\n")
PY

printf '\nMCP conformance: %s checks, %s failed (results in %s)\n' "$total" "$failures" "$RESULTS"
if [ "$failures" -ne 0 ]; then
    exit 1
fi
