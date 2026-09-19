# Backlog

Deferred work, newest first. The do-harness task runtime
(`.do-harness/agent_state.db`, `do-harness task list`) is the live record; this
file is the durable, reviewable copy. Promote an item by giving it a task
(`do-harness task add "<title>" --method <name>`); remove its section when the
work lands or the precondition expires.

## Low priority

### Verify the MCP server end-to-end in Codex

- **Status**: updated 2026-09-19 — registration verified with codex-cli 0.147.0; the model turn is blocked by the account usage limit.
- **Precondition**: Codex quota available again (the CLI reports the limit clears 2026-10-15 22:04 UTC).
- **Verified 2026-09-19**: `codex doctor` → auth mode `chatgpt`, 0 failures; a `[mcp_servers.do-context-shield]` table in `~/.codex/config.toml` (checked against an isolated `CODEX_HOME`) and the same keys via one-off `-c` overrides are both accepted, and `codex mcp list` reports the server as `enabled`; project `.codex/config.toml` is ignored unless the project is trusted.
- **Remaining work**: run one non-interactive turn (`codex exec --json --ephemeral` with the `-c` registration) that calls `context.inspect` + `context.sanitize` (session `codex-probe-1`), confirm the reply carries placeholders only, and record the flags.
- **Entry point**: `docs/client-integration.md` → "Other clients" (Codex shapes, one-off command).
- **Exit criteria**: a JSONL transcript proving the tool invocation and the sanitized reply.

### Verify the MCP server end-to-end in Claude Code

- **Status**: updated 2026-09-19 — registration re-verified with Claude Code 2.1.251; the model turn is still precondition-blocked.
- **Precondition**: working Claude Code credentials in the verification environment.
- **Verified 2026-09-19**: `claude mcp add -s project do-context-shield <binary> mcp-stdio` writes the documented `.mcp.json` and `claude mcp list` reports the server, but as `⏸ Pending approval (run claude to approve)` — project scope now requires one interactive approval.
- **Blocker evidence**: `claude -p --output-format json …` writes nothing to stdout/stderr and is killed only by the timeout (exit 124 after 60 s; 90 s in the first attempt); the 1.0.44 attempt earlier returned `401 Invalid Authentication`.
- **Remaining work**: with working credentials, approve the project server once, run a `claude -p` turn that calls `context.inspect` + `context.sanitize` (session `cc-probe-1`), confirm the reply carries placeholders only, and record the flags.
- **Entry point**: `docs/client-integration.md` → "Other clients"; non-interactive flags: `--mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__do-context-shield` with the prompt on stdin.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply.
