# Backlog

Deferred work, newest first. The do-harness task runtime
(`.do-harness/agent_state.db`, `do-harness task list`) is the live record; this
file is the durable, reviewable copy. Promote an item by giving it a task
(`do-harness task add "<title>" --method <name>`); remove its section when the
work lands or the precondition expires.

## Low priority

### Verify the MCP server end-to-end in Claude Code (harness task 1)

- **Status**: deferred 2026-09-17 — low priority, precondition-blocked.
- **Precondition**: valid Claude Code API credentials in the verification environment.
- **Already verified** (client-integration exercise): `claude mcp add -s project do-context-shield <binary> mcp-stdio`
  writes a valid project `.mcp.json` (`type: stdio`, `command`, `args`, `env`) and
  `claude mcp get do-context-shield` resolves project scope. The model turn could not run:
  `claude -p --debug` reports `401 Invalid Authentication`.
- **Remaining work**: with working credentials, run a `claude -p` turn that calls
  `private.inspect` + `private.sanitize` (session `cc-probe-1`) and confirm the reply carries
  placeholders only; record the exact client flags that were needed.
- **Entry point**: `docs/client-integration.md` → "Other clients"; non-interactive flags used
  during the attempt: `--mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__do-context-shield`
  with the prompt on stdin.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply, or a
  documented client-side blocker; update `docs/client-integration.md` with the verified status.
