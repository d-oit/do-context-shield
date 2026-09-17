# Client integration

## MCP

Use `do-context-shield mcp-stdio` as a local MCP server. The server keeps the application mapping vault in the server process and takes an explicit `session` argument, which fits the 2026-07-28 MCP model where protocol sessions were removed but applications may still carry their own handles. The server supports the 2026-07-28 `server/discover` path and a 2025-era `initialize` fallback. The 2026-07-28 revision removed the protocol-level initialize/session handshake, while application state can still be carried explicitly by a tool argument.

Example generic stdio registration:

```json
{
  "mcpServers": {
    "do-context-shield": {
      "command": "do-context-shield",
      "args": ["mcp-stdio"]
    }
  }
}
```

Modern MCP 2026-07-28 clients discover the server with `server/discover` and then call `tools/list` / `tools/call` without the legacy initialize exchange. Legacy clients can still use `initialize`. See the official MCP release notes for the protocol-era split.

Tool selection and caching contract:

- `tools/list` returns `private.sanitize`, `private.restore`, `private.inspect` in a fixed order with `ttlMs: 300000` and `cacheScope: private` (session-scoped results must not sit in shared caches).
- `sanitize` and `restore` schemas require `text` and `session`. The server still accepts a missing `session` as `default` for older clients, but always send an explicit per-task session.
- Plugin selection: `--detector regex|gliner2|process`, `--policy default|process`, `--transformer pseudonymize|process`, `--vault memory|json|process`, plus `--detector-command`, `--policy-command`, `--transformer-command`, `--vault-command`, and `--process-timeout-ms` for process plugins (`docs/process-plugin.md`). `--detector gliner2` also needs `--model-dir <dir>` and a binary built with `--features gliner2`; `--vault json` needs `--vault-file <path>` and cannot be combined with `--vault process`.

### OpenCode

Verified end-to-end with OpenCode 1.18.31 using a project-scoped config (no home-directory writes): the agent calls `private.inspect` and `private.sanitize` for real and replies with placeholders only.

`opencode.json` in the repository root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "do-context-shield": {
      "type": "local",
      "command": ["do-context-shield", "mcp-stdio"],
      "enabled": true
    }
  }
}
```

- Point `command[0]` at the absolute binary path when `do-context-shield` is not on `PATH`.
- `opencode mcp list` reports `✓ do-context-shield connected` when the registration is healthy.
- Tools surface as `<server>_<tool>` — `do-context-shield_private_inspect`, `do-context-shield_private_sanitize`, `do-context-shield_private_restore`. `opencode run "<prompt>"` drives them non-interactively; tool calls are printed to stderr and the final reply to stdout.
- Keep one stable `session` argument per task. The vault lives in the server process, so a later `opencode` run cannot restore an earlier run's placeholders; add `--vault-file <path>` to the server `command` (JSON vault) when restoration must survive a restart.

## Skill-only clients

Install `.agents/skills/private-data/SKILL.md` in the client's skills directory. Use the CLI for local sanitization. For reversible cross-process workflows, pass the same explicit `--vault-file` to `sanitize` and `restore`.

## Provider selection

The client still selects Claude, DeepSeek, Qwen, OpenRouter, a local model, or another provider. `do-context-shield` deliberately does not route or own that traffic.
