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
- Detector selection: `mcp-stdio --detector regex` (default), `mcp-stdio --detector gliner2 --model-dir <dir>` for local ONNX NER (requires a binary built with `--features gliner2`), or `mcp-stdio --detector process --detector-command "<program> [args...]"` for a local executable speaking the process protocol (`docs/process-plugin.md`).

## Skill-only clients

Install `.agents/skills/private-data/SKILL.md` in the client's skills directory. Use the CLI for local sanitization. For reversible cross-process workflows, pass the same explicit `--vault-file` to `sanitize` and `restore`.

## Provider selection

The client still selects Claude, DeepSeek, Qwen, OpenRouter, a local model, or another provider. `do-context-shield` deliberately does not route or own that traffic.
