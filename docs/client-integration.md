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

- `tools/list` returns `context.sanitize`, `context.restore`, `context.inspect`, `context.forget` in a fixed order with `ttlMs: 300000` and `cacheScope: private` (session-scoped results must not sit in shared caches).
- `sanitize` and `restore` schemas require `text` and `session`. `context.sanitize` still accepts a missing `session` as `default` for older clients, but `context.restore` resolves raw values and rejects a call without an explicit `session`. Always send an explicit per-task session.
- `context.forget` deletes every locally stored placeholder for an explicit session (required, no fallback) and answers `{"session":"…","forgotten":true}`; call it when a task's context is done. The CLI equivalent is `do-context-shield forget --session <id>` (same vault flags as `sanitize`/`restore`).
- `mcp-stdio --vault-ttl-seconds <SECONDS>` bounds the lifetime of in-process memory-vault mappings (memory vault only; combining it with `--vault json`/`process` is rejected). The server also drops expired mappings before every `context.sanitize`, and `resolve`/`get_or_insert` never resurrect an expired mapping.
- `context.sanitize` accepts the optional enforcement-context arguments `recipient` (`local`/`trusted`/`external`/`unknown`, default `external`), `data_category` (`non_personal`/`personal`/`special_category`, default `personal`), `purpose`, and `jurisdiction`. Omitted fields keep those conservative defaults; an unknown enum name or a wrong JSON type is an error, never a silent downgrade. The CLI exposes the same fields on `sanitize` as `--recipient`, `--data-category`, `--purpose`, and `--jurisdiction`.
- Plugin selection: `--detector regex|gliner2|process`, `--policy default|process`, `--transformer pseudonymize|process`, `--vault memory|json|process`, plus `--detector-command`, `--policy-command`, `--transformer-command`, `--vault-command`, and `--process-timeout-ms` for process plugins (`docs/process-plugin.md`). `--detector gliner2` also needs `--model-dir <dir>` and a binary built with `--features gliner2`; `--vault json` needs `--vault-file <path>` and cannot be combined with `--vault process`.
- Configuration: `--config <path>`, `./do-context-shield.toml`, or `$HOME/.config/do-context-shield/config.toml` can supply any of the options above as defaults, so MCP registrations can stay short; an explicit flag overrides the file value (`docs/configuration.md`).

### Client registration

Any MCP stdio client can register the server — the transport is plain stdio JSON-RPC, so nothing is client-specific beyond the config-file shape. Verified end-to-end in this repository with **OpenCode 1.18.31** and **omp 18.2.4**; Claude Code 1.0.44 accepted the project registration (`claude mcp get` resolves it) but its model turn could not run in the verification environment (invalid API credentials), and the Codex shape below comes from its own documentation and is not exercised here.

Shared notes for every client:

- Keep one stable `session` argument per task. The vault lives in the server process, so a later client run cannot restore an earlier run's placeholders; add `--vault-file <path>` to the server command (JSON vault) when restoration must survive a restart.
- Point the command at the absolute binary path when `do-context-shield` is not on `PATH`.

#### OpenCode

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

- `opencode mcp list` reports `✓ do-context-shield connected` when the registration is healthy.
- Tools surface as `<server>_<tool>` — `do-context-shield_context_inspect`, `do-context-shield_context_sanitize`, `do-context-shield_context_restore`. `opencode run "<prompt>"` drives them non-interactively; tool calls are printed to stderr and the final reply to stdout.

#### omp

`.omp/mcp.json` in the repository root:

```json
{
  "$schema": "https://raw.githubusercontent.com/can1357/oh-my-pi/main/packages/coding-agent/src/config/mcp-schema.json",
  "mcpServers": {
    "do-context-shield": {
      "type": "stdio",
      "command": "do-context-shield",
      "args": ["mcp-stdio"]
    }
  }
}
```

- omp exposes each tool as an `xd://` device — `xd://mcp__do_context_shield_context_inspect`, `xd://mcp__do_context_shield_context_sanitize`, `xd://mcp__do_context_shield_context_restore`.
- `omp -p --no-session --mode=json "<prompt>"` runs a non-interactive turn; the JSON stream carries `tool_execution_start` / `tool_execution_end` events with the tool result.

#### Other clients

- Claude Code 1.0.44: `claude mcp add -s project do-context-shield <binary> mcp-stdio` writes a project `.mcp.json` (`type: "stdio"`, `command`, `args`, `env`); `claude mcp get do-context-shield` resolves project scope. For non-interactive runs pass the prompt on stdin and pin the server with `--mcp-config .mcp.json --strict-mcp-config --allowedTools mcp__do-context-shield`.
- Codex: `~/.codex/config.toml` or project `.codex/config.toml`:

```toml
[mcp_servers.do-context-shield]
command = "do-context-shield"
args = ["mcp-stdio"]
```

## Skill-only clients

Install `.agents/skills/private-data/SKILL.md` in the client's skills directory. Use the CLI for local sanitization. For reversible cross-process workflows, pass the same explicit `--vault-file` to `sanitize` and `restore`.

## Provider selection

The client still selects Claude, DeepSeek, Qwen, OpenRouter, a local model, or another provider. `do-context-shield` deliberately does not route or own that traffic.
