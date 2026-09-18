# do-context-shield

[![CI](https://github.com/d-oit/do-context-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/d-oit/do-context-shield/actions/workflows/ci.yml)
[![Secret scan](https://github.com/d-oit/do-context-shield/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/d-oit/do-context-shield/actions/workflows/secret-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A local privacy engine for coding agents.

`do-context-shield` does **not** own the agent loop and does **not** proxy an LLM provider. It creates a privacy boundary that any coding client can use.

```text
Claude Code / OpenCode / Codex / Gemini CLI / custom agent
                         |
                    agent skill
                         |
                    do-context-shield
                  /      |      \
            detect   transform   vault
                         |
                  sanitized context
                         |
                  original LLM client
```

## First vertical slice

- Regex detector for email, phone, IBAN, IPv4 and common API-key shapes.
- Process plugins: a local executable can implement detection, judging, policy, transformation, or storage over newline-delimited JSON (`--detector process --detector-command "<program> [args...]"`, likewise `--judge`, `--policy`, `--transformer`, and `--vault` with their own command flags; see `docs/process-plugin.md`).
- Default policy: pseudonymize personal identifiers; redact secrets.
- Optional semantic judge (`--judge heuristics` or a local process judge) that labels candidates; secrets stay redacted regardless of judge output.
- In-memory vault with session scoping.
- CLI over stdin/stdout.
- MCP-style JSON-RPC stdio adapter with `context.sanitize`, `context.restore`, `context.inspect`, and `context.forget` tools.
- Agent skill instructions usable by coding clients that can execute shell tools.

## Architecture

All runtime capabilities are traits behind `plugin-api`:

```text
Detector -> Policy -> Transformer -> Vault
```

Each implementation is replaceable by name through `plugin-registry`. The core deliberately contains no provider SDK and no network client.

## Commands

```bash
do-context-shield sanitize --session work-1 < prompt.txt
printf '%s' '__DO_PRIVATE_EMAIL_1__' | do-context-shield restore --session work-1 --vault-file ~/.local/share/do-context-shield/vault.json
printf '%s' 'contact me at alice@example.com' | do-context-shield inspect
printf '%s' 'contact me at alice@example.com' | do-context-shield sanitize --session work-1 --vault-file ~/.local/share/do-context-shield/vault.json

do-context-shield mcp-stdio --vault-file ~/.local/share/do-context-shield/vault.json
```

`restore` only resolves tokens held by the same local vault/session. Nothing leaves the process unless a caller explicitly sends sanitized text onward. The optional JSON vault contains original values by design; protect that local file and use it only when cross-process restoration is required.

A `do-context-shield.toml` in the working directory, `$HOME/.config/do-context-shield/config.toml`, or the path passed with `--config` supplies defaults for plugin selection, vault, enforcement context, and the process timeout; explicitly passed CLI flags override it. Unknown fields and unknown plugin names are rejected at startup. Start from `do-context-shield.toml.example`.

## Agent skill

Install `.agents/skills/private-data/SKILL.md` into a coding client skill directory (for example `.agents/skills/private-data/SKILL.md`). The skill tells the agent when to sanitize sensitive context and how to restore placeholders after tool/model output.

MCP registration is verified end-to-end with OpenCode 1.18.31 and omp 18.2.4 (`opencode.json` / `.omp/mcp.json`); see `docs/client-integration.md` for the exact configs and the other clients' shapes.

## Security boundary

This first slice is intentionally conservative:

- No telemetry.
- No network calls.
- No cloud model dependency.
- Secrets are redacted rather than pseudonymized.
- Vault scope is explicit.
- Sanitized text is a separate value from the original input.

This is a foundation, not a claim of complete DLP coverage. Name/entity detection should be added through a local detector plugin such as GLiNER2 rather than hard-coded into the core.

## License

MIT — see [LICENSE](LICENSE).
