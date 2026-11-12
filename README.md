# do-context-shield

[![CI](https://github.com/d-oit/do-context-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/d-oit/do-context-shield/actions/workflows/ci.yml)
[![Secret scan](https://github.com/d-oit/do-context-shield/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/d-oit/do-context-shield/actions/workflows/secret-scan.yml)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-orange.svg)](LICENSE)

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

## Installation and Release Contract

`do-context-shield` supports the following release distribution paths:

1. **crates.io (Recommended for Rust users)**:
   ```bash
   cargo install do-context-shield
   ```
   Or pin a specific release version:
   ```bash
   cargo install do-context-shield --version 0.1.0
   ```

2. **GitHub Releases (Pre-compiled platform binaries)**:
   Pre-built binary archives and `SHA256SUMS` checksums are published on the [GitHub Releases](https://github.com/d-oit/do-context-shield/releases) page for supported targets:
   - `x86_64-unknown-linux-gnu` (Linux x86_64)
   - `x86_64-apple-darwin` (macOS Intel)
   - `aarch64-apple-darwin` (macOS Apple Silicon)
   - `x86_64-pc-windows-msvc` (Windows x86_64)

3. **Source Build**:
   ```bash
   git clone https://github.com/d-oit/do-context-shield.git
   cd do-context-shield
   cargo install --path crates/do-context-shield-cli
   ```

Note: Operating system package managers (e.g. Homebrew formula, apt repositories) are planned distribution channels and not yet active. See `docs/releasing.md` for the full release contract.

## First vertical slice

- Regex detector for email, phone, IBAN, IPv4/IPv6, SSN, credit-card and US bank-routing numbers, dates of birth, passports, driver's licenses, database connection URIs (`db_credential`: postgres, mysql, mongodb, redis, etc. with credentials), private-key blocks (PEM/OpenPGP/PKCS#8), AWS/Google/Slack/GitHub tokens (classic and fine-grained `github_pat_`), Stripe keys and webhook secrets, Hugging Face/PyPI/GitLab tokens, JWTs, `password=`/`Bearer` style secrets, and common API-key shapes. Structural candidates are validated before reporting: Luhn for cards, ABA for routing numbers, byte-bounded octets for IPv4, ISO 13616 mod-97 for IBAN.
- Process plugins: local executables implement detection, judging, policy, transformation, or storage over newline-delimited JSON. Select a capability with `--<capability> process`, pass its executable with `--<capability>-program`, and repeat `--<capability>-arg` for each literal argument; see `docs/process-plugin.md`.
- Default policy: pseudonymize personal identifiers; redact secrets. An opt-in `matrix` policy (`--policy matrix`, config `[policy_matrix]`) adds jurisdiction-adequacy pair checks and purpose-conditional rules (`docs/configuration.md`); it is never the default, and secrets stay redacted under every rule.
- Optional semantic judge (`--judge heuristics` or a local process judge) that labels candidates; secrets stay redacted regardless of judge output.
- In-memory vault with session scoping, plus an opt-in JSON vault for cross-process workflows that can be encrypted at rest with a key file (`create-key` generates a restrictive key; `--vault-key-file` selects it; `encrypt-vault` migrates an existing plaintext vault).
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
printf '%s' '__DO_PRIVATE_EMAIL_1_9F3A2C7B5D1E4F08__' | do-context-shield restore --session work-1 --vault-file ~/.local/share/do-context-shield/vault.json
printf '%s' 'contact me at alice@example.com' | do-context-shield inspect
printf '%s' 'contact me at alice@example.com' | do-context-shield sanitize --session work-1 --vault-file ~/.local/share/do-context-shield/vault.json

do-context-shield mcp-stdio --vault-file ~/.local/share/do-context-shield/vault.json

do-context-shield config   # effective plugin/context selection with its source layer

do-context-shield doctor --detector gliner2 --model-dir ~/.local/share/do-context-shield/gliner2-onnx
# ^ local preflight: configured and loadable, or a stable reason_code (exit 1)

do-context-shield verify-audit --audit-file ~/.local/share/do-context-shield/audit.jsonl
# ^ hash-chain integrity report: record index + safe category only
```

`restore` only resolves tokens held by the same local vault/session, and only the exact token the vault minted. The built-in memory and JSON vaults add per-mapping entropy, so a fabricated `__DO_PRIVATE_*__` string does not resolve; process vaults own their token policy and must be trusted local plugins. Nothing leaves the process unless a caller explicitly sends sanitized text onward. The optional JSON vault contains original values by design; protect that local file and use it only when cross-process restoration is required.

A `do-context-shield.toml` in the working directory, `$HOME/.config/do-context-shield/config.toml`, or the path passed with `--config` supplies defaults for plugin selection, vault, enforcement context, and the process timeout; explicitly passed CLI flags override it. The MCP server is the exception: `mcp-stdio` reads a configuration file only when `--config <path>` names it, so the project directory it is spawned in cannot configure it. Unknown fields and unknown plugin names are rejected at startup. See `docs/configuration.md` for the reference and `do-context-shield.toml.example` for a starting point.

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
- The MCP surface defaults to `sanitize` and `inspect`; `restore` resolves raw values and stays out of the model loop unless `--tools` opts it in.
- Sanitized text is a separate value from the original input.

This is a foundation, not a claim of complete DLP coverage. Name/entity detection should be added through a local detector plugin such as GLiNER2 rather than hard-coded into the core.

### What this does not protect against

- **Prompt injection or hostile instructions.** Sanitization rewrites detected spans; it does not neutralize untrusted instructions, jailbreaks, or hidden directives, and it is not a security boundary for instruction integrity.
- **Downstream tool authorization.** The product does not decide which tools a model may call, or what a tool is allowed to read or do.
- **Model output.** Validating, trusting, or acting on a model reply is the caller/harness responsibility, including placeholder-shaped tokens the model invents.
- **A compromised local account.** A same-user process can read the vault, key file, and audit log; the encrypted vault protects data at rest, not from the account that owns the key. Plugin executables and their code are trusted local software, and process isolation is not sandboxing.
- **Complete detection.** The regex detector covers selected structured formats; semantic NER is model-dependent; free-form names and unknown formats can be missed.

See the [threat model](docs/architecture.md#threat-model) for assets, trust boundaries, guarantees, and the safe deployment profiles (CLI, MCP stdio, encrypted JSON vault, audit logging, process plugins).

## License

PolyForm Noncommercial 1.0.0 — see [LICENSE](LICENSE). Commercial licenses available — see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
