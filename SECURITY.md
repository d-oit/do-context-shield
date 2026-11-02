# Security Policy

## Supported Versions

Security fixes are applied to the `main` branch only.

| Version | Supported |
| ------- | --------- |
| latest `main` | ✅ |
| older snapshots | ❌ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via
[GitHub Security Advisories](https://github.com/d-oit/do-context-shield/security/advisories/new).

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours and a full response within 7 days.

## Project-Specific Practices

- No telemetry, no network calls, no cloud model dependency.
- Secrets are redacted by default, never pseudonymized.
- The local JSON vault contains original values by design — protect that file. An encrypted vault (`--vault-key-file`) protects it at rest only: a same-user process that can read the key can decrypt it. Keep the key file owner-only (mode `0600`) and out of backups, sync folders, and shell history.
- Never log raw sensitive input or vault mappings. Audit records carry operation metadata only, are owner-private, and are hash-chained; `do-context-shield verify-audit --audit-file <path>` detects modification, deletion, truncation, and reordering (reporting only a record index and safe category). A same-account attacker can rewrite the whole chain, so this is tamper-evident, not tamper-proof. Rotation is opt-in (`--audit-max-records`/`--audit-max-bytes`).
- MCP stdio is bounded (`DEFAULT_MAX_REQUEST_BYTES`, 4 MiB per request frame) and rejects JSON-RPC batch arrays; an oversized frame never reaches parsing, a plugin, or the vault. See `docs/client-integration.md`.
- A configured plugin executable is trusted local software: point `--*-command` only at a path you control, and treat process isolation as containment, not a sandbox — the child can read the same files your account can.
- Run `cargo audit` before releases; Dependabot alerts are enabled.

The full contract — assets, trust boundaries, guarantees, and non-goals (prompt
injection, downstream tool authorization, model-output handling) — is in
[`docs/architecture.md`](docs/architecture.md#threat-model).
