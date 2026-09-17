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
- The local JSON vault contains original values by design — protect that file.
- Never log raw sensitive input or vault mappings.
- Run `cargo audit` before releases; Dependabot alerts are enabled.
