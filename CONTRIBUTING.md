# Contributing to do-context-shield

Thank you for considering contributing!

## Quick Links

- [Issues](https://github.com/d-oit/do-context-shield/issues)
- [Pull Requests](https://github.com/d-oit/do-context-shield/pulls)
- [Security Policy](SECURITY.md)

## Development Setup

### Prerequisites

- Rust 1.88 (see `rust-toolchain.toml`)

### Clone and Build

```bash
git clone https://github.com/d-oit/do-context-shield.git
cd do-context-shield
cargo build
cargo test --workspace
```

### Quality Gates

Always run before pushing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

## Project Rules

See [AGENTS.md](AGENTS.md):

- Keep the core provider-agnostic. No cloud LLM SDKs in runtime crates.
- Every detector, policy, transformer, and vault stays behind `plugin-api` traits.
- Prefer local/CPU implementations.
- Never log raw sensitive input or vault mappings.
- Secrets are redacted by default.

## Making Changes

### Branch Naming

| Type | Pattern | Example |
|---|---|---|
| Feature | `feat/description` | `feat/gliner2-detector` |
| Bug fix | `fix/description` | `fix/iban-false-positive` |
| Docs | `docs/description` | `docs/client-integration` |

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(detector): add local name detector
fix: resolve clippy warning in transformer
docs: update client-integration guide
```

## Pull Request Process

1. Fork the repository.
2. Create a feature branch.
3. Run quality gates.
4. Commit using Conventional Commits.
5. Open a PR against `main`.
6. Wait for CI to pass.

## Reporting Issues

Open an issue at <https://github.com/d-oit/do-context-shield/issues>.
For security vulnerabilities, see [SECURITY.md](SECURITY.md).
