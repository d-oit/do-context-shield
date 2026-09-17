# Contributing to do-context-shield

Thank you for considering contributing!

## Quick Links

- [Issues](https://github.com/d-oit/do-context-shield/issues)
- [Pull Requests](https://github.com/d-oit/do-context-shield/pulls)
- [Security Policy](SECURITY.md)

## Development Setup

### Prerequisites

- Rust via [rustup](https://rustup.rs/) — the toolchain in `rust-toolchain.toml` installs automatically on first cargo invocation.
- Python 3 (for `scripts/validate-structure.py`).
- Optional but recommended for full gates: `cargo install cargo-deny cargo-audit`.

### Clone and Build

```bash
git clone https://github.com/d-oit/do-context-shield.git
cd do-context-shield
git config core.hooksPath .githooks  # install the pre-commit hook (see do-harness.toml)
cargo build
cargo test --workspace
```

### Quality Gates

Always run before pushing (see the `harness` skill for the sensor map and fix procedures):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
python3 scripts/validate-structure.py
```

Local hooks are declared in `do-harness.toml` (`pre-commit`: fmt, check; `pre-push`: fmt, check, clippy, test) and implemented in `.githooks/`. CI enforces the same sensors plus audit, deny, structure validation, secret scanning, and publish-surface checks.

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

## Release Process

Release notes are drafted automatically from merged PRs (see `.github/release-drafter.yml`).

### Publishing to crates.io

Every publishable crate defines an `include` whitelist in its `Cargo.toml`
so internal files never end up in the published package. Verify the surface with:

```bash
cargo package --list -p <crate-name>
```

(Requires a clean tree; pass `--allow-dirty` for local iteration.)

Workspace crates depend on each other via versioned path dependencies, so they
must be published **bottom-up in dependency order** — `cargo publish` resolves
siblings through the crates.io index:

```bash
scripts/publish-crates.sh --dry-run  # rehearse the package surface
CARGO_REGISTRY_TOKEN=... scripts/publish-crates.sh  # publish in order
```

## Reporting Issues

Open an issue at <https://github.com/d-oit/do-context-shield/issues>.
For security vulnerabilities, see [SECURITY.md](SECURITY.md).
