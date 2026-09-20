# Contributing to do-context-shield

Thank you for considering contributing!

## Quick Links

- [Issues](https://github.com/d-oit/do-context-shield/issues)
- [Pull Requests](https://github.com/d-oit/do-context-shield/pulls)
- [Security Policy](SECURITY.md)

## Contributor License Agreement

All contributions require agreement to the [Contributor License Agreement](CLA.md).
Every pull request includes a checkbox confirming that you have read and agree to the
CLA; marking it and submitting the pull request is your acceptance.

The CLA grants the project owner the rights needed to relicense contributions
(including for the commercial license offered alongside PolyForm Noncommercial
1.0.0), while contributions remain the contributor's own copyright.

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

Install the harness CLI once (Linux/macOS; see the
[do-harness README](https://github.com/d-o-hub/do-harness) for other platforms):

```bash
curl -fsSL https://raw.githubusercontent.com/d-o-hub/do-harness/main/scripts/install.sh \
  | sh -s -- --version v0.1.1
```

Then run the whole local gate with one command, or the sensors directly:

```bash
do-harness verify --set verification          # fmt, check, clippy, test, loc, skills, deps, audit, commitlint
do-harness verify --changed --set verification   # only sensors whose inputs changed
do-harness explain --set verification --changed  # show the selection without running it
do-harness status --set verification          # evidence freshness without running sensors
do-harness eval --strict-fixtures             # skill structure + hermetic walkthroughs
bash scripts/check-skills.sh                  # skill gate + planning-catalog check

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
python3 scripts/validate-structure.py
```

Local sensors are declared in `do-harness.toml` (`pre-commit`: fmt, check, loc; `pre-push`: the full verification set) with shell implementations in `scripts/check-*.sh`; CI enforces the same sensors plus structure validation, secret scanning, and publish-surface checks. The `Harness` CI job installs the pinned `do-harness` and runs the `ci` signal set (`verification` minus `commitlint`, since PR titles are the enforced commit contract) with `--format json --strict`, verifies evidence freshness (`status --set ci`), and runs `do-harness eval --strict-fixtures` for the skill corpus.

Git hooks: `.githooks/` is this repository's hook source of truth — versioned and reviewed alongside the code (`git config core.hooksPath .githooks`). `do-harness hook install` is a per-developer alternative that writes managed hooks into `.git/hooks/`; the two do not combine, because a `core.hooksPath` pointing at `.githooks` makes git ignore `.git/hooks/` entirely — pick one. (Upstream: `hook install`/`hook status` do not yet detect that conflict — [d-o-hub/do-harness#108](https://github.com/d-o-hub/do-harness/issues/108).)

## Agent workflow

Work follows the harness phases in `AGENTS.md`: recon -> plan (`plans/methods.json`: `vertical-plugin-slice`, `spike-and-resolve`, `decision`, persisted with `do-harness task add --method`) -> spike when uncertain (throwaway under `target/spikes/`) -> failing contract test first -> implementation -> sensors -> distillation back into `.agents/skills/`. Durable rules live in `plans/invariants.json` with the sensor that enforces each one (`do-harness seed`). Three consecutive sensor failures on one subtask halt the loop (fail-fast); `.agents/skills/harness/SKILL.md` carries the response protocol, and `htn-planner`, `spike-runner`, `skill-distiller`, `skill-creator` carry the rest of the runbooks.

## Project Rules

See [AGENTS.md](AGENTS.md):

- Keep the core provider-agnostic. No cloud LLM SDKs in runtime crates.
- Every detector, judge, policy, transformer, and vault stays behind `plugin-api` traits.
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

Use [Conventional Commits](https://www.conventionalcommits.org/). CI checks the type prefix on PR
titles (`feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`)
via `action-semantic-pull-request`, and the local `commitlint` sensor
(`scripts/check-commitlint.sh`) checks the same shape on the last commit. Squash merges use the PR
title as the commit subject, so keep both conventional. Subjects are conventionally lowercase, but
case is not enforced.

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
