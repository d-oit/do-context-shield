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
```

Then run the quality gates below.

### Quality Gates

Install the harness CLI once (Linux/macOS; see the
[do-harness README](https://github.com/d-o-hub/do-harness) for other platforms).
The installer is fetched from the commit the `v0.1.1` tag points at — not from
upstream `main` — so an unrelated upstream change cannot alter the script that
runs here:

```bash
curl -fsSL https://raw.githubusercontent.com/d-o-hub/do-harness/32120c3644ac30236970809e2745981657efd5a7/scripts/install.sh \
  | sh -s -- --version v0.1.1
```

Then run the whole local gate with one command:

```bash
do-harness verify --set verification          # full local gate (sensor set declared in do-harness.toml)
do-harness verify --changed --set verification   # only sensors whose inputs changed
do-harness explain --set verification --changed  # show the selection without running it
do-harness status --set verification             # evidence freshness without running sensors
do-harness verify --only <name>                  # a single sensor by name
do-harness eval --strict-fixtures                # skill structure + hermetic walkthroughs
```

Every sensor command and signal set has exactly one executable definition: `do-harness.toml`. The sensor map, stages, and fix hints live in [.agents/skills/harness/SKILL.md](.agents/skills/harness/SKILL.md) — its command column is a mirror that `scripts/check-skills.sh` validates against the config, so docs never fork from it silently; anywhere else, link the config instead of copying argv.

Local sensors and their hook wiring are declared in `do-harness.toml`, with shell implementations in `scripts/check-*.sh`; CI enforces the same sensors plus structure validation, secret scanning, publish-surface checks, and a macOS/Windows test matrix (default-feature tests plus `cargo check --workspace --all-features --all-targets`, so feature-gated code is compiled on every supported OS; the Linux jobs cover the `--all-features` test run). The `Harness` CI job installs the pinned `do-harness`, runs the `ci` signal set with `--format json --strict`, and verifies evidence freshness (`status --set ci`); the skill corpus runs inside that set through the `skill-evals` sensor, which fails on a failed graded assertion.

Git hooks: `.githooks/` is this repository's hook source of truth — versioned and reviewed alongside the code (`git config core.hooksPath .githooks`). The `pre-commit`, `commit-msg`, and `pre-push` hooks are hand-written mirrors of the sensor sets declared in `do-harness.toml`, so they run without the do-harness binary; `do-harness hook install` is a per-developer alternative that writes managed hooks into `.git/hooks/`; the two do not combine, because a `core.hooksPath` pointing at `.githooks` makes git ignore `.git/hooks/` entirely — pick one. The `hooks` sensor enforces that choice plus sensor parity: every sensor `do-harness.toml` declares for a hook must actually be invoked by that hand-written hook, so adding a sensor without mirroring it fails locally instead of silently weakening the gate. (Known upstream issues for the pinned v0.1.1: [d-o-hub/do-harness#108](https://github.com/d-o-hub/do-harness/issues/108) — `hook status`/`doctor` ignore the `core.hooksPath` shadowing — and [d-o-hub/do-harness#159](https://github.com/d-o-hub/do-harness/issues/159) — `hook install`/`uninstall` ignore `--dry-run`.)

## Agent workflow

Agent-facing work follows the 6-phase harness protocol in [AGENTS.md](AGENTS.md) (recon → plan → spike → failing contract test → sensors → distillation), with fail-fast, steering-loop, and evidence rules there; `.agents/skills/harness/SKILL.md` carries the sensor response protocol, and `htn-planner`, `spike-runner`, `skill-distiller`, `skill-creator` carry the runbooks. Durable rules live in `plans/invariants.json` with the sensor that enforces each one (`do-harness seed`).

## Project Rules

Binding project rules live in [AGENTS.md](AGENTS.md) and apply to every contribution.

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
6. Wait for CI to pass — and keep the branch up to date. `main` requires the `CI Success` check
   on an up-to-date branch, and the check is bound to the PR's merge commit, so any other merge
   makes your checks stale. Rebase with `scripts/update-pr-branches.sh` (or
   `gh pr update-branch --rebase <number>`) and let the checks re-run; GitHub auto-merge will not
   update the branch for you.

## Release Process

For complete release details and contracts, see [docs/releasing.md](docs/releasing.md).

Release notes are drafted automatically from merged PRs (see `.github/release-drafter.yml`). Tagged release triggers (`v*.*.*`) execute release preflight verification, build cross-platform binaries, run release smoke tests, upload release assets with `SHA256SUMS`, and publish crates bottom-up.

### Preflight and Publishing

Local preflight verification, release smoke tests, and bottom-up publishing (including `cargo login` for a crate's first publish) are documented in [docs/releasing.md](docs/releasing.md) — follow that canonical procedure instead of duplicating its commands here.

## Reporting Issues

Open an issue at <https://github.com/d-oit/do-context-shield/issues>.
For security vulnerabilities, see [SECURITY.md](SECURITY.md).
