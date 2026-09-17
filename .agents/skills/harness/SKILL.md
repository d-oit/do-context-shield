---
name: harness
description: >
  Harness engineering guide for do-context-shield — maps local sensors
  (do-harness.toml) and CI sensors to their fix procedures. Use when a
  sensor fires, before committing, or when setting up agent context.
  Triggers: "harness", "sensor fire", "CI failure", "quality gates".
category: development
license: MIT
compatibility: Requires the Rust workspace in this repository (Rust 1.88, edition 2024). No network access.
metadata:
  author: d-oit
  version: "1.0"
  tags: harness sensors ci quality self-correction
---

# Harness Skill

Agent = Model + Harness. Feedforward guides (this skill, `AGENTS.md`, `CONTRIBUTING.md`) prevent errors before coding; feedback sensors catch violations after coding.

- **Computational sensors** (deterministic): always trust the output, apply the fix hint, re-run.
- **Inferential guidance** (skill docs): direction, not commands.

## Sensor Response Protocol

1. Read the full error message.
2. Classify: fmt / lint / test / supply-chain / security / structure.
3. Apply the minimal fix — do not refactor unrelated code.
4. Re-run that sensor only.
5. Commit only when green.

## Sensor Quick Reference

| Sensor | Command | Config | Stage |
|--------|---------|--------|-------|
| fmt | `cargo fmt --all -- --check` | `rust-toolchain.toml` | hook, CI |
| check | `cargo check --workspace` | `do-harness.toml` | hook |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `Cargo.toml` lints | hook, CI |
| test | `cargo test --workspace` (`--all-features` in CI) | `do-harness.toml` | hook, CI |
| audit | `cargo audit` | `Cargo.lock` | CI |
| deny | `cargo deny check` | `deny.toml` | CI |
| publish-check | `cargo package --list -p <crate>` | per-crate `include` | CI |
| secret-scan | `gitleaks detect` | `.gitleaks.toml` | CI |
| structure | `python3 scripts/validate-structure.py` | script `required` list | CI |

## Fix Hints

- **fmt**: run `cargo fmt --all`.
- **clippy**: fix the warning; `unwrap()`/`expect()` are forbidden — propagate typed errors (`DetectorError`, `PolicyError`, `TransformError`, `VaultError`); document `Result` fns with `# Errors`.
- **test**: fix the failing test; for intentional behavior change, update the test first.
- **deny**: licenses limited to `MIT`, `Apache-2.0`, `Unicode-3.0`, `Unlicense`; no wildcards, no git deps, crates.io only. Optional deps (e.g. `gliner2` feature) are unchecked by default config — verify with `cargo deny check --all-features` before release.
- **structure**: required files, no `unwrap(`/`expect(`, 500 LOC per file.

## Steering Loop

When any sensor fires repeatedly (>2 times in one task): update the corresponding feedforward guide (`AGENTS.md`, `CONTRIBUTING.md`, or a skill) and note it in `CHANGELOG.md`.

## References

- Sensor wiring: [`do-harness.toml`](../../do-harness.toml) (local hooks), [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).
- Contributor workflow: [`CONTRIBUTING.md`](../../CONTRIBUTING.md). Project rules: [`AGENTS.md`](../../AGENTS.md).
