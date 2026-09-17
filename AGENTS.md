# AGENTS.md

## Quick reference

| Task | Command |
|------|---------|
| Build | `cargo build` |
|Quality gates|`do-harness verify --set verification` (fmt, check, clippy, test, loc, deps, audit, commitlint), or directly: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, `cargo audit`, `python3 scripts/validate-structure.py`|
| Feature build | `cargo check -p <crate> --features <feature>` (e.g. `do-context-shield-detector-gliner2 --features gliner2`) |
| Setup | `git config core.hooksPath .githooks` after cloning |
| Sensors | Declared in `do-harness.toml`; procedures in `.agents/skills/harness/SKILL.md` |

## Change workflow

1. Discover: read the trait contract (`crates/plugin-api/src/lib.rs`) and relevant skill first.
2. Plan: identify affected files and test coverage.
3. Test-first: add or update tests before logic.
4. Implement: follow the project rules below.
5. Quality check: run the gates above; commit only when green (see `harness` skill).
6. Commit: Conventional Commits (`feat/fix/docs/...`).

## Project rules

- Keep the core provider-agnostic. Do not add cloud LLM SDKs to runtime crates.
- Every detector, policy, transformer, and vault implementation must remain replaceable behind `plugin-api` traits.
- Prefer local/CPU implementations.
- Never log raw sensitive input or vault mappings.
- Use explicit session scopes for mappings.
- Preserve semantic relationships when transforming entities.
- Secrets are redacted by default.
- Keep files under 500 LOC where practical.
- No hard-coded credentials or API keys.
- Rust 2024, strict lints, `unwrap()` and `expect()` are forbidden.
