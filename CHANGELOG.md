# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial privacy boundary: regex detector, default policy, pseudonymize transformer, memory/JSON vaults.
- CLI (`sanitize`, `restore`, `inspect`, `mcp-stdio`) and MCP JSON-RPC stdio adapter.
- Agent skills (`.agents/skills/private-data`, `.agents/skills/plugin-development`, indexed in `.agents/SKILLS.md`).
- GitHub best-practice governance: CI, security scan, Dependabot, issue/PR templates.
- Supply-chain policy (`deny.toml`: advisories, exact license allow-list, wildcard bans, crates.io-only sources) enforced by a CI dependency-policy job; Conventional Commits enforced on PR titles.
- Release readiness: per-crate descriptions and `include` whitelists, CI publish-surface check, ordered publish script (`scripts/publish-crates.sh`), automated release-note drafts.
- PR auto-labeling by changed paths (feeds release-drafter categories); label definitions in `.github/labels.yml`.
- GLiNER2 detector plugin (`detector-gliner2`): Rust-only local NER behind the `Detector` trait, 42-type PII taxonomy, fail-closed without a model, ONNX backend behind the `gliner2` Cargo feature; selectable via `--detector gliner2 --model-dir <dir>` and registry name `gliner2`.
- Process plugins (`plugin-process`): a user-configured local executable implements detection, policy, transformation, or storage over a newline-delimited JSON protocol, with fail-closed validation (spans and value equality, plan coverage, text/mapping consistency per action, vault resolvability of every emitted placeholder, exit status), an 8 MiB response cap, and `--process-timeout-ms` (default 30 000); selectable via `--detector`/`--policy`/`--transformer`/`--vault process` with the matching `--*-command` flag, MCP `ServerConfig`, and registry name `process` (`docs/process-plugin.md`).
- Harness wiring: `harness` agent skill (sensor map, response protocol), `.githooks/pre-commit` hook matching `do-harness.toml` sensors, structure validation enforced in CI, expanded `AGENTS.md`/`CONTRIBUTING.md` setup and workflow docs.
- Harness workflow adaptation (do-hub/do-harness model): machine-readable `plans/methods.json` (vertical-plugin-slice, spike-and-resolve, decision) and `plans/invariants.json` decision headers seeded with `do-harness seed`; development-methodology skills `htn-planner`, `spike-runner`, `skill-distiller`, and `skill-creator` (dependency-free structure gate at `.agents/skills/skill-creator/scripts/quick_validate.py`, no PyYAML); graded eval fixtures with hermetic walkthroughs for all seven skills (`do-harness eval --strict-fixtures` is green); new `skills` sensor (`scripts/check-skills.sh`) validating skill structure, fixture shape, method-to-sensor wiring, and repo paths named by skills, wired into the `verification`/`release` signal sets; `AGENTS.md` now carries the 6-phase workflow, fail-fast, steering loop, and evidence gates.

### Fixed

- Dependency policy: `cargo-deny` and `cargo-audit` now pass on the all-features graph — the reviewed `paste` exception (RUSTSEC-2024-0436, via `tokenizers` behind the `gliner2` feature) is documented in `deny.toml` and `.cargo/audit.toml`, and ISC joins the license allow-list for `libloading` (`ort` load-dynamic).
- `--vault-file` combined with `--vault memory` or `--vault process` is rejected instead of silently ignored, and a process transformer's text-consistency errors (leftover or dropped values) are reported ahead of vault lookup failures.
- Vault kind-aliasing: dedup keys now include entity kind, so the same value under different kinds yields distinct kind-tagged tokens (memory and JSON vaults).
- `detector-regex` compiles patterns once per process (`OnceLock`) instead of per call; added longest-span-wins regression coverage.
- Transformer rejects non-char-boundary ranges instead of panicking; `restore` skips malformed placeholders and keeps scanning (recovers nested valid tokens) instead of aborting.
- JSON vault: owner-only file permissions on Unix plus reload-on-insert so sequential CLI processes share counters and mappings.
- MCP 2026-07-28 compliance: `cacheScope` uses the spec `private` value, `session` is schema-required for `sanitize`/`restore` (server keeps a `default` fallback for older clients), detector selectable via `mcp-stdio --detector`, and the previously untested server now has JSON-RPC coverage (discover, list, round-trip, scope isolation, error paths).
- Detector overlap resolution: longest-span-wins dedup so `api_key` matches are no longer double-counted as `phone`.
- Zero clippy warnings under `-D warnings` (error docs, lint migration, envelope construction without macro-hidden moves).
- Wired root `tests/` invariants into `crates/privacy-core/tests/privacy_invariants.rs` as real end-to-end tests (PII absence, stable placeholders, secret redaction, scope-limited restore).
