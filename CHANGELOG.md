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

### Fixed

- Vault kind-aliasing: dedup keys now include entity kind, so the same value under different kinds yields distinct kind-tagged tokens (memory and JSON vaults).
- `detector-regex` compiles patterns once per process (`OnceLock`) instead of per call; added longest-span-wins regression coverage.
- Transformer rejects non-char-boundary ranges instead of panicking; `restore` skips malformed placeholders and keeps scanning (recovers nested valid tokens) instead of aborting.
- JSON vault: owner-only file permissions on Unix plus reload-on-insert so sequential CLI processes share counters and mappings.
- MCP 2026-07-28 compliance: `cacheScope` uses the spec `private` value, `session` is schema-required for `sanitize`/`restore` (server keeps a `default` fallback for older clients), detector selectable via `mcp-stdio --detector`, and the previously untested server now has JSON-RPC coverage (discover, list, round-trip, scope isolation, error paths).
- Detector overlap resolution: longest-span-wins dedup so `api_key` matches are no longer double-counted as `phone`.
- Zero clippy warnings under `-D warnings` (error docs, lint migration, envelope construction without macro-hidden moves).
- Wired root `tests/` invariants into `crates/privacy-core/tests/privacy_invariants.rs` as real end-to-end tests (PII absence, stable placeholders, secret redaction, scope-limited restore).
