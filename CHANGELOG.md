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

### Fixed

- Detector overlap resolution: longest-span-wins dedup so `api_key` matches are no longer double-counted as `phone`.
- Zero clippy warnings under `-D warnings` (error docs, lint migration, envelope construction without macro-hidden moves).
- Wired root `tests/` invariants into `crates/privacy-core/tests/privacy_invariants.rs` as real end-to-end tests (PII absence, stable placeholders, secret redaction, scope-limited restore).
