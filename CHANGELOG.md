# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial privacy boundary: regex detector, default policy, pseudonymize transformer, memory/JSON vaults.
- CLI (`sanitize`, `restore`, `inspect`, `mcp-stdio`) and MCP JSON-RPC stdio adapter.
- Agent skill (`skills/private-data/SKILL.md`).
- GitHub best-practice governance: CI, security scan, Dependabot, issue/PR templates.

### Fixed

- Detector overlap resolution: longest-span-wins dedup so `api_key` matches are no longer double-counted as `phone`.
- Zero clippy warnings under `-D warnings` (error docs, lint migration, envelope construction without macro-hidden moves).
- Wired root `tests/` invariants into `crates/privacy-core/tests/privacy_invariants.rs` as real end-to-end tests (PII absence, stable placeholders, secret redaction, scope-limited restore).
