---
name: plugin-development
description: >
  Implement a new detector, policy, transformer, or vault plugin for do-context-shield.
  Use when asked to "add a detector", "support a new entity type", "customize the policy",
  "add a vault backend", or change what gets detected, decided, transformed, or stored.
license: MIT
metadata:
  author: d-oit
  version: "1.0"
  category: development
  compatibility: Requires the Rust workspace in this repository (Rust 1.88, edition 2024). Heavy model dependencies must stay behind opt-in Cargo features.
  tags: plugin detector policy transformer vault rust
---

# Plugin Development Skill

Every runtime capability in `do-context-shield` is replaceable behind a `plugin-api` trait.
Follow this skill to add a new implementation without breaking the privacy boundary.

## Capability map

| Capability | Trait (`crates/plugin-api/src/lib.rs`) | Built-in | Future direction |
|---|---|---|---|
| detection | `Detector::detect` | `detector-regex`, `detector-gliner2` (local ONNX NER, `gliner2` feature), `plugin-process` (`detect`) | custom local NER, rules (`docs/plugins.md`) |
| policy | `Policy::plan` | `policy-default`, `plugin-process` (`plan`) | project / enterprise DLP policy |
| transformation | `Transformer::transform` | `transformer-pseudonymize`, `plugin-process` (`transform`) | redact, generalize, encrypt |
| storage | `Vault::get_or_insert`, `Vault::resolve` | `vault-memory`, `vault-json`, `plugin-process` (`vault_get_or_insert`, `vault_resolve`) | SQLite, OS keychain |

## Workflow

1. Read the trait contract in `crates/plugin-api/src/lib.rs` first. Do not change the trait unless the change is genuinely cross-plugin.
2. Create `crates/<name>/` with `Cargo.toml` (workspace inheritance: `version.workspace`, `edition.workspace`, `license.workspace`, `[lints] workspace = true`) and `src/lib.rs`.
3. Register the plugin by logical name in `crates/plugin-registry/src/lib.rs` (`detector()`, `policy()`, `transformer()`, or `vault()`).
4. Select it at the CLI: `--detector`, `--policy`, `--transformer`, or `--vault` with the logical name. Process plugins need their command flag (`--detector-command`, `--policy-command`, `--transformer-command`, `--vault-command`) and share `--process-timeout-ms`; `gliner2` needs `--model-dir <dir>` and `--vault json` needs `--vault-file <path>`. The pipeline composes as `Detector -> Policy -> Transformer -> Vault`.
5. Add unit tests in the new crate and extend `crates/privacy-core/tests/` invariants if behavior changes.
6. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`. If the crate has an opt-in feature, also run `cargo check -p <crate> --features <feature>` and `cargo clippy -p <crate> --all-targets --features <feature> -- -D warnings`.

## Hard rules (from AGENTS.md)

- Keep the core provider-agnostic. Never add cloud LLM SDKs to runtime crates.
- Prefer local/CPU implementations. Heavy native dependencies (e.g. ONNX Runtime) must stay behind an opt-in Cargo feature that is off by default, so the base workspace builds light and offline.
- New crates.io dependencies must satisfy `deny.toml` (license allow-list, no wildcards, crates.io-only); note that `cargo deny check` uses default features, so verify feature-gated trees explicitly before release.
- Never log raw sensitive input or vault mappings.
- Use explicit session scopes (`ScopeId`) for mappings.
- Preserve semantic relationships when transforming entities (repeated entity → stable token; see overlap handling in `detector-regex`).
- Secrets are redacted (`Action::Redact`), never pseudonymized.
- `unwrap()` and `expect()` are forbidden; propagate typed errors (`DetectorError`, `PolicyError`, `TransformError`, `VaultError`).
- Document every `Result`-returning function with an `# Errors` section.
- Keep files under 500 LOC where practical.

## Cross-language plugins

For non-Rust replacements, do not use a dynamic-library ABI. Implement the process protocol in `docs/process-plugin.md` (newline-delimited JSON on stdin/stdout); `crates/plugin-process` already drives detectors, policies, transformers, and vaults that way (`--detector`/`--policy`/`--transformer`/`--vault process` with the matching `--*-command` flag). A process transformer stays reversible only when the configured vault resolves the placeholders it emits.

## Red flags

- [ ] New dependency on a network client or provider SDK in a runtime crate
- [ ] `println!`/`eprintln!`/`log` of `input`, `original`, `value`, or vault contents
- [ ] Session id ignored or shared across unrelated tasks
- [ ] Overlapping entity spans emitted without longest-span-wins dedup
