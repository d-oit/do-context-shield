# AGENTS.md

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
