# Architecture

## Boundary

The project has four layers:

1. `plugin-api` — stable contracts.
2. concrete plugins — detection, judging, policy, transformation, vault implementations.
3. `do-context-shield-core` — composition and invariants.
4. adapters — CLI and MCP stdio.

No provider SDK belongs in the runtime core.

## Replacement model

A plugin is selected by logical name in `plugin-registry`. Detection, policy, transformation, and storage all ship compiled-in implementations, which keeps the ABI surface small and portable.

Any of them can instead run behind a process protocol (newline-delimited JSON over stdin/stdout, `docs/process-plugin.md`) rather than a Rust dynamic-library ABI: `crates/plugin-process` provides detector, judge, policy, transformer, and vault adapters that drive a user-configured local executable, so an implementation stays replaceable across Rust, compiler, and libc versions — and across languages.

## Semantic judging

Detection is context-blind by nature: a regex cannot tell a private address from a role address or a reserved test domain. An optional `SemanticJudge` stage between detection and policy lets a local rules engine, a local model, or a hosted judge label, score, or abstain per candidate. Models may classify, select, score, or abstain — they never generate the protected value: deterministic code owns spans, transformations, policy, and restoration. Judging is off by default and selected with `--judge`; it can never weaken secret redaction.

## Agent integration

The agent remains authoritative:

```text
agent loop
   |
   +-- private.sanitize --> local process
   |
   +-- remote model/tool receives sanitized context
   |
   +-- private.restore  --> local process
```

MCP and skill files are adapters, not a second agent runtime.

## Non-goals

- LLM routing.
- Provider billing/quotas.
- Cloud telemetry.
- Owning the coding agent's plan/execute loop.
