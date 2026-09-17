# Architecture

## Boundary

The project has four layers:

1. `plugin-api` — stable contracts.
2. concrete plugins — detection, policy, transformation, vault implementations.
3. `do-context-shield-core` — composition and invariants.
4. adapters — CLI and MCP stdio.

No provider SDK belongs in the runtime core.

## Replacement model

A plugin is selected by logical name in `plugin-registry`. Detection, policy, transformation, and storage all ship compiled-in implementations, which keeps the ABI surface small and portable.

Any of them can instead run behind a process protocol (newline-delimited JSON over stdin/stdout, `docs/process-plugin.md`) rather than a Rust dynamic-library ABI: `crates/plugin-process` provides detector, policy, transformer, and vault adapters that drive a user-configured local executable, so an implementation stays replaceable across Rust, compiler, and libc versions — and across languages.

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
