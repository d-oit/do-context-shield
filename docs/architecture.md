# Architecture

## Boundary

The project has four layers:

1. `plugin-api` — stable contracts.
2. concrete plugins — detection, policy, transformation, vault implementations.
3. `do-context-shield-core` — composition and invariants.
4. adapters — CLI and MCP stdio.

No provider SDK belongs in the runtime core.

## Replacement model

A plugin is selected by logical name in `plugin-registry`. The first release uses compiled-in plugins because this keeps the ABI surface small and portable.

Future external plugins should use a process protocol (JSON Lines over stdin/stdout) rather than a Rust dynamic-library ABI. That makes plugins replaceable across Rust/compiler/libc versions.

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
