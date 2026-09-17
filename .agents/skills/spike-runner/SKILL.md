---
name: spike-runner
description: >
  Execute isolated de-risking spikes for uncertain third-party APIs, model
  artifacts, wire protocols, or coding-client integrations, record the findings
  as traces, and clean the scratchpad. Use when a task has high uncertainty,
  when HTN decomposition flags a spike candidate, or when a minimal prototype
  must pass before a vertical slice is committed. Triggers: "spike",
  "uncertainty", "prototype", "de-risk", "unknown API".
license: MIT
metadata:
  version: "1.0"
  tags: spike prototype uncertainty de-risk scratchpad trace
---
# Spike Runner Skill

A spike is a throwaway experiment that produces knowledge, not production code.

## When to spike

- A third-party API, crate, model artifact, or wire protocol is uncertain.
- A performance boundary is unknown.
- A novel pattern needs validation before the slice (for example how a coding
  client performs the MCP handshake).
- `plans/methods.json` selected the `spike-and-resolve` method for the task.

## Execution steps

### 1. Create the spike

- Scratchpad under `target/spikes/<name>/` (gitignored) or another directory
  under `target/`.
- Write the hypothesis before the code: which unknown is being resolved, and
  which observation settles it.
- Use synthetic fixtures only — never real sensitive data, never a live vault
  mapping.

### 2. Execute the spike

- Run a real command; success is exit 0 (`cargo check`, a CLI invocation, a
  client probe), never self-assessment.
- Keep it minimal: one uncertain thing per spike.

### 3. Record findings

- `do-harness trace add --session <spike-id> --command "<cmd>" --error-diff "<failure>" --resolution-steps "<what settled it>"`.
- Generalized lessons go into the matching skill through
  `.agents/skills/skill-distiller/SKILL.md`.

### 4. Clean the spike

- Delete the scratchpad. `target/` is throwaway and never committed.
- Never let spike code leak into a crate or a slice.

### 5. Transition to slice

- Re-enter `vertical-plugin-slice` with the resolved approach and update the
  task state (`do-harness task advance <id>`).

## Gotchas

- A spike is not a partial implementation; production code never advances
  through it.
- 3 consecutive failures of the spike's command halt the loop (fail-fast):
  record the signature (`do-harness verify --record`, `do-harness errors list`)
  before retrying.
- Probe scripts and their outputs stay under `target/`; committing them violates
  the workspace contract.
