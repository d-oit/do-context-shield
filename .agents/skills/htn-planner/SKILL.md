---
name: htn-planner
description: >
  Decompose compound coding objectives into hierarchical task networks using the
  methods in plans/methods.json (vertical-plugin-slice, spike-and-resolve,
  decision), with sensor-gated subtasks tracked through the do-harness task
  workflow. Use when planning a multi-step change, choosing between a slice and
  a de-risking spike, or persisting task state for a long task. Triggers:
  "plan", "decompose", "subtasks", "task state", "HTN".
license: MIT
metadata:
  version: "1.0"
  tags: htn planning decomposition tasks sensors
---
# HTN Planner Skill

Turn an objective into a deterministic task network: named method -> ordered
subtasks, each with a precondition guard and a sensor gate. The catalog lives in
`plans/methods.json`; persist a network with
`do-harness task add "<title>" --method <name>`.

## Method catalog

### `vertical-plugin-slice`
Preconditions: the capability boundary is understood (one plugin-api stage or
one protocol surface changes) and the privacy invariants it must preserve are
named. Subtasks: `define-contract` -> `write-failing-test` -> `implement-slice`
(sensor: test) -> `verify-sensors` (sensor: check) -> `distill-learning`
(sensor: clippy).

### `spike-and-resolve`
Preconditions: a third-party API, model artifact, wire protocol, or
coding-client integration is uncertain. Subtasks: `create-spike` ->
`execute-spike` (sensor: check) -> `record-findings` -> `clean-spike`
(sensor: test) -> `transition-to-slice` (sensor: clippy). The prototype itself
follows `.agents/skills/spike-runner/SKILL.md`.

### `decision`
Preconditions: a design or dependency verdict (adopt, hold, reject) is being
recorded in `plans/invariants.json` with its invariant/rationale/sensor/category
header; feature-gated surfaces get an explicit feature build. Subtasks:
`record-decision-header` -> `verify-decision-evidence` (sensor: test) ->
`confirm-feature-boundary` (sensor: check).

## Execution rules

- Check preconditions before selecting a method; if they are unmet, pick the
  alternative or defer — recon first (`AGENTS.md` phase 1).
- Persist state with the harness CLI: `do-harness task add "<title>" --method <name>`,
  `do-harness task advance <id>`, `do-harness task done <id>`,
  `do-harness task list`, `do-harness task export` (writes `plans/tasks.json`).
- `task done` refuses until the method's named sensor has an ok beat recorded by
  `do-harness verify --record --task <id>`.
- Never advance the subtask pointer until the subtask's sensor exits 0.
- A subtask carrying uncertainty is a spike candidate: run
  `.agents/skills/spike-runner/SKILL.md` before advancing.
- `.do-harness/agent_state.db` is the source of truth; `plans/tasks.json` is an
  export snapshot for agents, never hand-edited.

## Gotchas

- Do not decompose an objective whose contract is unknown — the
  `vertical-plugin-slice` precondition is unmet; recon first.
- A spike decision is made at planning time, not discovered mid-implementation.
- Methods name sensors declared in `do-harness.toml`; a method without a real
  sensor gate is prose, not a gate (`scripts/check-skills.sh` rejects unknown
  sensor names).
