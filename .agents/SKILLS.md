# Agent Skills Index

Reusable skill runbooks for this repository. Skills live in `.agents/skills/<name>/SKILL.md`
following the Agent Skills specification (frontmatter with `name`, `description`, and
`license`; body under 250 lines) and carry graded eval fixtures in `evals/evals.json`.

## Available Skills

| Skill | Path | Description |
|-------|------|-------------|
| `private-data` | [skills/private-data/SKILL.md](skills/private-data/SKILL.md) | Sanitize sensitive coding context locally before sending it to an external model or tool, then restore placeholders only after the response returns. |
| `plugin-development` | [skills/plugin-development/SKILL.md](skills/plugin-development/SKILL.md) | Implement a new detector, policy, transformer, or vault plugin behind `plugin-api` traits. |
| `harness` | [skills/harness/SKILL.md](skills/harness/SKILL.md) | Sensor map, self-correction protocol, fail-fast and steering loops. |
| `htn-planner` | [skills/htn-planner/SKILL.md](skills/htn-planner/SKILL.md) | Decompose work into sensor-gated subtasks using `plans/methods.json`. |
| `spike-runner` | [skills/spike-runner/SKILL.md](skills/spike-runner/SKILL.md) | De-risk unknown APIs, models, and protocols with throwaway spikes. |
| `skill-distiller` | [skills/skill-distiller/SKILL.md](skills/skill-distiller/SKILL.md) | Compress verified traces into guides and anti-patterns. |
| `skill-creator` | [skills/skill-creator/SKILL.md](skills/skill-creator/SKILL.md) | Author skills: layout, structure gate, eval fixtures. |

## Notes

- `private-data` is the product's agent interface: it is also the file coding clients install into their own skills directory (see `README.md`).
- `plugin-development` is the contributor workflow for extending detection, policy, transformation, or storage. It encodes the hard rules from `AGENTS.md`.
- `harness`, `htn-planner`, `spike-runner`, `skill-distiller`, and `skill-creator` are the development-methodology skills: feedforward guides for the workflow in `AGENTS.md`.
- Every skill must pass `bash scripts/check-skills.sh` (structure gate + fixture shape) and is benchmarked by `do-harness eval`; `--strict-fixtures` rejects thin datasets. Do not add a skill without graded eval fixtures.
- Deliberately no other skills: MCP server setup is documented in `docs/client-integration.md`, and review rules live in `AGENTS.md`.
