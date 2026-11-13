# Agent Skills Index

Reusable skill runbooks for this repository. Skills live in `.agents/skills/<name>/SKILL.md`
following the Agent Skills specification (frontmatter with `name`, `description`, and
`license`; body under 250 lines) and carry graded eval fixtures in `evals/evals.json`.

## Available Skills

| Skill | Path | Description |
|-------|------|-------------|
| `private-data` | [skills/private-data/SKILL.md](skills/private-data/SKILL.md) | Sanitize sensitive coding context locally before sending it to an external model or tool, then restore placeholders only after the response returns. |
| `plugin-development` | [skills/plugin-development/SKILL.md](skills/plugin-development/SKILL.md) | Implement a new detector, judge, policy, transformer, or vault plugin behind `plugin-api` traits. |
| `fail-closed-boundary` | [skills/fail-closed-boundary/SKILL.md](skills/fail-closed-boundary/SKILL.md) | Review checklist for changing the privacy boundary: stage ownership, validation, fail-closed tests. |
| `harness` | [skills/harness/SKILL.md](skills/harness/SKILL.md) | Sensor map, self-correction protocol, fail-fast and steering loops. |
| `htn-planner` | [skills/htn-planner/SKILL.md](skills/htn-planner/SKILL.md) | Decompose work into sensor-gated subtasks using `plans/methods.json`. |
| `spike-runner` | [skills/spike-runner/SKILL.md](skills/spike-runner/SKILL.md) | De-risk unknown APIs, models, and protocols with throwaway spikes. |
| `skill-distiller` | [skills/skill-distiller/SKILL.md](skills/skill-distiller/SKILL.md) | Compress verified traces into guides and anti-patterns. |
| `skill-creator` | [skills/skill-creator/SKILL.md](skills/skill-creator/SKILL.md) | Author skills: layout, structure gate, eval fixtures. |
| `codacy-analysis-cli` | [skills/codacy-analysis-cli/SKILL.md](skills/codacy-analysis-cli/SKILL.md) | Run local Codacy static analysis with strict gating and trustworthy tool-coverage checks. |
| `codacy-cloud-cli` | [skills/codacy-cloud-cli/SKILL.md](skills/codacy-cloud-cli/SKILL.md) | Query Codacy Cloud repositories, issues, findings, pull requests, tools, patterns, and reanalysis. |
| `codacy-code-review` | [skills/codacy-code-review/SKILL.md](skills/codacy-code-review/SKILL.md) | Enrich pull-request reviews with local analysis and Codacy Cloud data without overstating coverage. |
| `configure-codacy` | [skills/configure-codacy/SKILL.md](skills/configure-codacy/SKILL.md) | Configure local Codacy analysis and reduce noise with evidence-backed, security-preserving tuning. |
| `configure-codacy-cloud` | [skills/configure-codacy-cloud/SKILL.md](skills/configure-codacy-cloud/SKILL.md) | Tune an existing analyzed Codacy Cloud repository and report configuration changes. |
| `setup-coverage` | [skills/setup-coverage/SKILL.md](skills/setup-coverage/SKILL.md) | Generate, upload, and verify test coverage reports for Codacy. |

## Cross-Repo Skill Export Contract

This repository exports portable, language-neutral safety workflows defined in `.agents/exported-skills.json` (schema `$schema_version: "1.0"`). External repositories (such as templates, harnesses, or application runners) consume these workflows by pinned reference rather than duplicating the full skill tree.

### Exported Items

| Export ID | Canonical Path | Description |
|-----------|----------------|-------------|
| `private-data-handling` | [.agents/skills/private-data/references/portable.md](skills/private-data/references/portable.md) | Language-neutral local-first sanitization, harness-side restoration, and vault lifecycle checklist. |
| `fail-closed-boundary-review` | [.agents/skills/fail-closed-boundary/references/portable.md](skills/fail-closed-boundary/references/portable.md) | Stage ownership, deterministic policy priority, and fail-closed validation review checklist. |

### Manifest Schema & Consumption Rules

1. **Deterministic Pinning**: Adopters pin exported items by canonical path, 40-character git commit SHA (`pinned_commit`), and SHA-256 content digest (`digest`). Unpinned moving refs (e.g. `main`, `latest`) fail closed.
2. **Explicit Adaptations**: Adopters must declare local adaptations (`adaptations`) mapping abstract workflows to native language or runtime mechanics (e.g., Replacing CLI flags with stdio RPC or native SDK calls).
3. **Drift Verification**: `bash scripts/check-shared-skills.sh` (sensor `shared-skills`) computes SHA-256 digests against pinned content. Upstream changes trigger explicit drift warnings rather than silent updates.
4. **Fail-Closed Gate**: Missing paths, digest mismatches, unpinned moving refs, or unknown schema versions fail verification.

*Disclaimer*: Generic checklist coverage guides local agent behavior but does not mechanically prove client integrations sanitize context without runtime integration tests.

## Notes

- `private-data` is the product's agent interface: it is also the file coding clients install into their own skills directory (see `README.md`).
- `plugin-development` is the contributor workflow for extending detection, judging, policy, transformation, or storage. It encodes the hard rules from `AGENTS.md`.
- `fail-closed-boundary` is the contributor review checklist for the privacy boundary itself: who owns spans, labels, actions, and restoration, what must be validated, and which fail-closed tests a change must keep.
- `harness`, `htn-planner`, `spike-runner`, `skill-distiller`, and `skill-creator` are the development-methodology skills: feedforward guides for the workflow in `AGENTS.md`.
- Every skill must pass `bash scripts/check-skills.sh` (structure gate + fixture shape) and is benchmarked by `do-harness eval`; `--strict-fixtures` rejects thin datasets. Do not add a skill without graded eval fixtures.
- Codacy skills are copied from [codacy/codacy-skills](https://github.com/codacy/codacy-skills); source hashes are recorded in `../skills-lock.json`, and the upstream MIT notice is retained at [references/codacy-skills-LICENSE](references/codacy-skills-LICENSE). Detailed runbooks live in linked references so every skill entry stays within the local body limit.
