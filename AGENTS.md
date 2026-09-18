# AGENTS.md

## Quick reference

|Task|Command|
|---|---|
|Build|`cargo build`|
|Full local gate|`do-harness verify --set verification` (fmt, check, clippy, test, loc, skills, deps, audit, commitlint)|
|Changed-only gate|`do-harness verify --changed --set verification`|
|Selection preview|`do-harness explain --set verification --changed`|
|Evidence freshness|`do-harness status --set verification`|
|Skill structure gate|`bash scripts/check-skills.sh`|
|Skill evals|`do-harness eval --strict-fixtures` (narrow with `--skill <name>`)|
|Feature build|`cargo check -p <crate> --features <feature>` (e.g. `do-context-shield-detector-gliner2 --features gliner2`)|
|Setup|`git config core.hooksPath .githooks` after cloning|
|Sensors|Declared in `do-harness.toml`; procedures in `.agents/skills/harness/SKILL.md`|

## Harness model

Agent = Model + Harness: feedforward guides prevent errors before coding, feedback sensors catch violations after coding.

- **Feedforward guides**: this file, `.agents/skills/*/SKILL.md`, `plans/methods.json`, `plans/invariants.json`, `docs/`.
- **Feedback sensors**: the `do-harness.toml` suite plus CI. Computational output (exit codes, evidence artifacts) strictly supersedes LLM self-assessment.
- **Self-correction protocol**: read the full error, classify it, apply the minimal fix, re-run that sensor only, commit only when green. Never weaken or delete the sensor that fired; never refactor unrelated code in the same pass.
- **Fail-fast**: 3 consecutive failures of the same subtask halt the loop — record the signature (`do-harness verify --record`), inspect it (`do-harness errors list`), resolve the defect before re-running.
- **Steering loop**: a sensor firing more than twice in one task is a guide defect — update the matching skill/`AGENTS.md` section (procedure in `.agents/skills/skill-distiller`) instead of patching the symptom.
- **No hallucinated success**: a subtask is complete only when the sensor named in `plans/methods.json` exits 0. Completion claims need evidence (`do-harness status --set verification`), not prose.

## Workflow

1. **Recon** — read `crates/plugin-api/src/lib.rs` (trait contract) and the matching skill (`plugin-development`, `fail-closed-boundary`, `private-data`, `harness`) before touching code. Preview the sensor selection with `do-harness explain --set verification --changed`.
2. **Plan** — decompose compound work with the HTN methods in `plans/methods.json` (`vertical-plugin-slice`, `spike-and-resolve`, `decision`) and record it: `do-harness task add "<title>" --method <name>`. Advance the pointer only when the named sensor is green.
3. **Spike (only when uncertain)** — third-party APIs, model artifacts, wire protocols, coding-client integrations, and performance boundaries go to `target/spikes/<name>/` first (gitignored, throwaway). Record findings with `do-harness trace add`, then delete the spike. Never advance production code through a spike.
4. **Contract and failing tests first** — define the typed contract (trait implementation, error enum, request/response shape) and a test that fails for the expected reason before implementing. Privacy invariants get explicit assertions: no raw value in output, scope isolation, secrets stay redacted, plugin failures fail closed.
5. **Implement, then sensors (green)** — minimal implementation; run the changed gate; on fire apply the minimal fix and re-run that sensor only. Commit only when green (see `harness` skill).
6. **Distill** — after a green slice or a non-trivial recovery, update the matching skill/heuristics (`.agents/skills/skill-distiller`) and keep `plans/invariants.json` in sync (`do-harness seed`).

## CLI tool protocol and guardrails

- Hooks: `.githooks/` is the hook source of truth (`git config core.hooksPath .githooks`). `do-harness hook install` is the per-developer alternative writing `.git/hooks/`; the two do not combine — pick one.
- `do-harness verify` exit codes: 0 pass, 1 sensor failed, 2 usage/config error. `--format json` writes one JSON object to stdout; diagnostics stay on stderr.
- Mutating commands support `--dry-run`. Task state lives in `.do-harness/agent_state.db`; `do-harness task export` writes the `plans/tasks.json` snapshot. Never edit `.do-harness/` by hand — use `task`, `errors`, `trace`, `distill`.
- Feature-gated builds (`--features gliner2`) are not part of the default sensor suite; run `cargo check`/`clippy`/`test` for the feature explicitly when touching those crates.
- Probes and throwaway scripts stay under `target/` (gitignored); never commit them.

## Machine-readable decisions

Every durable rule is recorded in `plans/invariants.json` as `{invariant, rationale, sensor, category}` and seeded into the state database (`do-harness seed --prune`). A rule whose `sensor` is review-only is not machine-enforced — prefer adding the sensor.

## Project rules

- Keep the core provider-agnostic. Do not add cloud LLM SDKs to runtime crates.
- Every detector, judge, policy, transformer, and vault implementation must remain replaceable behind `plugin-api` traits.
- Prefer local/CPU implementations. Heavy native dependencies stay behind opt-in Cargo features.
- Never log raw sensitive input or vault mappings.
- Use explicit session scopes for mappings.
- Preserve semantic relationships when transforming entities.
- Secrets are redacted by default.
- Keep files under 500 LOC (decompose when nearing 450).
- No hard-coded credentials or API keys.
- Rust 2024, strict lints, `unwrap()` and `expect()` are forbidden; document every `Result`-returning function with an `# Errors` section.
