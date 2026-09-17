---
name: harness
description: >
  Map this repository's feedforward guides and feedback sensors, and run the
  self-correction protocol when a computational sensor fires. Use when a sensor
  fails (fmt, check, clippy, test, loc, skills, deps, audit, commitlint),
  before committing, or when setting up agent context for a task.
  Triggers: "harness", "sensor fire", "CI failure", "quality gates",
  "self-correction".
license: MIT
metadata:
  version: "2.0"
  tags: harness sensors feedback feedforward self-correction quality
---
## Guides

See [references/heuristics.md](references/heuristics.md) for distilled repository heuristics.

# Harness Skill

Agent = Model + Harness. Feedforward guides (this skill, `AGENTS.md`, `CONTRIBUTING.md`, `plans/methods.json`) prevent errors before coding; feedback sensors (the `do-harness.toml` suite, CI) catch violations after coding. Computational output strictly supersedes LLM self-assessment.

## Feedforward guides

| Guide | Path | Purpose |
|---|---|---|
| Agent contract | `AGENTS.md` | Operating rules, 6-phase workflow, project rules |
| Method catalog | `plans/methods.json` | HTN methods and their sensor gates |
| Invariants | `plans/invariants.json` | Decision headers (invariant/rationale/sensor/category) |
| Planning | `.agents/skills/htn-planner/SKILL.md` | Task decomposition |
| Spikes | `.agents/skills/spike-runner/SKILL.md` | De-risking throwaway prototypes |
| Distillation | `.agents/skills/skill-distiller/SKILL.md` | Turning recoveries into guides |
| Skill authoring | `.agents/skills/skill-creator/SKILL.md` | Structure gate and eval fixtures |
| Product skills | `.agents/skills/private-data/SKILL.md`, `.agents/skills/plugin-development/SKILL.md` | Agent-facing usage and plugin development |

## Feedback sensors

| Sensor | Command | Stage | Fix hint |
|---|---|---|---|
| fmt | `cargo fmt --all -- --check` | pre-commit, CI | `cargo fmt --all` |
| check | `cargo check --workspace` | pre-commit, CI | fix the compile error |
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | pre-push, CI | fix the lint; no `unwrap()`/`expect()`; document `Result` fns with `# Errors` |
| test | `cargo test --workspace` (`--all-features` in CI) | pre-push, CI | fix the test; update it first when behavior changes intentionally |
| loc | `bash scripts/check-loc.sh` | pre-commit, CI | decompose at 450 LOC; extract a module or a `<module>_tests.rs` |
| skills | `bash scripts/check-skills.sh` | pre-push | fix frontmatter/evals; see skill-creator |
| deps | `bash scripts/check-deps.sh` | pre-push, CI | license allow-list, crates.io only, no wildcards; check feature-gated trees explicitly |
| audit | `bash scripts/check-audit.sh` | CI | resolve or document the advisory in `deny.toml` / `.cargo/audit.toml` |
| commitlint | `bash scripts/check-commitlint.sh` | CI | conventional commit with a type prefix |
| structure | `python3 scripts/validate-structure.py` | CI | restore required files; remove unwrap/expect; shrink files |
| deny | `cargo deny check` | CI | dependency policy (`deny.toml`) |
| publish-check | `cargo package --list -p <crate>` | CI | fix the crate's include whitelist |
| secret-scan | gitleaks (`.github/workflows/secret-scan.yml`) | CI | remove and rotate the secret |

Changed-only gate: `do-harness verify --changed --set verification`; preview the selection with `do-harness explain --set verification --changed`. A tool that is unavailable prints `SKIP:` and is reported as WARN, never as a silent pass; under `--strict` a warn is not a pass.

## Self-correction protocol

1. Read the full error message.
2. Classify: fmt / compile / lint / test / supply-chain / structure / skills.
3. Apply the minimal fix — do not refactor unrelated code.
4. Re-run that sensor only (`do-harness verify --only <name>`).
5. Commit only when green; for an intentional behavior change, update the test first.

## Fail-fast policy

The same subtask failing a sensor 3 consecutive times halts: record the signature with `do-harness verify --record`, inspect it with `do-harness errors list --format json`, and resolve the underlying defect before re-running. `do-harness task done <id>` refuses until the method's named sensor has an ok beat.

## Steering loop

A sensor firing more than twice in one task is a feedforward-guide defect. Update the matching guide (this skill, `AGENTS.md`, a project skill) with the generalized heuristic — `.agents/skills/skill-distiller/SKILL.md` carries the procedure, and `do-harness distill --from-strikes --dry-run` shows what a recorded strike would scaffold. The loop closes: sensors fire -> guides update -> sensors fire less.

## Gotchas

- Never trust LLM self-assessment over a computational sensor's exit code.
- Never weaken or delete the sensor that fired; fix the cause.
- `.do-harness/` (state database, evidence) and `target/` are gitignored local state — never durable evidence, never committed.
- `do-harness eval` needs `.agents/skills/skill-creator/scripts/quick_validate.py` (dependency-free, no PyYAML) in its sandbox, and `--strict-fixtures` rejects thin datasets; grader drift requires an explicit `--bless`.
- Feature-gated crates (`--features gliner2`) are not covered by the default suite: run the feature build explicitly.

## References

- Sensor wiring: `do-harness.toml`, `.github/workflows/ci.yml`.
- Contributor workflow: `CONTRIBUTING.md`. Project rules: `AGENTS.md`.
