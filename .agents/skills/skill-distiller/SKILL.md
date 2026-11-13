---
name: skill-distiller
description: >
  Compress verified interaction traces, error recoveries, and spike findings
  into reusable, benchmarked skills and heuristic references, and repair the
  feedforward guide when the steering loop fires. Use after a slice passes its
  sensors, after a non-trivial recovery, when a sensor fires more than twice in
  one task, or when editing skills in .agents/skills/. Triggers: "distill",
  "heuristic", "steering loop", "anti-pattern", "negative knowledge".
license: MIT
metadata:
  version: "1.0"
  tags: distillation heuristics skills steering eval
---
## Guides
See references/heuristics.md for distilled heuristics.
# Skill Distiller Skill

Post-task loop that compresses verified traces into guides, so sensors fire less
over time.

## Triggers

1. A slice passed all sensors and produced a reusable pattern.
2. A non-trivial recovery happened (borrow checker, feature build, protocol
   mismatch, supply-chain failure).
3. A spike resolved a previously unknown constraint.
4. Steering loop: a sensor fired more than twice in one task — the matching
   guide is defective, not just the code.

## Steps

1. **Extract the trace** — `do-harness trace list --session <id> --format json`
   returns the `command`, `error-diff`, and `resolution-steps` recorded at the
   time. Recover from the trace, never from memory.
2. **Generalize** — convert the specific fix into a durable rule; strip
   project-specific identifiers and machine paths. Never extract a fix that did
   not pass a computational sensor.
3. **Record the heuristic** —
   `do-harness distill --skill <name> --pattern "<rule>" --description "<when it applies>" --from-trace <id>`.
   Add `--to-fixture` when the recovery should also raise the skill's pass-rate
   bar; `--dry-run` previews without touching skill files.
4. **Update the guide** — put the rule in the matching skill (`SKILL.md` body or
   `references/heuristics.md`). If no skill matches, scaffold one with
   `.agents/skills/skill-creator/SKILL.md`.
5. **Benchmark** —
   `python3 .agents/skills/skill-creator/scripts/quick_validate.py <skill-dir>`,
   then `bash scripts/check-skills.sh`, then `do-harness eval --skill <name>`.
6. **Negative knowledge** — represent an unsolved trap using a supported eval
   kind (`explicit`, `implicit`, `contextual`, or `negative`). For a trap that
   depends on skill guidance, use `kind: contextual` and include a
   `not-contains:` assertion for the wrong action plus a positive assertion for
   the safe response. Record the wrong action and why it failed in
   Anti-patterns.

## Anti-patterns

Seed anti-patterns from real incidents only — an unsolved blocker, a repeated
correction, a revert — never from speculation. Each names the observed wrong
action and why it failed, so a future agent can recognize the trap.

- Do not use `kind: gotchas` for eval fixtures: repo-pinned `do-harness v0.1.1`
  rejects it; use a supported kind (`contextual` for guidance-dependent traps).

## Gotchas

- Never distill a fix that did not pass computational sensors — hallucinations
  propagate.
- Strip secrets, real PII, and machine-specific paths from traces before
  writing them into a skill.
- Distilled learnings land in tracked artifacts (skills, `references/`, docs,
  `plans/`); `.do-harness/` and `target/` are local state, not durable evidence.
- A sensor firing repeatedly is a guide defect: patch the guide, not the
  symptom.
