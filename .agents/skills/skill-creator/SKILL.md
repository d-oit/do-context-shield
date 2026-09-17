---
name: skill-creator
description: >
  Create or update agent skills in .agents/skills/ with the local layout
  (SKILL.md plus evals/evals.json and an optional evals/walkthrough.sh),
  validated by the vendored structure gate and do-harness eval. Use when
  scaffolding a new skill, editing an existing one, or wiring its evaluation
  fixtures. Triggers: "new skill", "skill structure", "evals", "walkthrough".
license: MIT
metadata:
  version: "1.0"
  tags: skills evaluation fixtures structure gate
---
## Guides

See [references/heuristics.md](references/heuristics.md) for distilled repository heuristics.

# Skill Creator

Scaffold and evolve skills in `.agents/skills/` so they pass the structure gate
(`.agents/skills/skill-creator/scripts/quick_validate.py`) and the hermetic evaluator (`do-harness eval`).
Skills obey the same repository invariants as production code (see `AGENTS.md`).

## Local skill layout

```
<skill-name>/
├── SKILL.md (required: frontmatter name + description + license, imperative body)
├── evals/evals.json (required: cases with graded assertions)
├── evals/walkthrough.sh (when residue is graded: hermetic, exit 0)
├── scripts/ (deterministic executables the skill runs)
└── references/ (detail loaded on demand; SKILL.md links each file)
```

No READMEs, changelogs, or setup docs inside a skill. Frontmatter allows only
`name`, `description`, `license`, `allowed-tools`, and `metadata`.

## Process

1. **Scaffold**: copy the closest existing skill directory, or
   `mkdir -p .agents/skills/<name>/evals` — the name must match the directory and
   be hyphen-case.
2. **Write SKILL.md**: imperative guidance; when-to-use coverage belongs in the
   `description` (the body loads only after triggering); move long detail into
   `references/`, one level deep, each linked with when to read it.
3. **Write evals/evals.json**: `{"skill_name": ..., "evals": [...]}` where each
   case has `id`, `prompt`, `expected_output`, `files`, `dim`, `kind`, and
   `assertions`. Cover explicit, implicit, contextual, and negative cases; at
   least one negative case must prove the skill stays unloaded (`absent:`).
4. **Write evals/walkthrough.sh** when residue is graded: `#!/usr/bin/env bash`
   with `set -euo pipefail`; `$DO_HARNESS_ROOT` is the sandbox root and
   `$DO_HARNESS_BIN` the harness binary under test; write only under the root;
   exit 0 only on real success.
5. **Validate**: `python3 .agents/skills/skill-creator/scripts/quick_validate.py .agents/skills/<name>`,
   then `bash scripts/check-skills.sh`, then `do-harness eval --skill <name>`
   (`--strict-fixtures` rejects thin datasets). Re-bless graders explicitly:
   `do-harness eval --bless --skill <name>`.
6. **Iterate from eval evidence**; new reusable patterns go through
   `.agents/skills/skill-distiller/SKILL.md`, never straight into prose.

## Assertion DSL

Only prefixed assertions are graded; everything else is documentation and scores
nothing:

| Prefix | Meaning |
|---|---|
| `exists:PATH` | path exists relative to the sandbox root |
| `absent:PATH` | path does not exist (negative/discoverability cases) |
| `contains:PATH\|NEEDLE` | file text contains the needle |
| `not-contains:PATH\|NEEDLE` | file text does not contain the needle (anti-pattern proof) |
| `db:TABLE:COLUMN=VALUE:min=CNT` | state database row count |
| `cli:ARGV:contains:TEXT` | `do-harness --root <sandbox> ARGV` exits 0 and prints TEXT |
| `walk:` | the skill's walkthrough exited 0 |

## Gotchas

- Frontmatter keys outside the allowed set fail the gate; license must be `MIT`
  or `Apache-2.0`.
- Unprefixed assertion strings are docs — a fixture full of prose grades zero
  and `--strict-fixtures` rejects it.
- `contains:` needles must match the file text exactly, including backticks and
  case; grep the skill file before committing a fixture.
- Never distill a fix that did not pass computational sensors.

## References

- Repository invariants and workflow: `AGENTS.md`.
- Gate implementation: `.agents/skills/skill-creator/scripts/quick_validate.py` (dependency-free; no PyYAML).
- Distillation procedure: `.agents/skills/skill-distiller/SKILL.md`.
