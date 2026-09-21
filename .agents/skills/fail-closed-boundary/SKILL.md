---
name: fail-closed-boundary
description: >
  Extend or review the fail-closed privacy boundary: detection, semantic judging,
  policy, transformation, vault, and the pipeline that composes them. Use when
  adding or changing a detector, judge, policy, transformer, vault, or pipeline
  stage, when validating plugin output, or when a failure raises the question
  "should this text continue?". Triggers: "fail-closed", "privacy boundary",
  "redaction", "judge", "plugin validation".
license: MIT
metadata:
  version: "1.0"
  tags: privacy fail-closed boundary plugins judge redaction
---
## Guides

See [references/heuristics.md](references/heuristics.md) for distilled repository heuristics.

# Fail-Closed Boundary Skill

The product guarantee is deny-by-default mediation of sensitive text: every
stage either produces a validated result or the call fails; text never continues
unchecked. `docs/architecture.md` maps the layers; this skill is the review
checklist for changing them.

## Stage ownership

| Stage | Owns | Never does |
|---|---|---|
| detector | spans, kinds, confidence | invent values |
| semantic judge (optional) | a label and confidence per candidate, or abstention | return spans or text, or weaken redaction |
| policy | one action per entity; reject via `Action::Block`/`Action::Review` | leave an entity undecided |
| transformer | rewritten text and mappings for pseudonymized values | keep a value it was told to replace, leak a raw value |
| vault | scope-keyed reversible mappings, `delete_scope`, `expire` | resolve tokens across scopes |
| pipeline | validation between stages, `EntitySummary` results | echo raw matched text, pass a failure through |

## Method

1. **Decide** every entity deterministically: secrets redact first
   (`is_secret_kind`), then recipient context (special-category data to
   external/unknown recipients blocks; unknown recipients block personal
   data), then judge labels (`test`/`business` at ≥ 0.90 keep), local
   recipients keep remaining values, and everything else pseudonymizes.
   Abstention and a missing judgment fall back to the kind rule — never to
   keep. A judge returns labels and confidence only; it never returns spans or
   text.
2. **Validate** stage output before use, fail closed: detector entities with a
   non-empty kind and confidence in `0..=1`, spans on UTF-8 boundaries with
   `value == input[start..end]`, within bounds, and resolved
   longest-span-wins; exactly one decision per entity; any `Action::Block` or
   `Action::Review` halts the pipeline; judgment indices in range and unique
   with confidence in `0..=1`; every emitted placeholder resolvable by the
   configured vault.
3. **Transform and record** only after validation. Results carry `EntitySummary`
   (kind, span, confidence), so the matched text cannot travel back into an
   agent context; child stderr stays discarded and error messages never echo
   input values.
4. **Restore** resolves placeholders only in the same explicit session scope and
   vault. Vault mappings support scope deletion (`delete_scope`) and TTL
   expiry (`expire`).

## Required tests

- A judge that says `test` cannot keep a secret-like kind (redaction wins).
- A judge failure, an out-of-range or duplicate judgment index, or an
  out-of-range confidence fails the sanitize call (`PipelineError::Judge`).
- Process plugins fail closed on malformed responses, undecided entities,
  leftover values, and unresolvable placeholders.
- Results and CLI/MCP `inspect` output never contain the matched text.
- A plugin that formats the input or a detected value into its error cannot
  leak it: stage error text is scrubbed of known values before it surfaces.
- Restore is scope-limited: another session resolves nothing; `context.restore`
  requires an explicit session.
- Policy `Action::Block` and `Action::Review` fail the pipeline before transform.
- Special-category data to external recipients and personal data to unknown
  recipients fail closed (`Action::Block`).
- Detector entities with an empty kind or confidence outside `0..=1`, spans not
  on character boundaries, out of bounds, or mismatched to the input fail the
  pipeline closed.
- Adapter context surfaces (MCP arguments, CLI flags) reject unknown
  recipient/data_category names or wrong types instead of silently downgrading
  to a weaker enforcement context.
- Vault `delete_scope` removes mappings and resets counters; TTL expires stale
  mappings.

## Gotchas

- A permissive plugin turns the boundary into a passthrough: report the
  violation; never drop it silently.
- Judge labels select among deterministic actions; they never generate the
  protected value — spans, transformations, policy, and restoration stay
  deterministic code.
- `--features gliner2` is outside the default sensor suite: run the feature
  build explicitly when touching that detector.

## References

- Layer map and non-goals: `docs/architecture.md`.
- Pipeline mechanics, registry names, and plugin flags: `.agents/skills/plugin-development/SKILL.md`.
- Process wire contract and its fail-closed list: `docs/process-plugin.md`.
