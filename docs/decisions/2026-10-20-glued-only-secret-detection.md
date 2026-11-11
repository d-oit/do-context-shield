# Glued-only secret detection: hold, no slice

Decision date: 2026-10-20.

## Decision

Keep the detector's current credential boundaries. Do not add a lookaround/backtracking regex engine or broaden weak credential prefixes without a new false-positive and performance review. This decision does not resolve the glued-only residual; the active risk remains listed in [`plans/backlog.md`](../../plans/backlog.md#residual-risks).

## Original rationale and evidence

### Prior backlog entry

- **Status**: decided 2026-10-20 (harness task, `decision`). This is the
  documented residual of the redaction-postcondition implementation; its
  completed implementation record is in the
  [backlog history](2026-11-11-backlog-history.md). A secret that never
  appears at a detectable boundary anywhere in the input is still missed,
  and with no detected value the postcondition has nothing to check.
- **Verdict (recorded, hold — no slice)**: both options are rejected. A
  lookaround/backtracking engine (e.g. `fancy-regex`) would trade a
  linear-time guarantee for backtracking on untrusted input — a ReDoS vector
  at the privacy boundary — plus a new dependency against the
  local/CPU-minimal rule. Broader patterns (dropping the `\b` anchors for
  weak prefixes such as `sk-`, `hf_`, `xox`) fail the false-positive review:
  they redact ordinary text such as `disk-usage-of-the-container`, and the
  `regex` crate has no lookaround to separate a "real but glued" token from
  one inside a longer word. The accepted mitigation stays the central
  redaction postcondition: any glued duplicate of a *detected* value fails
  closed (regressions in `crates/privacy-core/src/tests/redaction.rs` plus
  the `glued_duplicate.txt` fuzz seed). A *glued-only* occurrence — a secret
  with no detectable boundary anywhere — remains a documented residual, not a
  silent pass: detectors report what they can, the pipeline never downgrades
  on uncertainty, and the quality corpus (`--test quality`) guards the
  boundary rules that do exist.
- **Exit criteria**: met — verdict plus rationale recorded here and as an
  invariant in `plans/invariants.json`; no pattern or dependency change.

