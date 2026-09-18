#!/usr/bin/env bash
# fail-closed-boundary walkthrough: leaves hermetic checklist residue in the
# eval sandbox. Exit 0 proves the structure gate accepts the skill and the
# fail-closed checklist was written.
#
# The eval sandbox contains only this skill directory (plus skill-creator's
# scripts), so this walkthrough never reads repository crates; repo-path claims
# in the skill are checked by scripts/check-skills.sh against the real workspace.
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"

python3 "$root/.agents/skills/skill-creator/scripts/quick_validate.py" \
  "$root/.agents/skills/fail-closed-boundary" > "$root/boundary_validate.txt"

cat > "$root/boundary-checklist.md" << 'MD'
# fail-closed boundary checklist
- decide deterministically: secrets redact first (is_secret_kind); test/business labels at >= 0.90 keep; everything else pseudonymizes.
- abstention and missing judgments fall back to the kind rule, never to keep.
- validate before use: spans in range with value == input[start..end]; one decision per entity; judgment indices in range and unique; confidence in 0..=1; every placeholder resolvable by the configured vault.
- on any validation failure the sanitize call fails closed instead of passing text through.
- a judge returns labels and confidence only; it never returns spans or text.
- results carry EntitySummary (kind, span, confidence); raw matched values never leave the pipeline.
- restore resolves tokens only in the same explicit session scope and vault.
MD
test -s "$root/boundary-checklist.md"

cat > "$root/boundary_negative.txt" << 'TXT'
negative: a judge labeling an api_key as test still redacts; abstention never means keep
out-of-scope: general questions never touch the detect -> judge -> plan -> transform -> vault path
TXT
