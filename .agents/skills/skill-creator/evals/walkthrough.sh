#!/usr/bin/env bash
# skill-creator walkthrough: proves the structure gate accepts a valid skill and
# rejects an invalid one (negative control), hermetically inside the sandbox.
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"
validator="$root/.agents/skills/skill-creator/scripts/quick_validate.py"
receipt="$root/skill_creator_receipt.txt"

[[ -f "$validator" ]] || { printf 'structure gate missing\n' > "$receipt"; exit 1; }

probe="$root/.agents/skills/probe-valid"
mkdir -p "$probe"
cat > "$probe/SKILL.md" << 'MD'
---
name: probe-valid
description: >
  A deliberately minimal probe skill used by the skill-creator walkthrough to
  prove the structure gate accepts a valid skill directory.
license: MIT
metadata:
  version: "1.0"
---

# Probe Valid

This directory is walkthrough residue. It exists only inside the eval sandbox.
MD

python3 "$validator" "$probe" > "$root/skill_creator_valid.txt"

bad="$root/.agents/skills/probe-invalid"
mkdir -p "$bad"
cat > "$bad/SKILL.md" << 'MD'
---
name: probe-invalid
description: too short
license: Proprietary
---

# Probe Invalid
MD

if python3 "$validator" "$bad" > "$root/skill_creator_invalid.txt" 2>&1; then
  printf 'gate accepted an invalid skill: negative control failed\n' > "$receipt"
  exit 1
fi

printf 'structure gate: accepts valid skills, rejects invalid ones\n' > "$receipt"
