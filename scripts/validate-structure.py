import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
required = [
    "AGENTS.md", "README.md", "Cargo.toml", "do-harness.toml",
    ".agents/SKILLS.md",
    "plans/methods.json",
    "plans/invariants.json",
    "docs/architecture.md",
    "crates/plugin-api/src/lib.rs", "crates/privacy-core/src/lib.rs",
    "crates/detector-regex/src/lib.rs", "crates/detector-gliner2/src/lib.rs",
    "crates/plugin-process/src/lib.rs",
    "crates/policy-default/src/lib.rs",
    "crates/transformer-pseudonymize/src/lib.rs", "crates/vault-memory/src/lib.rs",
    "crates/vault-json/src/lib.rs", "crates/mcp-server/src/lib.rs",
]
required += [
    ".agents/skills/skill-creator/SKILL.md",
    ".agents/skills/skill-creator/scripts/quick_validate.py",
]

skills_dir = ROOT / ".agents/skills"
required += [
    str(skill.relative_to(ROOT) / "SKILL.md")
    for skill in sorted(skills_dir.iterdir())
    if skill.is_dir()
]
required += [
    str(skill.relative_to(ROOT) / "evals" / "evals.json")
    for skill in sorted(skills_dir.iterdir())
    if skill.is_dir()
]

missing = [p for p in required if not (ROOT / p).exists()]
if missing:
    raise SystemExit(f"missing required files: {missing}")

source = "\n".join(p.read_text(encoding="utf-8") for p in ROOT.rglob("*.rs"))
for bad in (".unwrap()", ".expect("):
    if bad in source:
        raise SystemExit(f"forbidden pattern found: {bad}")

for p in ROOT.rglob("*.rs"):
    if len(p.read_text(encoding="utf-8").splitlines()) > 500:
        raise SystemExit(f"file exceeds 500 LOC: {p}")

# Supply chain: every GitHub Actions `uses:` must pin an immutable commit SHA
# (40 hex) with the release version kept as a trailing comment. Mutable tags
# can be moved to a revision this repository never reviewed. Local composite
# actions (`./...`) and `docker://` refs are not tags and are exempt.
uses_re = re.compile(r"uses:\s*([^\s#]+)")
pin_re = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + sorted(
    (ROOT / ".github" / "workflows").glob("*.yaml")
)
for wf in workflows:
    for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
        m = uses_re.search(line)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if not pin_re.match(ref):
            raise SystemExit(f"unpinned action in {wf.name}:{lineno}: {ref}")

print("structure validation: OK")
