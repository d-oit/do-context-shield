#!/usr/bin/env python3
"""Structure gate for skills in .agents/skills.

Dependency-free (no PyYAML): it runs in eval sandboxes and CI images where the
only guaranteed interpreter is python3. Checks the same Tier-1 surface the
do-harness skill-creator gate enforces: frontmatter shape and allowed keys,
license, name/directory agreement, description quality, body size, risky
patterns, and shell syntax.

Usage:
    python3 quick_validate.py <skill_directory>

Exit codes: 0 valid, 1 invalid (message on stdout).
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

MAX_SKILL_NAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 1024
MIN_DESCRIPTION_LENGTH = 40
MAX_BODY_WORDS = 5000
MAX_BODY_LINES = 500
ALLOWED_LICENSES = {"MIT", "Apache-2.0"}
ALLOWED_PROPERTIES = {"name", "description", "license", "allowed-tools", "metadata"}

RISKY_PATTERNS = (
    (r"AKIA[0-9A-Z]{16}", "possible AWS access key"),
    (r"ghp_[A-Za-z0-9]{20,}", "possible GitHub token"),
    (r"gho_[A-Za-z0-9]{20,}", "possible GitHub OAuth token"),
    (r"xox[bap]-[A-Za-z0-9-]+", "possible Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key material"),
    (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "hardcoded password"),
)

TOP_LEVEL_KEY = re.compile(r"^([A-Za-z0-9_-]+):(.*)$")


def parse_frontmatter(text):
    """Return (frontmatter dict, key set, body) or raise ValueError.

    Handles the frontmatter subset the corpus uses: scalar keys and folded
    (`>`) block scalars with indented continuation lines.
    """
    if not text.startswith("---\n"):
        raise ValueError("No YAML frontmatter found")
    end = text.find("\n---", 3)
    if end < 0:
        raise ValueError("Invalid frontmatter format")
    block = text[4:end]
    body = text[end + 4 :]

    values = {}
    keys = []
    lines = block.split("\n")
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        match = TOP_LEVEL_KEY.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2).strip()
        keys.append(key)
        if raw in (">", "|", ">-", "|-"):
            folded = []
            while index < len(lines) and (lines[index].startswith((" ", "\t")) or not lines[index]):
                folded.append(lines[index].strip())
                index += 1
            values[key] = " ".join(part for part in folded if part)
        else:
            values[key] = raw.strip('"').strip("'")
    if not keys:
        raise ValueError("Invalid frontmatter format")
    return values, set(keys), body


def scan_risky_patterns(skill_path):
    """Fail-closed risky-pattern scan over skill text files."""
    candidates = [skill_path / "SKILL.md"]
    for sub in ("references", "scripts", "evals"):
        directory = skill_path / sub
        if directory.is_dir():
            candidates.extend(p for p in directory.rglob("*") if p.is_file())
    for path in candidates:
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern, label in RISKY_PATTERNS:
                if re.search(pattern, line):
                    return f"Risky-pattern hit ({label}) at {path.relative_to(skill_path)}:{lineno}"
    return None


def lint_shell(skill_path):
    """bash -n every shell script; shellcheck -S error when installed."""
    scripts = []
    for sub in ("scripts", "evals"):
        directory = skill_path / sub
        if directory.is_dir():
            scripts.extend(p for p in directory.rglob("*.sh") if p.is_file())
    for script in scripts:
        proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        if proc.returncode != 0:
            err = (proc.stderr.strip().splitlines() or ["syntax error"])[0]
            return False, f"Shell syntax error in {script.relative_to(skill_path)}: {err}"
    checker = shutil.which("shellcheck")
    if checker is None:
        return True, "SKIP: shellcheck not installed"
    for script in scripts:
        proc = subprocess.run(
            [checker, "-S", "error", str(script)], capture_output=True, text=True
        )
        if proc.returncode != 0:
            err = (proc.stdout.strip().splitlines() or ["shellcheck error"])[0]
            return False, f"shellcheck error in {script.relative_to(skill_path)}: {err}"
    return True, "shell lint clean"


def validate_skill(skill_path):
    skill_path = Path(skill_path)

    skill_md = skill_path / "SKILL.md"
    if not skill_md.exists():
        return False, "SKILL.md not found"

    content = skill_md.read_text()
    try:
        frontmatter, keys, body = parse_frontmatter(content)
    except ValueError as error:
        return False, str(error)

    unexpected = keys - ALLOWED_PROPERTIES
    if unexpected:
        allowed = ", ".join(sorted(ALLOWED_PROPERTIES))
        return (
            False,
            f"Unexpected key(s) in SKILL.md frontmatter: {', '.join(sorted(unexpected))}. "
            f"Allowed properties are: {allowed}",
        )

    for required in ("name", "description", "license"):
        if required not in keys:
            return False, f"Missing '{required}' in frontmatter"

    name = frontmatter.get("name", "").strip()
    if not re.match(r"^[a-z0-9-]+$", name):
        return False, f"Name '{name}' should be hyphen-case (lowercase letters, digits, and hyphens only)"
    if name.startswith("-") or name.endswith("-") or "--" in name:
        return False, f"Name '{name}' cannot start/end with hyphen or contain consecutive hyphens"
    if len(name) > MAX_SKILL_NAME_LENGTH:
        return False, f"Name is too long ({len(name)} characters). Maximum is {MAX_SKILL_NAME_LENGTH} characters."
    if name != skill_path.name:
        return False, f"Name '{name}' must match the skill directory '{skill_path.name}'"

    license_value = frontmatter.get("license", "").strip()
    if license_value not in ALLOWED_LICENSES:
        allowed = ", ".join(sorted(ALLOWED_LICENSES))
        return False, f"License must be one of: {allowed}"

    description = frontmatter.get("description", "").strip()
    if "<" in description or ">" in description:
        return False, "Description cannot contain angle brackets (< or >)"
    if len(description) > MAX_DESCRIPTION_LENGTH:
        return False, f"Description is too long ({len(description)} characters). Maximum is {MAX_DESCRIPTION_LENGTH} characters."
    if len(description) < MIN_DESCRIPTION_LENGTH:
        return False, f"Description is too short ({len(description)} characters). Minimum is {MIN_DESCRIPTION_LENGTH} characters."

    words = len(body.split())
    if words > MAX_BODY_WORDS:
        return False, f"SKILL.md body is too long ({words} words). Split detail into references/."
    lines = body.count("\n") + 1
    if lines > MAX_BODY_LINES:
        return False, f"SKILL.md body is too long ({lines} lines). Split detail into references/."

    pattern_hit = scan_risky_patterns(skill_path)
    if pattern_hit is not None:
        return False, pattern_hit

    shell_ok, shell_note = lint_shell(skill_path)
    if not shell_ok:
        return False, shell_note
    if shell_note.startswith("SKIP"):
        print(shell_note)

    return True, "Skill is valid!"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python quick_validate.py <skill_directory>")
        sys.exit(1)
    valid, message = validate_skill(sys.argv[1])
    print(message)
    sys.exit(0 if valid else 1)
