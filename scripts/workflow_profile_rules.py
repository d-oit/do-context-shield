"""Fixed allowlists that bound low-risk workflow profile classification."""

from __future__ import annotations

SAFE_EXACT_PATHS = frozenset({"README.md", "CHANGELOG.md", "LICENSE"})
SAFE_PREFIXES = ("docs/",)
FEATURE_RULE_PATHS = {
    "detector-quality-corpus": ("prefix", "quality/corpus/"),
    "shared-skill-integration-test": ("exact", "tests/test_shared_skills.py"),
    "shared-skill-test-fixtures": ("prefix", "tests/fixtures/shared-skills/"),
    "crate-readme-metadata": ("crate-readme", ""),
}


def matches_explicit_feature_path(path: str, names: set[str]) -> bool:
    """Return whether all matched feature rules retain their fixed safe paths."""
    if not names or not names.issubset(FEATURE_RULE_PATHS):
        return False
    for name in names:
        match_type, matcher = FEATURE_RULE_PATHS[name]
        if match_type == "exact" and path != matcher:
            return False
        if match_type == "prefix" and not path.startswith(matcher):
            return False
        if match_type == "crate-readme" and not (
            path.startswith("crates/") and path.endswith("/README.md")
        ):
            return False
    return True
