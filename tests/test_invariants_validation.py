#!/usr/bin/env python3
"""Category, structure, and evidence tests for plans/invariants.json (issue #197).

The validator lives here so `scripts/check-skills.sh` can run this file as its
invariant-catalog gate (the same wiring as tests/test_shared_skills.py) while
the deterministic cases below pin the rules against synthetic catalogs.

Rules (issue #197 items 6-7): the four allowed categories are
`security-contract`, `architecture-constraint`, `workflow-rule`, and
`historical-decisions`; a `security-contract` must cite executable test/sensor
evidence and may never be `review-only`, because review-only means an
explicitly documented human-reviewed decision. No active invariant is removed
by these checks — only miscategorized or unevidenced ones fail.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVARIANTS_PATH = ROOT / "plans" / "invariants.json"

# The four normalized invariant concepts (issue #197). Nothing else may appear
# as a `category` value in plans/invariants.json.
ALLOWED_CATEGORIES = (
    "security-contract",
    "architecture-constraint",
    "workflow-rule",
    "historical-decisions",
)
REQUIRED_FIELDS = ("invariant", "rationale", "sensor", "category")
REVIEW_ONLY_PREFIX = "review-only"
# A security contract must cite executable evidence: a cargo test/check/clippy
# run, a tests/ tree, a scripts/ gate, a do-harness command, a CI job, or the
# gitleaks scan (coverage of every current entry is pinned by
# test_repository_catalog_is_normalized).
EXECUTABLE_EVIDENCE_MARKERS = (
    "cargo test",
    "cargo check",
    "cargo clippy",
    "scripts/",
    "do-harness",
    "tests/",
    "::tests",
    "gh api",
    "gitleaks",
)


def validate_invariants(entries: object) -> list[str]:
    """Return the category/evidence/structure violations in a loaded catalog."""
    errors: list[str] = []
    if not isinstance(entries, list):
        return [f"invariants.json: expected a list of entries, got {type(entries).__name__}"]
    seen: set[str] = set()
    for position, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"invariants.json: entry {position} is not an object")
            continue
        label = str(entry.get("invariant") or f"entry {position}")
        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"invariants.json: entry missing or invalid field {field}: {label}"
                )
        category = entry.get("category")
        if category and category not in ALLOWED_CATEGORIES:
            allowed = ", ".join(ALLOWED_CATEGORIES)
            errors.append(
                f"invariants.json: unsupported category {category!r} "
                f"(allowed: {allowed}): {label}"
            )
        invariant = entry.get("invariant")
        if isinstance(invariant, str):
            if invariant in seen:
                errors.append(f"invariants.json: duplicate invariant: {invariant[:80]}")
            seen.add(invariant)
        sensor = entry.get("sensor")
        if not isinstance(sensor, str) or not sensor.strip():
            continue
        if sensor.startswith(REVIEW_ONLY_PREFIX) and category == "security-contract":
            errors.append(
                "invariants.json: security-contract may not be review-only; "
                f"cite executable test/sensor evidence instead: {label}"
            )
        if category == "security-contract" and not sensor.startswith(REVIEW_ONLY_PREFIX):
            lowered = sensor.lower()
            if not any(marker in lowered for marker in EXECUTABLE_EVIDENCE_MARKERS):
                errors.append(
                    "invariants.json: security-contract must cite executable "
                    f"test/sensor evidence, got {sensor[:80]!r}: {label}"
                )
    return errors


def validate_repository(root: Path = ROOT) -> list[str]:
    """Load the catalog under ``root`` and validate it."""
    path = root / "plans" / "invariants.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return ["plans/invariants.json: file not found"]
    except json.JSONDecodeError as error:
        return [f"plans/invariants.json: invalid JSON: {error}"]
    return validate_invariants(data)


def make_entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "invariant": "Example invariant",
        "rationale": "Example rationale",
        "sensor": "cargo test -p do-context-shield (example)",
        "category": "security-contract",
    }
    entry.update(overrides)
    return entry


class InvariantValidationTests(unittest.TestCase):
    def test_repository_catalog_is_normalized(self) -> None:
        errors = validate_repository()
        self.assertEqual([], errors)
        catalog = json.loads(INVARIANTS_PATH.read_text())
        self.assertIsInstance(catalog, list)
        self.assertGreater(len(catalog), 0)
        categories = {entry["category"] for entry in catalog}
        self.assertTrue(categories <= set(ALLOWED_CATEGORIES), categories)

    def test_accepts_each_allowed_category(self) -> None:
        entries = [
            make_entry(
                invariant=f"Example {category}",
                category=category,
                sensor=(
                    "review-only (dated decision record)"
                    if category == "historical-decisions"
                    else "cargo test -p do-context-shield (example)"
                ),
            )
            for category in ALLOWED_CATEGORIES
        ]
        self.assertEqual([], validate_invariants(entries))

    def test_rejects_legacy_category_value(self) -> None:
        errors = validate_invariants([make_entry(category="security")])
        self.assertTrue(any("unsupported category 'security'" in e for e in errors), errors)

    def test_rejects_missing_required_fields(self) -> None:
        errors = validate_invariants([{"invariant": "Bare entry"}])
        for field in ("rationale", "sensor", "category"):
            self.assertTrue(
                any(f"missing or invalid field {field}" in e for e in errors),
                (field, errors),
            )

    def test_rejects_non_string_required_fields(self) -> None:
        entry = make_entry(invariant=42, rationale=["not text"], sensor=17, category=[])
        errors = validate_invariants([entry])
        for field in REQUIRED_FIELDS:
            self.assertTrue(
                any(f"missing or invalid field {field}" in error for error in errors),
                (field, errors),
            )

    def test_security_contract_requires_executable_evidence(self) -> None:
        errors = validate_invariants(
            [make_entry(sensor="human review of the privacy boundary")]
        )
        self.assertTrue(
            any("security-contract must cite executable" in e for e in errors), errors
        )

    def test_security_contract_accepts_test_and_sensor_evidence(self) -> None:
        for sensor in (
            "cargo test -p do-context-shield-core",
            "bash scripts/check-loc.sh (loc sensor)",
            "do-harness verify --set verification",
            "crates/example/tests/privacy.rs::test_boundary",
        ):
            self.assertEqual([], validate_invariants([make_entry(sensor=sensor)]), sensor)

    def test_security_contract_rejects_vague_test_prose_as_evidence(self) -> None:
        errors = validate_invariants(
            [make_entry(sensor="tests should cover the privacy boundary")]
        )
        self.assertTrue(
            any("must cite executable test/sensor evidence" in error for error in errors),
            errors,
        )

    def test_security_contract_rejects_review_only(self) -> None:
        errors = validate_invariants(
            [make_entry(sensor="review-only (maintainer-enforced)")]
        )
        self.assertTrue(
            any("security-contract may not be review-only" in e for e in errors), errors
        )

    def test_other_categories_may_document_human_review(self) -> None:
        for category in ("architecture-constraint", "workflow-rule", "historical-decisions"):
            entry = make_entry(
                category=category, sensor="review-only (maintainer-enforced)"
            )
            self.assertEqual([], validate_invariants([entry]), category)

    def test_rejects_duplicate_invariant(self) -> None:
        errors = validate_invariants([make_entry(), make_entry()])
        self.assertTrue(any("duplicate invariant" in e for e in errors), errors)

    def test_rejects_non_list_catalog(self) -> None:
        errors = validate_invariants({"invariants": []})
        self.assertTrue(any("expected a list" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()