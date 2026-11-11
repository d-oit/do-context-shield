#!/usr/bin/env python3
"""Behavioral tests for active-backlog status and internal-link validation."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import backlog_validation  # noqa: E402

VALID_BACKLOG = """# Backlog

## Active work

### Ship a workflow
- **Status**: active

## External blockers

### Issue #188: approval to rerun the release workflow
- **Status**: blocked

### Claude Code end-to-end client probe
- **Status**: blocked

## Residual risks

### Glued-only secret occurrences can evade detection
- **Status**: residual-risk
"""


class BacklogValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="backlog-validation-")
        self.root = Path(self.temp.name)
        (self.root / "plans").mkdir()
        (self.root / "docs" / "decisions").mkdir(parents=True)
        (self.root / "docs" / "test-evidence").mkdir(parents=True)
        (self.root / "plans" / "backlog.md").write_text(
            VALID_BACKLOG + "\nSee [decision](../docs/decisions/decision.md#held-decision).\n",
            encoding="utf-8",
        )
        (self.root / "docs" / "decisions" / "decision.md").write_text(
            "# Decision\n\n## Held decision\n\nDetails.\n", encoding="utf-8"
        )
        (self.root / "docs" / "test-evidence" / "runs.md").write_text(
            "# Evidence\n\nMeasurements.\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_accepts_active_blocked_and_residual_statuses_with_valid_links(self) -> None:
        self.assertEqual([], backlog_validation.validate_repository(self.root))

    def test_rejects_completed_status(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text(VALID_BACKLOG.replace("Status**: active", "Status**: done", 1), encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("unsupported status 'done'" in error for error in errors), errors)

    def test_requires_one_status_per_entry(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text(VALID_BACKLOG.replace("- **Status**: active\n", "", 1), encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("must declare exactly one status" in error for error in errors), errors)

    def test_status_must_match_section(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text(VALID_BACKLOG.replace("Status**: blocked", "Status**: active", 1), encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("requires status 'blocked'" in error for error in errors), errors)

    def test_rejects_missing_local_markdown_link(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text(VALID_BACKLOG + "\n[missing](../docs/decisions/missing.md)\n", encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("missing local link target" in error for error in errors), errors)

    def test_rejects_missing_heading_anchor(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text(VALID_BACKLOG + "\n[bad anchor](../docs/decisions/decision.md#not-found)\n", encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("missing heading anchor 'not-found'" in error for error in errors), errors)

    def test_rejects_empty_local_link_target(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text(VALID_BACKLOG + "\n[empty]()\n", encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("empty local link target" in error for error in errors), errors)

    def test_rejects_unknown_sections_and_entries_outside_sections(self) -> None:
        path = self.root / "plans" / "backlog.md"
        path.write_text("# Backlog\n\n## Completed\n\n### Finished\n- **Status**: done\n", encoding="utf-8")
        errors = backlog_validation.validate_repository(self.root)
        self.assertTrue(any("unsupported backlog section 'Completed'" in error for error in errors), errors)
        self.assertTrue(any("unsupported status 'done'" in error for error in errors), errors)

    def test_rejects_removing_required_blockers_or_residuals(self) -> None:
        path = self.root / "plans" / "backlog.md"
        required_entries = (
            (
                "Issue #188",
                "### Issue #188: approval to rerun the release workflow\n- **Status**: blocked\n\n",
            ),
            (
                "Glued-only secret",
                "### Glued-only secret occurrences can evade detection\n- **Status**: residual-risk\n",
            ),
        )
        for required_title, entry in required_entries:
            with self.subTest(required_title=required_title):
                path.write_text(VALID_BACKLOG.replace(entry, "", 1), encoding="utf-8")
                errors = backlog_validation.validate_repository(self.root)
                self.assertTrue(
                    any("required open item" in error and required_title in error for error in errors),
                    errors,
                )


if __name__ == "__main__":
    unittest.main()
