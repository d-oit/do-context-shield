#!/usr/bin/env python3
"""Behavioral fixtures for changed-path selection and fail-closed fallback."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import security_regression  # noqa: E402

HARNESS = os.environ.get("DO_HARNESS_BIN", "do-harness")


class HarnessFixture:
    def __init__(self, config_source: Path | None = None) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="security-selection-")
        self.root = Path(self.temp.name)
        if config_source is None:
            shutil.copy2(ROOT / "do-harness.toml", self.root / "do-harness.toml")
        else:
            shutil.copy2(config_source, self.root / "do-harness.toml")
        (self.root / ".baseline").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "security-test@example.invalid"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Security Selection Test"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture baseline"], cwd=self.root, check=True)

    def add(self, path: str) -> None:
        file_path = self.root / path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text("fixture\n", encoding="utf-8")

    def explain(self, signal_set: str = "verification", changed: bool = True) -> dict[str, object]:
        command = [HARNESS, "--root", str(self.root), "explain", "--set", signal_set]
        if changed:
            command.append("--changed")
        command.extend(["--format", "json"])
        result = subprocess.run(command, cwd=self.root, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(f"do-harness explain failed: {result.stderr}")
        return json.loads(result.stdout)

    def close(self) -> None:
        self.temp.cleanup()


class SecurityRegressionSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.security_map = security_regression.load_map()

    def test_ci_explain_reports_a_reason_for_every_selected_sensor(self) -> None:
        result = subprocess.run(
            [HARNESS, "explain", "--set", "ci", "--format", "json"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        selected = json.loads(result.stdout)["selected"]
        self.assertIn("security-regression", {item["name"] for item in selected})
        self.assertTrue(selected)
        self.assertTrue(all(isinstance(item.get("reason"), str) and item["reason"] for item in selected))

    def assert_selected(self, path: str, expected: set[str]) -> dict[str, object]:
        fixture = HarnessFixture()
        try:
            fixture.add(path)
            report = fixture.explain()
            selected = {item["name"] for item in report["selected"]}
            self.assertTrue(expected <= selected, f"{path}: expected {expected}; selected {selected}")
            return report
        finally:
            fixture.close()

    def test_complete_path_sets_select_exactly_one_deterministic_profile(self) -> None:
        cases = {
            ("docs/architecture.md",): "quick-fix",
            ("quality/corpus/v1.json",): "feature",
            ("crates/plugin-api/src/lib.rs",): "security-critical",
            ("Cargo.toml",): "security-critical",
            ("unknown/opaque.yaml",): "security-critical",
            ("tests/test_shared_skills.py",): "feature",
        }
        for paths, expected in cases.items():
            with self.subTest(paths=paths):
                self.assertEqual(expected, security_regression.classify_profile(list(paths), self.security_map)["name"])

        self.assertEqual(
            "feature",
            security_regression.classify_profile(
                ["docs/architecture.md", "quality/corpus/v1.json"], self.security_map
            )["name"],
        )
        for paths in (
            ["quality/corpus/v1.json", "crates/plugin-api/src/lib.rs"],
            ["crates/plugin-api/src/lib.rs", "quality/corpus/v1.json"],
        ):
            self.assertEqual(
                "security-critical",
                security_regression.classify_profile(paths, self.security_map)["name"],
            )

    def test_security_component_workspace_global_and_ambiguous_paths_are_strict(self) -> None:
        paths = (
            "crates/plugin-api/src/lib.rs",
            "crates/plugin-api/README.md",
            "Cargo.toml",
            "crates/benchmarks/Cargo.toml",
            "do-harness.toml",
            ".github/workflows/ci.yml",
            "../outside",
            "docs//malformed.md",
            "docs/./malformed.md",
            r"docs\malformed.md",
            "",
            "unknown/config.yaml",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(
                    "security-critical",
                    security_regression.classify_profile([path], self.security_map)["name"],
                )

        ambiguous_map = copy.deepcopy(self.security_map)
        ambiguous_map["components"].append(
            {
                "name": "conflicting-document-rule",
                "prefixes": ["docs/"],
                "suffixes": [".md"],
                "required_sensors": ["test"],
            }
        )
        self.assertEqual(
            "security-critical",
            security_regression.classify_profile(["docs/architecture.md"], ambiguous_map)["name"],
        )

    def test_low_risk_profiles_cannot_be_broadened_to_unmapped_code(self) -> None:
        broadened_safe = copy.deepcopy(self.security_map)
        broadened_safe["safe_paths"]["prefixes"].append("crates/")
        self.assertEqual(
            "security-critical",
            security_regression.classify_profile(
                ["crates/new-component/src/lib.rs"], broadened_safe
            )["name"],
        )

        broadened_feature = copy.deepcopy(self.security_map)
        quality_rule = next(
            rule
            for rule in broadened_feature["path_rules"]
            if rule["name"] == "detector-quality-corpus"
        )
        quality_rule["prefixes"] = ["crates/"]
        self.assertEqual(
            "security-critical",
            security_regression.classify_profile(
                ["crates/new-component/src/lib.rs"], broadened_feature
            )["name"],
        )

        broadened_feature["feature_path_rules"].append("process-plugin-fixtures")
        self.assertEqual(
            "security-critical",
            security_regression.classify_profile(
                ["crates/plugin-process/tests/fixtures/plugin.sh"], broadened_feature
            )["name"],
        )

    def test_profile_signal_sets_select_expected_sensors_with_explain(self) -> None:
        profile_sets = tomllib.loads((ROOT / "do-harness.toml").read_text(encoding="utf-8"))["signal-sets"]
        fixture = HarnessFixture()
        try:
            fixture.add("docs/quick-fix.md")
            quick_fix = {item["name"] for item in fixture.explain("quick-fix")["selected"]}
            self.assertIn("security-regression", quick_fix)
            self.assertTrue(
                {"fmt", "check", "clippy", "test", "security-regression"}
                <= set(profile_sets["quick-fix"])
            )

            fixture.add("quality/corpus/new-case.json")
            feature = {item["name"] for item in fixture.explain("feature")["selected"]}
            self.assertTrue({"test", "security-regression"} <= feature)
            fixture.add("tests/test_shared_skills.py")
            feature = {item["name"] for item in fixture.explain("feature")["selected"]}
            self.assertIn("skills", feature)


            fixture.add("crates/plugin-api/src/public.rs")
            critical = {item["name"] for item in fixture.explain("security-critical", changed=False)["selected"]}
            verification = set(profile_sets["verification"])
            self.assertEqual(verification, critical)
            self.assertEqual(verification, set(profile_sets["feature"]))
            self.assertEqual(verification, set(profile_sets["security-critical"]))
            self.assertIn("security-regression", critical)
            for profile, path, sensors in (
                ("quick-fix", "docs/quick-fix.md", quick_fix),
                ("feature", "quality/corpus + shared-skill test", feature),
                ("security-critical", "crates/plugin-api", critical),
            ):
                print(f"Workflow profile dry-run {profile} ({path}):")
                print(f"  sensors: {', '.join(sorted(sensors))}")
        finally:
            fixture.close()

    def test_security_components_select_workspace_build_and_test_sensors(self) -> None:
        paths = [
            "crates/detector-regex/src/lib.rs",
            "crates/privacy-core/src/plan.rs",
            "crates/policy-matrix/src/lib.rs",
            "crates/transformer-pseudonymize/src/lib.rs",
            "crates/vault-json/src/lib.rs",
            "crates/plugin-api/src/placeholder.rs",
            "crates/plugin-process/src/lib.rs",
            "crates/mcp-server/src/framing.rs",
            "crates/audit-file/src/lib.rs",
            "crates/do-context-shield-cli/src/config.rs",
        ]
        required = {"fmt", "check", "clippy", "test", "loc"}
        for path in paths:
            with self.subTest(path=path):
                self.assert_selected(path, required | {"security-regression"})
                decision = security_regression.classify_path(path, self.security_map)
                self.assertTrue(required <= set(decision["required_sensors"]))

    def test_non_rust_inputs_select_their_consuming_sensor(self) -> None:
        cases = {
            "quality/corpus/v1.json": {"test", "security-regression"},
            "crates/do-context-shield-cli/tests/fixtures/mcp_threat_cases.json": {"test", "security-regression"},
            "crates/plugin-process/tests/fixtures/hostile-response.sh": {"test", "shellcheck", "security-regression"},
            "tests/test_shared_skills.py": {"skills", "security-regression"},
            "tests/fixtures/shared-skills/valid_adopter.json": {"skills", "security-regression"},
            "fuzz/fuzz_targets/fuzz_mcp_parse.rs": {"fuzz-check", "security-regression"},
            "crates/plugin-api/Cargo.toml": {
                "fmt",
                "check",
                "clippy",
                "test",
                "publish-order",
                "release-preflight",
                "security-regression",
            },
            "crates/audit-file/README.md": {"release-preflight", "security-regression"},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assert_selected(path, expected)
                decision = security_regression.classify_path(path, self.security_map)
                self.assertEqual("mapped", decision["kind"])
                self.assertTrue(expected - {"security-regression"} <= set(decision["required_sensors"]))

    def test_root_manifest_and_global_workflow_classify_broadly(self) -> None:
        manifest = security_regression.classify_path("Cargo.toml", self.security_map)
        workflow = security_regression.classify_path(".github/workflows/ci.yml", self.security_map)
        self.assertEqual("fallback", manifest["kind"])
        self.assertEqual("fallback", workflow["kind"])
        self.assert_selected(
            "Cargo.toml",
            {
                "fmt",
                "check",
                "clippy",
                "test",
                "deps",
                "audit",
                "publish-order",
                "release-preflight",
                "commitlint",
                "security-regression",
            },
        )
        self.assert_selected(".github/workflows/ci.yml", {"security-regression"})

    def test_documentation_is_the_only_safe_exclusion(self) -> None:
        excluded = {
            "fmt",
            "check",
            "clippy",
            "test",
            "loc",
            "shellcheck",
            "hooks",
            "skills",
            "skill-evals",
            "shared-skills",
            "publish-order",
            "release-preflight",
            "fuzz-check",
        }
        for path in ("README.md", "CHANGELOG.md", "docs/architecture.md"):
            with self.subTest(path=path):
                decision = security_regression.classify_path(path, self.security_map)
                self.assertEqual("safe", decision["kind"])
                report = self.assert_selected(path, {"security-regression"})
                selected = {item["name"] for item in report["selected"]}
                self.assertTrue(excluded.isdisjoint(selected), f"{path}: unexpected checks selected: {selected & excluded}")
        self.assertEqual("fallback", security_regression.classify_path("unknown/config.yaml", self.security_map)["kind"])

    def test_safe_and_component_overlap_is_ambiguous(self) -> None:
        ambiguous_map = copy.deepcopy(self.security_map)
        ambiguous_map["components"].append(
            {
                "name": "conflicting-document-rule",
                "prefixes": ["docs/"],
                "suffixes": [".md"],
                "required_sensors": ["test"],
            }
        )
        decision = security_regression.classify_path("docs/architecture.md", ambiguous_map)
        self.assertEqual("fallback", decision["kind"])

    def test_renames_preserve_the_protected_source_path(self) -> None:
        fixture = HarnessFixture()
        try:
            source = fixture.root / "crates" / "plugin-api" / "src" / "public.rs"
            source.parent.mkdir(parents=True)
            source.write_text("".join(f"pub fn item_{index}() {{}}\n" for index in range(40)), encoding="utf-8")
            subprocess.run(["git", "add", "crates/plugin-api/src/public.rs"], cwd=fixture.root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "add protected source"], cwd=fixture.root, check=True)
            target = fixture.root / "docs" / "public-api.md"
            target.parent.mkdir(parents=True)
            source.rename(target)
            changed = security_regression.discover_changed_paths(fixture.root)
            self.assertIn("crates/plugin-api/src/public.rs", changed)
            self.assertIn("docs/public-api.md", changed)
            decision = security_regression.classify_paths(changed, self.security_map)
            self.assertFalse(decision["fallback"])
            self.assertTrue({"check", "clippy", "test", "loc"} <= set(decision["required_sensors"]))
        finally:
            fixture.close()

    def test_unknown_global_and_underselected_paths_run_full_verification(self) -> None:
        paths = ("unmapped/opaque.json", ".github/workflows/ci.yml", "crates/plugin-api/src/api.rs")
        for path in paths:
            with self.subTest(path=path):
                self._run_fallback_fixture(path)

    def _run_fallback_fixture(self, changed_path: str) -> None:
        with tempfile.TemporaryDirectory(prefix="security-fallback-") as directory:
            root = Path(directory)
            # Keep the probe sentinel out of the untracked input manifest.
            marker = root / ".git" / "full-verification.marker"
            gate = str(ROOT / "scripts" / "security_regression.py").replace("\\", "\\\\").replace('"', '\\"')
            config_text = (
                'language = "rust"\n\n'
                '[signal-sets]\n'
                'verification = ["security-regression", "probe"]\n\n'
                '[[sensors]]\n'
                'name = "security-regression"\n'
                f'argv = ["python3", "{gate}"]\n\n'
                '[[sensors]]\n'
                'name = "probe"\n'
                'argv = ["python3", "-c", "from pathlib import Path; Path(\'.git/full-verification.marker\').write_text(\'ran\')"]\n'
                'when-changed = ["known/**"]\n'
            )
            (root / "do-harness.toml").write_text(config_text, encoding="utf-8")
            (root / ".baseline").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "security-test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Security Selection Test"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "fallback baseline"], cwd=root, check=True)
            changed = root / changed_path
            changed.parent.mkdir(parents=True, exist_ok=True)
            changed.write_text("trigger fallback\n", encoding="utf-8")
            preview = subprocess.run(
                [HARNESS, "--root", str(root), "explain", "--set", "verification", "--changed", "--format", "json"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, preview.returncode, preview.stderr)
            self.assertNotIn("probe", {item["name"] for item in json.loads(preview.stdout)["selected"]})
            result = subprocess.run(
                [HARNESS, "--root", str(root), "verify", "--changed", "--set", "verification", "--strict"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, f"fallback verification failed:\n{result.stdout}\n{result.stderr}")
            self.assertTrue(marker.is_file(), f"fallback sensor did not run:\n{result.stdout}\n{result.stderr}")


if __name__ == "__main__":
    unittest.main()
