#!/usr/bin/env python3
"""Integration tests for shared skill export contracts, drift detection, and adopter validation."""

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parent.parent.resolve()
SCRIPT = ROOT / "scripts" / "check-shared-skills.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "shared-skills"


def run_check(adopter_fixture):
    proc = subprocess.run(
        ["bash", str(SCRIPT), "--adopter", str(adopter_fixture)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def main():
    print("Running shared skills integration test suite...")

    # 1. Valid adopter fixture
    rc, out = run_check(FIXTURES / "valid_adopter.json")
    if rc != 0 or "shared-skills check OK." not in out:
        print(f"FAIL: valid_adopter failed unexpectedly. rc={rc}, output:\n{out}")
        sys.exit(1)
    print("PASS: valid_adopter verified with deterministic digest.")

    # 2. Drifted adopter fixture
    rc, out = run_check(FIXTURES / "drifted_adopter.json")
    if rc == 0 or "DRIFT:" not in out or "content drift detected" not in out:
        print(f"FAIL: drifted_adopter did not report drift as expected. rc={rc}, output:\n{out}")
        sys.exit(1)
    print("PASS: drifted_adopter correctly reported upstream drift.")

    # 3. Unpinned moving ref adopter fixture
    rc, out = run_check(FIXTURES / "unpinned_adopter.json")
    if rc == 0 or "moving ref or unpinned commit 'main' is invalid" not in out:
        print(f"FAIL: unpinned_adopter did not reject moving ref as expected. rc={rc}, output:\n{out}")
        sys.exit(1)
    print("PASS: unpinned_adopter correctly rejected moving ref 'main'.")

    # 4. Unknown schema version adopter fixture
    rc, out = run_check(FIXTURES / "unknown_schema_adopter.json")
    if rc == 0 or "unknown or unsupported schema_version '99.0'" not in out:
        print(f"FAIL: unknown_schema_adopter did not reject schema version as expected. rc={rc}, output:\n{out}")
        sys.exit(1)
    print("PASS: unknown_schema_adopter correctly failed closed on unknown schema version.")

    # 5. Missing path adopter fixture
    rc, out = run_check(FIXTURES / "missing_path_adopter.json")
    if rc == 0 or "canonical_path '.agents/skills/nonexistent/portable.md' does not exist" not in out:
        print(f"FAIL: missing_path_adopter did not report missing path as expected. rc={rc}, output:\n{out}")
        sys.exit(1)
    print("PASS: missing_path_adopter correctly failed closed on missing path.")

    # 6. Default execution (export manifest check)
    proc = subprocess.run(["bash", str(SCRIPT)], cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0 or "shared-skills check OK." not in proc.stdout:
        print(f"FAIL: default export manifest check failed. rc={proc.returncode}, output:\n{proc.stdout}{proc.stderr}")
        sys.exit(1)
    print("PASS: default export contract manifest verified.")

    print("\nAll shared skill tests PASSED successfully!")


if __name__ == "__main__":
    main()
