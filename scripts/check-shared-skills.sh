#!/usr/bin/env bash
# check-shared-skills.sh — validation script for exported skills and adopter manifest pins
#
# Sensor: scripts/check-shared-skills.sh (do-harness.toml name: shared-skills)
# Checks:
#   1. .agents/exported-skills.json exists, is valid JSON, schema_version is "1.0"
#   2. every exported skill canonical_path exists and matches declared digest (drift check)
#   3. every pinned_commit is a 40-hex commit SHA (moving refs fail closed)
#   4. adopter manifests (if supplied via --adopter) are validated:
#      missing paths, mismatched digests (drift), unknown schema versions, and unpinned moving refs fail closed.
set -euo pipefail

require_tools() { [[ "${CI:-}" == "true" || "${DO_HARNESS_REQUIRE_TOOLS:-}" == "1" ]]; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
    if require_tools; then
        echo "FAIL: python3 is required when CI=true or DO_HARNESS_REQUIRE_TOOLS=1."
        exit 1
    fi
    echo "SKIP: python3 not installed; shared-skills gate unavailable."
    exit 0
fi

python3 - "$@" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(".")
failures = []
drift_reports = []

HEX_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}

def validate_commit_pin(ref, context):
    if not HEX_40_RE.match(ref):
        return f"{context}: moving ref or unpinned commit '{ref}' is invalid; must be a 40-hex commit hash"
    return None

def validate_export_manifest(manifest_path):
    if not manifest_path.is_file():
        return [f"Missing export manifest: {manifest_path}"]
    try:
        data = json.loads(manifest_path.read_text())
    except Exception as err:
        return [f"Export manifest {manifest_path} is not valid JSON: {err}"]

    schema = str(data.get("$schema_version") or data.get("schema_version") or "")
    if schema not in SUPPORTED_SCHEMA_VERSIONS:
        return [f"{manifest_path}: unknown or unsupported schema_version '{schema}'"]

    errs = []
    skills = data.get("exported_skills") or []
    if not skills:
        errs.append(f"{manifest_path}: no exported skills found")

    for skill in skills:
        skill_id = skill.get("id", "<unknown>")
        path_str = skill.get("canonical_path")
        if not path_str:
            errs.append(f"{manifest_path}: skill {skill_id} missing canonical_path")
            continue
        canon_path = root / path_str
        if not canon_path.is_file():
            errs.append(f"{manifest_path}: skill {skill_id} canonical_path '{path_str}' does not exist")
            continue

        commit = skill.get("pinned_commit", "")
        commit_err = validate_commit_pin(commit, f"{manifest_path} skill {skill_id}")
        if commit_err:
            errs.append(commit_err)

        declared_digest = skill.get("digest", "")
        if not declared_digest.startswith("sha256:"):
            errs.append(f"{manifest_path}: skill {skill_id} digest '{declared_digest}' must start with sha256:")
            continue

        expected_hash = hashlib.sha256(canon_path.read_bytes()).hexdigest()
        expected_digest = f"sha256:{expected_hash}"
        if declared_digest != expected_digest:
            drift_reports.append(
                f"DRIFT: {manifest_path} skill {skill_id} digest mismatch! Declared '{declared_digest}', computed '{expected_digest}'"
            )
            errs.append(f"{manifest_path}: skill {skill_id} content drift detected")

    return errs

def validate_adopter_manifest(manifest_path):
    if not manifest_path.is_file():
        return [f"Missing adopter manifest: {manifest_path}"]
    try:
        data = json.loads(manifest_path.read_text())
    except Exception as err:
        return [f"Adopter manifest {manifest_path} is not valid JSON: {err}"]

    schema = str(data.get("$schema_version") or data.get("schema_version") or "")
    if schema not in SUPPORTED_SCHEMA_VERSIONS:
        return [f"{manifest_path}: unknown or unsupported schema_version '{schema}'"]

    errs = []
    pins = data.get("shared_skills") or []
    if not pins:
        errs.append(f"{manifest_path}: no shared_skills pins found")

    for pin in pins:
        skill_id = pin.get("id", "<unknown>")
        path_str = pin.get("canonical_path")
        if not path_str:
            errs.append(f"{manifest_path}: pin {skill_id} missing canonical_path")
            continue
        canon_path = root / path_str
        if not canon_path.is_file():
            errs.append(f"{manifest_path}: pin {skill_id} canonical_path '{path_str}' does not exist")
            continue

        commit = pin.get("pinned_commit", "")
        commit_err = validate_commit_pin(commit, f"{manifest_path} pin {skill_id}")
        if commit_err:
            errs.append(commit_err)

        declared_digest = pin.get("digest", "")
        if not declared_digest.startswith("sha256:"):
            errs.append(f"{manifest_path}: pin {skill_id} digest '{declared_digest}' must start with sha256:")
            continue

        expected_hash = hashlib.sha256(canon_path.read_bytes()).hexdigest()
        expected_digest = f"sha256:{expected_hash}"
        if declared_digest != expected_digest:
            drift_reports.append(
                f"DRIFT: {manifest_path} pin {skill_id} digest mismatch! Declared '{declared_digest}', computed '{expected_digest}'"
            )
            errs.append(f"{manifest_path}: pin {skill_id} content drift detected")

        adaptations = pin.get("adaptations")
        if adaptations is None:
            errs.append(f"{manifest_path}: pin {skill_id} missing explicit local adaptations field")

    return errs

args = sys.argv[1:]
if "--adopter" in args:
    idx = args.index("--adopter")
    if idx + 1 < len(args):
        adopter_file = pathlib.Path(args[idx + 1])
        errs = validate_adopter_manifest(adopter_file)
        failures.extend(errs)
    else:
        failures.append("--adopter flag requires a manifest file path argument")
else:
    # Default execution: check repo export manifest
    export_manifest = root / ".agents/exported-skills.json"
    failures.extend(validate_export_manifest(export_manifest))

for drift in drift_reports:
    print(f"WARN: {drift}")

for failure in failures:
    print(f"FAIL: {failure}")

if failures:
    sys.exit(1)

print("shared-skills check OK.")
sys.exit(0)
PY
