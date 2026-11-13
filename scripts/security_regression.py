#!/usr/bin/env python3
"""Select required security checks for changed paths, failing safe to full verification."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from workflow_profile_rules import (
    FEATURE_RULE_PATHS,
    SAFE_EXACT_PATHS,
    SAFE_PREFIXES,
    matches_explicit_feature_path,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = REPOSITORY_ROOT / "plans" / "security-regression-map.json"
SIGNAL_SET = "verification"
SECURITY_SENSOR = "security-regression"
PROFILES = ("quick-fix", "feature", "security-critical")
PROFILE_RANK = {name: rank for rank, name in enumerate(PROFILES)}


# Keep the map and gate self-protecting: a malformed or edited map cannot
# classify its own inputs as documentation-only and bypass broader checks.
REQUIRED_GLOBAL_EXACT = {
    "do-harness.toml",
    "plans/security-regression-map.json",
    "scripts/security_regression.py",
    "scripts/check-security-regression.sh",
}
REQUIRED_GLOBAL_PREFIXES = {".agents/", ".cargo/", ".github/", ".githooks/", "plans/", "scripts/"}


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"invalid {field}")
    return value


def load_map(path: Path = MAP_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported security map schema")
    if data.get("signal_set") != SIGNAL_SET or data.get("fallback_signal_set") != SIGNAL_SET:
        raise ValueError("security map must use the verification signal set")
    if data.get("security_sensor") != SECURITY_SENSOR:
        raise ValueError("security map names a different gate sensor")

    global_paths = data.get("global_paths")
    if not isinstance(global_paths, dict):
        raise ValueError("missing global path rules")
    global_exact = set(_string_list(global_paths.get("exact"), "global exact paths"))
    global_prefixes = set(_string_list(global_paths.get("prefixes"), "global path prefixes"))
    if not REQUIRED_GLOBAL_EXACT <= global_exact or not REQUIRED_GLOBAL_PREFIXES <= global_prefixes:
        raise ValueError("security map omits a gate or global configuration path")

    for key in ("components", "path_rules"):
        rules = data.get(key)
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"missing {key}")
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("name"), str):
                raise ValueError(f"invalid rule in {key}")
            sensors = _string_list(rule.get("required_sensors"), f"{key} required sensors")
            if not sensors:
                raise ValueError(f"rule in {key} has no required sensors")
            for field in ("exact", "prefixes", "suffixes"):
                if field in rule:
                    _string_list(rule[field], f"{key} {field}")
            if not any(field in rule for field in ("exact", "prefixes", "suffixes")):
                raise ValueError(f"rule in {key} has no path matcher")

    safe_paths = data.get("safe_paths")
    if not isinstance(safe_paths, dict):
        raise ValueError("missing safe path rules")
    safe_exact = set(_string_list(safe_paths.get("exact"), "safe exact paths"))
    safe_prefixes = set(_string_list(safe_paths.get("prefixes"), "safe path prefixes"))
    if not safe_exact <= SAFE_EXACT_PATHS or not safe_prefixes <= set(SAFE_PREFIXES):
        raise ValueError("safe path rules exceed the fixed low-risk allowlist")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        raise ValueError("security map must define exactly the three workflow profiles")
    for name, profile in profiles.items():
        if not isinstance(profile, dict) or profile.get("signal_set") != name:
            raise ValueError(f"profile {name} must reference its named signal set")
        for field in ("invocation", "recon", "planning", "tests", "evidence", "rationale"):
            if not isinstance(profile.get(field), str) or not profile[field]:
                raise ValueError(f"profile {name} has invalid {field}")
    if profiles["quick-fix"]["invocation"] != "do-harness verify --changed --set quick-fix --strict":
        raise ValueError("quick-fix invocation must use changed-only strict selection")
    if profiles["feature"]["invocation"] != "do-harness verify --changed --set feature --strict":
        raise ValueError("feature invocation must use changed-only strict selection")
    if profiles["security-critical"]["invocation"] != "do-harness verify --set security-critical --strict":
        raise ValueError("security-critical invocation must run full strict verification")

    critical_paths = data.get("security_critical_paths")
    if not isinstance(critical_paths, list) or not critical_paths:
        raise ValueError("missing security-critical path rules")
    for rule in critical_paths:
        if not isinstance(rule, dict) or not any(field in rule for field in ("exact", "prefixes", "suffixes")):
            raise ValueError("invalid security-critical path matcher")
        for field in ("exact", "prefixes", "suffixes"):
            if field in rule:
                _string_list(rule[field], f"security-critical {field}")

    feature_rules = _string_list(data.get("feature_path_rules"), "feature path rules")
    known_path_rules = {rule["name"] for rule in data["path_rules"]}
    if (
        not feature_rules
        or len(feature_rules) != len(set(feature_rules))
        or not set(feature_rules) <= known_path_rules
        or not set(feature_rules).issubset(FEATURE_RULE_PATHS)
    ):
        raise ValueError("feature profile references unknown, duplicate, or non-allowlisted path rules")

    return data


def _matches_path(path: str, rule: dict[str, Any]) -> bool:
    exact = rule.get("exact", [])
    prefixes = rule.get("prefixes", [])
    suffixes = rule.get("suffixes", [])
    if exact:
        return path in exact
    if prefixes and not any(path.startswith(prefix) for prefix in prefixes):
        return False
    if suffixes and not any(path.endswith(suffix) for suffix in suffixes):
        return False
    return bool(prefixes or suffixes)


def _matches_group(path: str, rules: dict[str, Any]) -> bool:
    return path in rules.get("exact", []) or any(
        path.startswith(prefix) for prefix in rules.get("prefixes", [])
    )


def classify_profile_path(path: str, data: dict[str, Any]) -> dict[str, str]:
    classification = classify_path(path, data)
    if classification["kind"] == "fallback":
        return {"profile": "security-critical", "reason": classification["reason"]}

    component_prefixes = {
        prefix for rule in data["components"] for prefix in rule.get("prefixes", [])
    }
    if any(path.startswith(prefix) for prefix in component_prefixes):
        return {"profile": "security-critical", "reason": "security component or shared API path"}
    if any(_matches_path(path, rule) for rule in data["components"]):
        return {"profile": "security-critical", "reason": "security component or shared API path"}
    if any(_matches_path(path, rule) for rule in data["security_critical_paths"]):
        return {"profile": "security-critical", "reason": "workspace or security-critical path"}

    if classification["kind"] == "safe" and (
        path in SAFE_EXACT_PATHS or path.startswith(SAFE_PREFIXES)
    ):
        return {"profile": "quick-fix", "reason": "explicitly safe low-risk path"}

    feature_rule_names = set(data["feature_path_rules"])
    matched_names = {
        rule["name"] for rule in data["path_rules"] if _matches_path(path, rule)
    }
    if (
        matched_names
        and matched_names <= feature_rule_names
        and matches_explicit_feature_path(path, matched_names)
    ):
        return {"profile": "feature", "reason": "explicitly mapped low-risk dependent path"}
    return {"profile": "security-critical", "reason": "path is not explicitly eligible for a low-risk profile"}


def _profile_for_paths(paths: list[str], data: dict[str, Any]) -> dict[str, Any]:
    decisions = sorted(
        ({"path": path, **classify_profile_path(path, data)} for path in paths),
        key=lambda item: item["path"],
    )
    if not decisions:
        return {"name": None, "reason": "no changed paths", "paths": []}
    strictest = max(decisions, key=lambda item: PROFILE_RANK[item["profile"]])
    return {
        "name": strictest["profile"],
        "reason": strictest["reason"],
        "paths": decisions,
    }


def classify_profile(paths: list[str], data: dict[str, Any]) -> dict[str, Any]:
    """Return one deterministic workflow profile for the complete changed-path set."""
    return _profile_for_paths(paths, data)


def classify_paths(paths: list[str], data: dict[str, Any]) -> dict[str, Any]:
    profile = _profile_for_paths(paths, data)
    if not paths:
        return {
            "fallback": False,
            "kind": "unchanged",
            "required_sensors": [],
            "names": [],
            "profile": profile,
        }

    required: set[str] = set()
    names: set[str] = set()
    safe_count = 0
    for path in paths:
        decision = classify_path(path, data)
        if decision["kind"] == "fallback":
            return {
                "fallback": True,
                "kind": "fallback",
                "reason": decision["reason"],
                "required_sensors": [],
                "names": [],
                "profile": profile,
            }
        if decision["kind"] == "safe":
            safe_count += 1
        else:
            required.update(decision["required_sensors"])
            names.update(decision["names"])

    return {
        "fallback": False,
        "kind": "mapped" if names else "safe",
        "required_sensors": sorted(required),
        "names": sorted(names),
        "safe_count": safe_count,
        "profile": profile,
    }

def classify_path(path: str, data: dict[str, Any]) -> dict[str, Any]:
    segments = path.split("/")
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(segment in ("", ".", "..") for segment in segments)
    ):
        return {"kind": "fallback", "reason": "unsafe or malformed repository path"}

    if _matches_group(path, data["global_paths"]):
        return {"kind": "fallback", "reason": "global build, harness, workflow, or shared input"}

    component_matches = [rule for rule in data["components"] if _matches_path(path, rule)]
    path_rule_matches = [rule for rule in data["path_rules"] if _matches_path(path, rule)]
    safe = _matches_group(path, data["safe_paths"])

    if safe and (component_matches or path_rule_matches):
        return {"kind": "fallback", "reason": "path matches both safe and checked classifications"}

    if component_matches or path_rule_matches:
        matched = component_matches + path_rule_matches
        sensors = {
            sensor for rule in matched for sensor in rule["required_sensors"]
        }
        return {
            "kind": "mapped",
            "names": sorted({rule["name"] for rule in matched}),
            "required_sensors": sorted(sensors),
        }

    if safe:
        return {"kind": "safe", "required_sensors": []}
    return {"kind": "fallback", "reason": "unmapped path"}




def _decode_git_paths(raw: bytes, statuses: bool) -> list[str]:
    tokens = raw.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(tokens) and tokens[index]:
        if statuses:
            status = tokens[index].decode("ascii", errors="replace")
            index += 1
            count = 2 if status.startswith(("R", "C")) else 1
            if index + count > len(tokens) or any(not token for token in tokens[index : index + count]):
                raise ValueError("malformed git name-status output")
            paths.extend(os.fsdecode(token) for token in tokens[index : index + count])
            index += count
        else:
            paths.append(os.fsdecode(tokens[index]))
            index += 1
    return paths


def discover_changed_paths(root: Path) -> list[str]:
    diff = subprocess.run(
        ["git", "diff", "--name-status", "-z", "--find-renames", "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if diff.returncode != 0:
        raise RuntimeError("git diff could not determine changed paths")
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if untracked.returncode != 0:
        raise RuntimeError("git could not enumerate untracked paths")
    return sorted(set(_decode_git_paths(diff.stdout, statuses=True) + _decode_git_paths(untracked.stdout, statuses=False)))


def _explain(root: Path) -> dict[str, Any]:
    binary = os.environ.get("DO_HARNESS_BIN", "do-harness")
    result = subprocess.run(
        [binary, "--root", str(root), "explain", "--set", SIGNAL_SET, "--changed", "--format", "json"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("do-harness explain failed")
    report = json.loads(result.stdout)
    selected = report.get("selected")
    if not isinstance(selected, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("reason"), str)
        for item in selected
    ):
        raise ValueError("do-harness explain returned an invalid selection")
    return report


def run_full_verification(root: Path, reason: str) -> int:
    binary = os.environ.get("DO_HARNESS_BIN", "do-harness")
    command = [
        binary,
        "--root",
        str(root),
        "verify",
        "--set",
        SIGNAL_SET,
        "--exclude",
        SECURITY_SENSOR,
        "--strict",
    ]
    print(f"Security regression gate: {reason}; running the full `{SIGNAL_SET}` signal set.", flush=True)
    print("Command: do-harness verify --set verification --exclude security-regression --strict", flush=True)
    try:
        return subprocess.run(command, cwd=root, check=False).returncode
    except OSError:
        print("Security regression gate: do-harness could not be executed; failing closed.", file=sys.stderr)
        return 127


def run_gate(root: Path) -> int:
    try:
        data = load_map()
        paths = discover_changed_paths(root)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        return run_full_verification(root, f"change classification failed ({type(error).__name__})")

    decision = classify_paths(paths, data)
    if decision["kind"] == "unchanged":
        print("Security regression gate: no working-tree changes to classify.")
        return 0

    profile = decision["profile"]
    print(
        f"Workflow profile: {profile['name']} — {profile['reason']}.",
        flush=True,
    )
    if decision["fallback"]:
        return run_full_verification(root, decision["reason"])
    if profile["name"] == "security-critical":
        return run_full_verification(root, "security-critical workflow profile selected")

    try:
        report = _explain(root)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        return run_full_verification(root, f"sensor selection could not be verified ({type(error).__name__})")

    selected = {item["name"] for item in report["selected"]}
    expected = set(decision["required_sensors"]) | {SECURITY_SENSOR}
    missing = expected - selected
    if missing:
        return run_full_verification(root, f"required sensors are not selected: {', '.join(sorted(missing))}")

    if decision["kind"] == "safe":
        print("Security regression gate: documentation-only paths are classified as safe; always-on checks remain selected.")
    else:
        print(f"Security regression gate: mapped components/rules: {', '.join(decision['names'])}.")
        print(f"Required sensors: {', '.join(decision['required_sensors'])}.")
    print("Selected sensors and reasons:")
    for item in report["selected"]:
        print(f"  {item['name']}: {item['reason']}")
    return 0


def main() -> int:
    return run_gate(Path.cwd())


if __name__ == "__main__":
    raise SystemExit(main())
