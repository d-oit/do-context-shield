#!/usr/bin/env python3
"""Select required security checks for changed paths, failing safe to full verification."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = REPOSITORY_ROOT / "plans" / "security-regression-map.json"
SIGNAL_SET = "verification"
SECURITY_SENSOR = "security-regression"

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
    _string_list(safe_paths.get("exact"), "safe exact paths")
    _string_list(safe_paths.get("prefixes"), "safe path prefixes")
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


def classify_path(path: str, data: dict[str, Any]) -> dict[str, Any]:
    if not path or path.startswith("/") or "\x00" in path or ".." in path.split("/"):
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


def classify_paths(paths: list[str], data: dict[str, Any]) -> dict[str, Any]:
    if not paths:
        return {"fallback": False, "kind": "unchanged", "required_sensors": [], "names": []}

    required: set[str] = set()
    names: set[str] = set()
    safe_count = 0
    for path in paths:
        decision = classify_path(path, data)
        if decision["kind"] == "fallback":
            return {
                "fallback": True,
                "reason": decision["reason"],
                "required_sensors": [],
                "names": [],
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
    }


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
    if decision["fallback"]:
        return run_full_verification(root, decision["reason"])
    if decision["kind"] == "unchanged":
        print("Security regression gate: no working-tree changes to classify.")
        return 0

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
