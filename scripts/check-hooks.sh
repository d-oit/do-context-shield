#!/usr/bin/env bash
# check-hooks.sh — the git hooks are the local gate, so their wiring is checked.
#
# Sensor: scripts/check-hooks.sh
# Enforces the hook invariant: hooks come from `.githooks` via
# `core.hooksPath`, and a `do-harness hook install` into `.git/hooks` is the
# per-developer alternative — the two must never be combined. It also asserts
# that every sensor `do-harness.toml` declares for a hook is actually invoked
# by that hook, so adding a sensor to the hook list without mirroring it in the
# hand-written hook fails here instead of silently weakening the local gate.
#
# `do-harness doctor` cannot cover this: it only inspects `.git/hooks`, so it
# reports "hook absent" warnings in the documented `.githooks` mode.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="do-harness.toml"
FAIL=0

# Hook -> the non-sample hooks that exist in .git/hooks when the alternative
# installation mode is in use.
HOOKS=(pre-commit pre-push commit-msg)

# Sensor -> the command fragments that count as "the hook runs this sensor".
# Alternatives are separated by `|`; `loc` has an inline staged-file variant in
# the pre-commit hook, everything else points at the shared script or cargo.
sensor_needles() {
    case "$1" in
        fmt) echo "cargo fmt --all -- --check" ;;
        check) echo "cargo check" ;;
        clippy) echo "cargo clippy" ;;
        test) echo "cargo test" ;;
        loc) echo "scripts/check-loc.sh|wc -l" ;;
        shellcheck) echo "scripts/check-shellcheck.sh" ;;
        hooks) echo "scripts/check-hooks.sh" ;;
        skills) echo "scripts/check-skills.sh" ;;
        deps) echo "scripts/check-deps.sh" ;;
        audit) echo "scripts/check-audit.sh" ;;
        commitlint) echo "scripts/check-commitlint.sh" ;;
        *) return 1 ;;
    esac
}

# Sensors declared for one hook in do-harness.toml, one name per line.
declared_sensors() {
    local hook="$1" line
    line="$(sed -n "s/^${hook} = \[\(.*\)\]\$/\1/p" "$CONFIG")"
    if [[ -z "$line" ]]; then
        echo "FAIL: ${CONFIG} declares no sensor list for the '${hook}' hook." >&2
        return 1
    fi
    printf '%s\n' "$line" | tr -d ' "' | tr ',' '\n' | sed '/^$/d'
}

# 1. Every hook file exists and is executable.
for hook in "${HOOKS[@]}"; do
    if [[ ! -f ".githooks/${hook}" ]]; then
        echo "FAIL: .githooks/${hook} is missing."
        FAIL=1
    elif [[ ! -x ".githooks/${hook}" ]]; then
        echo "FAIL: .githooks/${hook} is not executable (chmod +x)."
        FAIL=1
    fi
done

# 2. Each declared sensor is known here and really invoked by its hook.
for hook in pre-commit pre-push; do
    body="$(cat ".githooks/${hook}" 2>/dev/null || true)"
    for sensor in $(declared_sensors "$hook" || true); do
        needles="$(sensor_needles "$sensor")" || {
            echo "FAIL: sensor '${sensor}' is declared for the ${hook} hook but has no entry in scripts/check-hooks.sh."
            FAIL=1
            continue
        }
        found=0
        while IFS= read -r needle; do
            [[ -z "$needle" ]] && continue
            if [[ "$body" == *"$needle"* ]]; then
                found=1
                break
            fi
        done < <(printf '%s\n' "$needles" | tr '|' '\n')
        if (( found == 0 )); then
            echo "FAIL: the ${hook} hook does not invoke sensor '${sensor}' (expected one of: ${needles//|/, })."
            FAIL=1
        fi
    done
done

# 3. commit-msg is not a do-harness hook list entry: it must run commitlint.
if ! grep -q "scripts/check-commitlint.sh" ".githooks/commit-msg" 2>/dev/null; then
    echo "FAIL: .githooks/commit-msg does not run scripts/check-commitlint.sh."
    FAIL=1
fi

# 4. The two installation modes must not be combined, and core.hooksPath must
#    stay on .githooks. Skipped where there is no git directory (release
#    tarballs), which is the only case the invariant cannot apply to.
if git rev-parse --git-dir >/dev/null 2>&1; then
    configured="$(git config --get core.hooksPath || true)"
    installed=()
    for hook in "${HOOKS[@]}"; do
        if [[ -e ".git/hooks/${hook}" ]]; then
            installed+=("${hook}")
        fi
    done
    if [[ -n "$configured" && ${#installed[@]} -gt 0 ]]; then
        echo "FAIL: both hook modes are active — core.hooksPath=${configured} and .git/hooks/${installed[*]}. Pick one (AGENTS.md setup)."
        FAIL=1
    fi
    if [[ -n "$configured" && "$configured" != ".githooks" ]]; then
        echo "FAIL: core.hooksPath=${configured}; the repository hooks live in .githooks (git config core.hooksPath .githooks)."
        FAIL=1
    fi
    if [[ -z "$configured" && ${#installed[@]} -eq 0 && "${CI:-}" != "true" ]]; then
        echo "WARN: no git hooks active — run: git config core.hooksPath .githooks (or do-harness hook install)."
    fi
fi

if (( FAIL )); then
    echo "check-hooks FAILED."
    exit 1
fi

echo "check-hooks OK."
