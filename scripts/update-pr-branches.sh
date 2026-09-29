#!/usr/bin/env bash
# update-pr-branches.sh — rebase every open PR whose head is behind `main`.
#
# `main` accepts pull requests only and requires the `CI Success` check on an
# up-to-date branch. The check is bound to the PR's merge commit, so every
# merge to `main` invalidates the checks of every other open PR, and GitHub
# auto-merge never updates the head branch itself — a `BEHIND` PR waits
# forever instead of draining. Run this before merging and again after each
# merge; merge one PR per round (`AGENTS.md` → "Pull-request merges").
#
# Usage: scripts/update-pr-branches.sh [--dry-run]

set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "gh is required to update pull-request branches" >&2
    exit 2
fi

behind=0
rebased=0
for number in $(gh pr list --state open --limit 100 --json number --jq '.[].number'); do
    state="$(gh pr view "$number" --json mergeStateStatus --jq .mergeStateStatus)"
    if [ "$state" != "BEHIND" ]; then
        continue
    fi
    behind=$((behind + 1))
    if ((DRY_RUN)); then
        printf 'would rebase PR %s\n' "$number"
        continue
    fi
    if gh pr update-branch "$number" --rebase >/dev/null 2>&1; then
        printf 'rebased PR %s\n' "$number"
        rebased=$((rebased + 1))
    else
        printf 'CONFLICT: PR %s needs a local rebase (resolve by hand)\n' "$number" >&2
    fi
done

printf 'behind=%d rebased=%d\n' "$behind" "$rebased"
