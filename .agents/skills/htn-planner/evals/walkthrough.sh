#!/usr/bin/env bash
# htn-planner walkthrough: proves the task workflow persists and exports state,
# hermetically inside the eval sandbox. plans/ is not mirrored, so this uses a
# method-less task (the catalog is validated repo-locally by check-skills.sh).
set -euo pipefail
root="${DO_HARNESS_ROOT:?DO_HARNESS_ROOT required}"
bin="${DO_HARNESS_BIN:-do-harness}"
cd "$root"

"$bin" --root "$root" task add htn-walkthrough-probe > "$root/htn_task.txt"
"$bin" --root "$root" task list --format json > "$root/htn_tasks.json"
grep -q 'htn-walkthrough-probe' "$root/htn_tasks.json"
"$bin" --root "$root" task export > /dev/null
[[ -f "$root/plans/tasks.json" ]]
grep -q 'htn-walkthrough-probe' "$root/plans/tasks.json"

printf 'task workflow: add/list/export persisted a task\n' > "$root/htn_receipt.txt"
