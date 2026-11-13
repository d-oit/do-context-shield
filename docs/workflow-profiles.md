# Workflow profiles

Profile selection is deterministic over the complete changed-path set discovered by the security-regression gate, including both sides of renames and untracked files. Mixed changes use the strictest profile: `security-critical` > `feature` > `quick-fix`. The gate prints the selected profile and reason. The executable sensor argv remains exclusively in `do-harness.toml`; profiles refer only to named signal sets.

| Profile | Eligibility and recon | Planning | Tests and signal set | Evidence |
|---|---|---|---|---|
| `quick-fix` | Only the explicit `safe_paths` entries in `plans/security-regression-map.json` (root README, CHANGELOG, LICENSE, and `docs/`). Read the changed files and relevant project guidance. | One direct low-risk task; split only if scope grows. | Strict changed-only run of `quick-fix`; the set includes formatting, lint, tests, backlog validation for changes under `docs/decisions/` and `docs/test-evidence/`, and the always-on `security-regression` gate. | Retain the strict sensor result and inspect `do-harness status --set quick-fix`. |
| `feature` | Only mapped, explicitly allowlisted feature path rules that do not overlap a security-component directory or workspace-critical path. Read the path rule, its consumers, and matching focused guidance. | Decompose multi-step work using the repository method catalog and record the task and sensor gate. | Strict changed-only run of `feature`; it selects applicable dependent sensors and keeps `security-regression` always on. | Retain strict sensor results and inspect `do-harness status --set feature`. |
| `security-critical` | Security component directories (including shared API), workspace/member manifests, fuzz workspace, global/harness/workflow files, malformed or unsafe paths, ambiguous classifications, and every unmapped or unknown path. Read relevant contracts, skills, invariants, and affected consumers. | Define the contract and regression tests first; decompose cross-boundary work and preserve fail-closed behavior. | Strict, unfiltered full run of `security-critical`. | Retain full strict verification results and inspect `do-harness status --set security-critical`. |

## Commands

Preview quick-fix and feature selection with `do-harness explain --set <profile> --changed`; preview security-critical's full set without `--changed`. Use the strict profile invocation documented in `plans/security-regression-map.json` for verification. The security-regression sensor remains in all profile sets.

## Manual escalation

Escalate manually to `security-critical` whenever classification is uncertain, a path is not explicitly eligible for `quick-fix` or `feature`, or a change may affect a security boundary. Unknown, malformed, ambiguous, global, workspace, harness, shared-API, or security-component changes cannot be downgraded by a low-risk file in the same change set. If the profile metadata or sensor selection cannot be loaded or reconciled, the gate fails closed to full verification.
