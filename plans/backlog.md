# Backlog

Only active work, external or approval blockers, and documented residual risks belong here. Every item has machine-checked status metadata. Completed investigations and decisions live in `docs/decisions/`; detailed mutation and fuzz measurements live in `docs/test-evidence/`.

The do-harness task runtime (`.do-harness/agent_state.db`, `do-harness task list`) is the live task record; `plans/tasks.json` is its exported snapshot, not the active backlog. Promote actionable work with `do-harness task add "<title>" --method <name>`. Do not keep completed work in this file.

## External blockers

### Issue #188: approval to rerun the release workflow

- **Status**: blocked
- **Blocker**: maintainer approval is required before rerunning the `v0.1.0` release workflow because it would replace existing GitHub release assets. All 18 crates are published and trusted publishing is configured, but the live release-workflow rerun remains unverified.
- **Next action**: obtain explicit maintainer approval for the live rerun, then perform the documented release verification; keep this blocker until the workflow completes successfully.
- **References**: [issue #188](https://github.com/d-oit/do-context-shield/issues/188), [publication history](../docs/decisions/2026-11-11-backlog-history.md).

### Claude Code end-to-end client probe

- **Status**: blocked
- **Blocker**: the recorded Claude Code attempts produced no output or returned `401 Invalid Authentication`; further CLI invocation requires explicit human approval. Agents must not invoke it without that approval.
- **Next action**: with approval, run one non-interactive turn calling `context.inspect` and `context.sanitize`, verify the reply contains only the sanitized placeholder, and update `docs/client-integration.md`.
- **References**: [historical client-probe record](../docs/decisions/2026-11-11-client-e2e-status.md), `AGENTS.md`.

## Residual risks

### Glued-only secret occurrences can evade detection

- **Status**: residual-risk
- **Risk**: a credential occurrence that never matches a detector boundary can remain raw; the central redaction postcondition cannot check a value that was never detected. This is an explicit limitation, not an implementation task under the current hold decision.
- **Evidence**: the 2026-10-20 workspace mutation re-dispatch recorded zero missed mutants, but mutation scores do not prove security and do not resolve this residual. See the [decision record](../docs/decisions/2026-10-20-glued-only-secret-detection.md) and [mutation/fuzz evidence](../docs/test-evidence/mutation-fuzz-runs.md).
