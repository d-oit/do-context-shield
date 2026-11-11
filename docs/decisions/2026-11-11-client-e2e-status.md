# Client end-to-end verification status (2026-11-11)

This record preserves completed client-probe investigations moved from the active backlog. The remaining Claude Code approval-gated action is tracked in [`plans/backlog.md`](../../plans/backlog.md#external-blockers).

## Historical approval-gated probe

### Claude Code end-to-end check is manual and requires explicit human approval

- **Codex: verified (2026-10-30)**. With explicit human approval, Codex
  0.166.0 (`gpt-6-luna`, `codex doctor`: chatgpt auth, 21 ok / 0 fail) ran the
  non-interactive probe against a release binary built from `main`:
  `codex exec --json` with one-off `-c mcp_servers.do-context-shield.*`
  overrides called `context.inspect` and `context.sanitize` (session
  `codex-probe-1`) and replied with the sanitized placeholder only. The
  transcript is recorded in `docs/client-integration.md` → "Other clients",
  meeting the probe half of the exit criteria. The 2026-10-13 usage limit
  (`try again at Oct 15th, 2026 10:04 PM`) has expired.
- **Progress review (2026-10-13)**: `plans/tasks.json` reports 40 done, 0 pending, 0 in progress, and 0 failed. No implementation task remains open in the harness plan. The remaining client check is Claude Code: `-p` produced no output and died on timeout (exit 124), and its 1.0.44 attempt returned `401 Invalid Authentication`.
- **Progress review (2026-10-18)**: the 40-task plan was complete and its
  completed work now lives in the [backlog history](2026-11-11-backlog-history.md).
  The then-current `plans/tasks.json` snapshot carried five promoted follow-up
  tasks (mutation survivor triage, restore-scan bound, mutation re-dispatch,
  action pinning, glued-only approach verdict) plus the deps-sensor repair.
  The Codex usage-limit window (`until Oct 15th, 2026 10:04 PM`) has elapsed,
  and the probe was re-run with explicit approval on 2026-10-30 (verified
  above). Claude Code is unchanged (no output / `401 Invalid Authentication`).
- **Rule**: never invoke `claude` in an agent session without explicit human approval. Codex now works in this environment; its invocation remains approval-gated by `AGENTS.md`. Registration mechanics are verified and documented (`docs/client-integration.md` → "Other clients"); everything beyond that is human-driven.
- **Remaining work (human-run only)**: Claude Code — approve the project server once, then one non-interactive turn calling `context.inspect` + `context.sanitize` (session `cc-probe-1`) and a placeholder-only reply.
- **Exit criteria**: a Claude Code transcript proving the tool invocation and the sanitized reply, recorded here and in `docs/client-integration.md`.
