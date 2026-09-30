# Backlog

Deferred work, newest first. The do-harness task runtime
(`.do-harness/agent_state.db`, `do-harness task list`) is the live record; this
file is the durable, reviewable copy. Promote an item by giving it a task
(`do-harness task add "<title>" --method <name>`); remove its section when the
work lands or the precondition expires.

## Deferred — needs a design decision

Recorded 2026-09-29 from the gap-analysis hardening pass (harness task 24).
Each item was explicitly out of scope there and needs a product or
architecture decision before code.

### Audit trail for transform mappings

- **Status**: mappings live only inside the session-scoped vault; nothing
  records what was transformed. An audit trail is itself sensitive (it would
  hold raw originals or reversible references), so it needs a design.
- **Decision needed**: sink (local file, process plugin, vault extension),
  retention/rotation, who may read it, and how it stays scope-isolated and
  redaction-safe.
- **Exit criteria**: an audit surface behind `plugin-api` with scope
  isolation, secret redaction, and tests proving no raw value leaks outside
  the boundary.

### Jurisdiction pairing and purpose-conditional transfers

- **Status**: the conservative default landed — an unset jurisdiction fails
  closed for special-category data to non-local recipients, and `purpose` is
  documented and tested as forwarded intent that cannot loosen a decision.
  What remains is the legal/product matrix the default deliberately does not
  guess.
- **Decision needed**: which jurisdiction pairs may receive special-category
  data (adequacy mappings), and which purposes, if any, permit a looser action.
- **Exit criteria**: a documented matrix implemented as a new opt-in policy
  plugin (never in the conservative default), with privacy-invariant tests
  covering every cell.

## Blocked — approval-gated

### Client end-to-end checks are manual and require explicit human approval

- **Status**: 2026-09-19 — both CLIs are installed but unusable in this environment: Codex is account usage-limited (`try again at Oct 15th, 2026 10:04 PM`), Claude Code `-p` produces no output and dies on timeout (exit 124), and its 1.0.44 attempt returned `401 Invalid Authentication`.
- **Rule**: never invoke `claude` or `codex` in an agent session without explicit human approval. Registration mechanics are verified and documented (`docs/client-integration.md` → "Other clients"); everything beyond that is human-driven.
- **Remaining work (human-run only)**: Codex — one non-interactive turn calling `context.inspect` + `context.sanitize` (session `codex-probe-1`) and a placeholder-only reply. Claude Code — approve the project server once, then the same turn with session `cc-probe-1`.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply, recorded here and in `docs/client-integration.md`.
