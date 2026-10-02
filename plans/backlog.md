# Backlog

Deferred work, newest first. The do-harness task runtime
(`.do-harness/agent_state.db`, `do-harness task list`) is the live record; this
file is the durable, reviewable copy. Promote an item by giving it a task
(`do-harness task add "<title>" --method <name>`); remove its section when the
work lands or the precondition expires.

## Landed

### Jurisdiction pairing and purpose-conditional transfers

- **Status**: landed (harness task 34). The opt-in `matrix` policy
  (`crates/policy-matrix`, `plugins.policy = "matrix"` / `--policy matrix`,
  config `[policy_matrix]`) implements the decision this item deferred:
  adequacy is a **pair** decision (a destination is adequate only when it is
  the declared `origin` itself or a member of `adequate_jurisdictions`; an
  unset origin makes nothing adequate, so special-category data to a trusted
  recipient fails closed), and `purpose_rules` map an exact purpose (optionally
  filtered by data category and recipient) to `keep`/`pseudonymize`/`block` in
  declaration order. Secrets redact under every rule. The conservative
  `default` policy is unchanged.
- **Decision (recorded)**: the matrix deliberately does not hard-code a legal
  adequacy list; an operator declares their own `origin` and
  `adequate_jurisdictions`. A `[policy_matrix]` section under another policy is
  rejected at startup rather than silently ignored.
- **Exit criteria**: met — a documented matrix implemented as an opt-in policy
  plugin (never in the conservative default), with privacy-invariant tests
  covering secrets-always-redact, unknown-recipient, failed adequacy, the
  undeclared-origin cell, rule ordering, and the CLI/file selection surfaces.

## Blocked — approval-gated

### Client end-to-end checks are manual and require explicit human approval

- **Status**: 2026-09-19 — both CLIs are installed but unusable in this environment: Codex is account usage-limited (`try again at Oct 15th, 2026 10:04 PM`), Claude Code `-p` produces no output and dies on timeout (exit 124), and its 1.0.44 attempt returned `401 Invalid Authentication`.
- **Rule**: never invoke `claude` or `codex` in an agent session without explicit human approval. Registration mechanics are verified and documented (`docs/client-integration.md` → "Other clients"); everything beyond that is human-driven.
- **Remaining work (human-run only)**: Codex — one non-interactive turn calling `context.inspect` + `context.sanitize` (session `codex-probe-1`) and a placeholder-only reply. Claude Code — approve the project server once, then the same turn with session `cc-probe-1`.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply, recorded here and in `docs/client-integration.md`.
