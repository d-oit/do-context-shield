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

### Format-preserving, generalize, and mask transformers

- **Status**: `transformer-pseudonymize` is the only transformer, and it also
  carries the `Redact` path. Generalize (kind-only, non-restorable output) and
  mask (partial reveal) are new user-visible behaviors, not a code gap.
- **Decision needed**: the generalize token shape (for example a kind-only
  `__DO_PRIVATE_<KIND>__` that `restore` must leave untouched) and the masking
  policy per kind (how many characters stay visible, and in which positions).
- **Exit criteria**: transformer implementation(s) registered in
  `plugin-registry` with CLI/config names, `restore` proven to be a no-op on
  their output, and unit + CLI integration tests. Collapsing equal values must
  not silently break the stable-identity guarantee pseudonymization keeps.

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

### Jurisdiction- and purpose-aware default policy

- **Status**: `ProcessingContext.purpose` and `.jurisdiction` are carried
  through every adapter and ignored by `DefaultPolicy`, which reads only the
  recipient class and data category.
- **Decision needed**: the decision tree itself (which jurisdiction pairs
  block special-category data, whether an unknown jurisdiction fails closed,
  and which purposes permit pseudonymized transfer).
- **Exit criteria**: a documented matrix implemented in `DefaultPolicy` (or a
  new policy plugin), with privacy-invariant tests covering every cell.

### `Action::Review` human-review flow

- **Status**: `Action::Review` fails the pipeline exactly like `Block`
  (`PipelineError::Policy`), so it is a reserved action with no flow behind it.
- **Decision needed**: where review happens (CLI queue, MCP sidecar,
  harness-side hook), who approves, what text continues after approval, and
  the timeout/failure behavior.
- **Exit criteria**: a documented, testable flow — or removal of the action
  from the public enum if review belongs outside the boundary.

### `JsonVault` at-rest encryption and expiry

- **Status**: the JSON vault persists raw originals in plaintext with
  owner-only file permissions; the TTL applies to the memory vault only.
- **Decision needed**: key source and management (OS keychain or passphrase;
  hosted KMS stays out per provider-agnosticism), format versioning and the
  migration path for existing files, and on-disk TTL semantics (lazy purge vs
  eager rewrite).
- **Exit criteria**: an encrypted format with a migration path, documented
  and tested TTL behavior, and no raw value recoverable from the file alone.

## Blocked — approval-gated

### Client end-to-end checks are manual and require explicit human approval

- **Status**: 2026-09-19 — both CLIs are installed but unusable in this environment: Codex is account usage-limited (`try again at Oct 15th, 2026 10:04 PM`), Claude Code `-p` produces no output and dies on timeout (exit 124), and its 1.0.44 attempt returned `401 Invalid Authentication`.
- **Rule**: never invoke `claude` or `codex` in an agent session without explicit human approval. Registration mechanics are verified and documented (`docs/client-integration.md` → "Other clients"); everything beyond that is human-driven.
- **Remaining work (human-run only)**: Codex — one non-interactive turn calling `context.inspect` + `context.sanitize` (session `codex-probe-1`) and a placeholder-only reply. Claude Code — approve the project server once, then the same turn with session `cc-probe-1`.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply, recorded here and in `docs/client-integration.md`.
