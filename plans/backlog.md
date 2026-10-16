# Backlog

Deferred work, newest first. The do-harness task runtime
(`.do-harness/agent_state.db`, `do-harness task list`) is the live record; this
file is the durable, reviewable copy. Promote an item by giving it a task
(`do-harness task add "<title>" --method <name>`); remove its section when the
work lands or the precondition expires.

## Open defect

### Credential word-boundary miss: secrets glued to letters or digits leak raw

- **Status**: open. Found by the `fuzz_sanitize_pipeline` target (PR #126 smoke run, two crashing inputs). Deferred to a separate PR by maintainer decision on 2026-10-16; the fuzz target stays in the seed test and is excluded from the scheduled matrix in `.github/workflows/fuzz.yml` until this lands.
- **Defect**: credential patterns anchor with `\b`, so a secret directly followed by a letter or digit is not matched at all, and its raw value survives `sanitize`. Replayed against `RegexDetector` (`crates/detector-regex`):
  - `AIzaSYNTHETIC0123456789012345678901234_` alone → detected (`google_api_key`, 0..39)
  - `AIzaSYNTHETIC0123456789012345678901234_dabc` → **no entities**
  - `AIzaSYNTHETIC0123456789012345678901234_12345` → **no entities**
  - `AIzaSYNTHETIC012345678901234567890123Xdabc` → **no entities**
  - `x AIzaSYNTHETIC0123456789012345678901234_ d` → detected (word-separated)
- **Scope**: the credential family anchored by `\b` (`google_api_key`, `api_key`, `anthropic_key`, and similar), not only the seed corpus. The documented contract (`docs/plugins.md`, credential span rule) says a value ends at its declared alphabet, so the glued case is a miss, not an intended boundary.
- **Exit criteria**: a detector fix with exact-span regression tests for the glued cases above; `cargo test --manifest-path fuzz/Cargo.toml --locked` green; `fuzz_sanitize_pipeline` re-added to the `fuzz.yml` matrix; the quality benchmark still passes with its existing boundary cases. The invariant in `fuzz_sanitize_pipeline.rs` is not weakened.

## Landed

### Harness tasks 35–40: developer, cloud, and generic credential shapes

- **Status**: landed (harness tasks 35–40). Covered: database connection URIs with
  credentials (`db_credential`), fine-grained GitHub PATs (`github_pat_`), a
  trailing-hyphen secret miss fix, Google API key underscore boundary repair,
  routable and versioned GitLab PATs (`glpat-`), and quoted generic secret
  assignments (`password="xyz"`).
- **Exit criteria**: met — each shape has a detector test in
  `crates/detector-regex/src/tests/credentials.rs` and redaction is enforced by
  `is_secret_kind` in `crates/plugin-api`.

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

### Modern 2026 developer and cloud credentials

- **Status**: detection landed for Anthropic (`anthropic_key`, `sk-ant-api03-` /
  `sk-ant-admin01-`), OpenAI project and service-account keys
  (`openai_project_key`, `sk-proj-` / `sk-svcacct-`), and Azure storage
  connection strings (`azure_storage_credential`). Each is classified as a
  secret by `is_secret_kind`.
- **Boundary coverage**: verified in the quality corpus with exact-span cases
  for Anthropic and OpenAI payloads ending in `-`/`_` (including the admin and
  service-account prefixes), and Azure account-key `==` padding.

### MCP 2026-07-28 tool annotations and cache hints

- **Status**: annotations landed. `tools/list` uses schema-defined
  `ToolAnnotations`: `context.inspect` is read-only; `context.sanitize` and
  `context.restore` are non-read-only but non-destructive; `context.forget` is
  destructive; every tool has `openWorldHint: false`. These are untrusted
  hints, not enforcement. The existing list response retains `ttlMs: 300000`
  and `cacheScope: "private"`.
- **Protocol metadata**: missing or malformed `clientCapabilities` under an
  explicitly supported namespaced version remains `-32602` (invalid params);
  `-32021` is reserved for a required capability the client did not declare.
  Requests without namespaced version metadata retain legacy behavior.
- **Exit criteria**: met for tool annotations — `cargo test -p
  do-context-shield-mcp-server` covers all four tools' hints. No new wire error
  change is needed; `protocol_version_metadata_is_enforced` covers the
  spec-correct invalid-params response.

### Egress canary token verification

- **Status**: landed. `sanitize --canary-key-file <path>` appends
  `<!-- do-context-shield-canary: <hex> -->`, an HMAC-SHA256 tag over the
  domain-separated session scope (`crates/privacy-core/src/canary.rs`).
  `verify-canary --session <id> --canary-key-file <path>` checks stdin and exits
  non-zero on a missing, forged, or wrong-session marker. The canary key is a
  separate per-install file (owner-only on Unix), not the vault key.
- **Decision (recorded)**: per-install key file over a scope-only vault token,
  so an external egress proxy can verify the marker without vault access.
- **Exit criteria**: met — canary unit tests, CLI suites, a binary smoke test
  (same-session ok; wrong session, unmarked text, and loose key permissions
  fail), and the verification gate.

## Blocked — approval-gated

### Client end-to-end checks are manual and require explicit human approval

- **Progress review (2026-10-13)**: `plans/tasks.json` reports 40 done, 0 pending, 0 in progress, and 0 failed. No implementation task remains open in the harness plan. These client checks are still outstanding: Codex is account usage-limited (`try again at Oct 15th, 2026 10:04 PM`), Claude Code `-p` produced no output and died on timeout (exit 124), and its 1.0.44 attempt returned `401 Invalid Authentication`.
- **Rule**: never invoke `claude` or `codex` in an agent session without explicit human approval. Registration mechanics are verified and documented (`docs/client-integration.md` → "Other clients"); everything beyond that is human-driven.
- **Remaining work (human-run only)**: Codex — one non-interactive turn calling `context.inspect` + `context.sanitize` (session `codex-probe-1`) and a placeholder-only reply. Claude Code — approve the project server once, then the same turn with session `cc-probe-1`.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply, recorded here and in `docs/client-integration.md`.
