# Backlog

Deferred work, newest first. The do-harness task runtime
(`.do-harness/agent_state.db`, `do-harness task list`) is the live record; this
file is the durable, reviewable copy. Promote an item by giving it a task
(`do-harness task add "<title>" --method <name>`); remove its section when the
work lands or the precondition expires.

## Landed

### deps sensor broken by a CVSS 4.0 advisory: repaired

- **Status**: landed 2026-10-18 (harness task, `workflow-improvement`). The
  `deps` sensor failed at advisory-database load: the rustsec parser in
  cargo-deny 0.18.5 rejects the `CVSS:4.0/...` string in the newly published
  `RUSTSEC-2026-0146` advisory (upstream: EmbarkStudios/cargo-deny#804,
  fixed by #805 bumping rustsec to 0.31; the CVSS-4.0-capable line starts at
  0.18.9 and current is 0.20.2).
- **Correction**: the original entry's claim that CI would fail on the next
  pull request was wrong — `ci.yml` pins
  `EmbarkStudios/cargo-deny-action@v2.1.1`, whose Dockerfile bundles
  `deny_version="0.20.2"`, so only local tools were affected.
- **Resolution**: local cargo-deny upgraded to the official 0.20.2 release
  binary (sha256-verified against the published asset);
  `bash scripts/check-deps.sh` is green again ("advisories ok, bans ok,
  licenses ok, sources ok").

### GitHub Actions pinned to immutable commits across all workflows

- **Status**: landed 2026-10-18 (harness task, `workflow-improvement`). The
  six floating `uses:` refs now pin the commit SHA their tag resolves to,
  versions kept as comments: `commitlint.yml`
  (`amannn/action-semantic-pull-request@48f25628… # v6.1.1`), `labeler.yml`
  (`actions/labeler@bf12e9b0… # v7.0.0`), `release-drafter.yml`
  (`release-drafter/release-drafter@978bb0b3… # v7.10.0`, twice),
  `secret-scan.yml` (`actions/checkout@fbc6f399… # v5.1.0`, matching the
  existing `ci.yml` pin, and `gitleaks/gitleaks-action@e0c47f4f… # v3.0.0`).
- **Enforcement**: `scripts/validate-structure.py` now rejects any `uses:`
  ref that is not `owner/repo@<40-hex sha>` (local `./` and `docker://` refs
  exempt) — verified both ways, a planted `@v7` tag fails it — and the rule
  is recorded in `plans/invariants.json`.

### Credential word-boundary miss: fail closed instead of leaking a surviving copy

- **Status**: landed. Found by the `fuzz_sanitize_pipeline` target (two crashing inputs in PR #126), fixed by enforcing the plan's postcondition centrally rather than reworking detector boundaries.
- **Decision (recorded)**: `PrivacyPipeline::sanitize` now rejects transformed text that still contains a value the plan removes (`crates/privacy-core/src/plan.rs`), mirroring the check `plugin-process` already applied to its own transformer output. Failing closed was chosen over relaxing the `\b` anchors: dropping the left anchor for weak prefixes (`sk-`, `hf_`, `xox…`) would redact ordinary text such as `disk-usage-of-the-container`, and the `regex` crate has no lookaround, so a "real but glued" token cannot be distinguished from one inside a longer word. The exact-width boundary controls are unchanged.
- **Hardened after review**: the postcondition is only as good as the plan it reads, so the plan's decision values are now validated against the detected entities (a substituted value used to be checked instead of the real one), and the `Keep` exemption was removed — a detector labelling one secret under both a secret and a non-secret kind made the default policy redact one span and keep the other, returning the raw value for a local recipient. Both bypasses carried failing-before regressions.
- **Residual (documented)**: a *glued-only* occurrence — a secret that never appears at a detectable boundary anywhere in the input — is still missed by the detector, and with no detected value there is nothing for the postcondition to check. Closing that gap needs a lookaround-capable engine or a broader credential pattern, both larger changes with their own false-positive review.
- **Exit criteria**: met — five regressions in `crates/privacy-core/src/tests/redaction.rs` (glued duplicate of a redacted key, duplicate glued after a digit, undetected copy of a pseudonymized value, kept-value control, keep-alias refusal) plus the substituted-value regression in `crates/privacy-core/src/tests/policy.rs`, a committed seed (`fuzz/corpus/fuzz_sanitize_pipeline/glued_duplicate.txt`) asserted to fail closed by `fuzz/tests/seed_corpus.rs`, `fuzz_sanitize_pipeline` back in the `fuzz.yml` matrix, and a 45k-run local fuzz confirmation.

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

## Open

### Glued-only secret detection gap: approach verdict before any slice

- **Status**: open (promoted to a harness task, `decision`). This is the
  documented residual of the redaction-postcondition item under **Landed**: a
  secret that never appears at a detectable boundary anywhere in the input is
  still missed, and with no detected value the postcondition has nothing to
  check.
- **Next**: record the verdict on closing it — a lookaround-capable regex
  engine (the `regex` crate has none) versus broader credential patterns —
  with the false-positive review each option implies, then slice only the
  winning option.

### Mutation-run findings: 31 survivors, 2 restore timeouts

- **Measured** (manual dispatch 39012269650, 2026-10-17; workspace test scope, 8 shards): 511 mutants in ~16 minutes wall clock (8–16 minutes per shard) on two cores — 417 caught, 31 missed, 61 unviable, 2 timeouts. The earlier package-scoped dispatch (39009589543) reported 62 missed; **31 of those 62 are caught under the workspace scope and no mutant became newly missed**, so the drop is a measurement correction, not new tests. Reports: `gh run download --pattern 'mutants-report-shard-*'`.
- **Scope correction (why the old list was inflated)**: cargo-mutants' default (`TestPackages::Mutated`) runs only the mutated package's own tests, so behavior a consumer crate asserts was invisible. `plugin-api` contracts dominated the old list (17 `traits.rs` + 15 `context.rs` survivors) because `privacy-core`, the CLI, and the MCP server hold that coverage — the five `validate_judgments` mutants were the clearest case (`traits.rs` now shows 1 survivor, `context.rs` 2). The workflow passes `--test-workspace true`.
- **Timeouts**: two `+`-operator mutants in `PrivacyPipeline::restore` (`crates/privacy-core/src/lib.rs:221` and `:240`) still hang the suite — no test bounds the placeholder scan. The third (`:221` `+`→`-`) is now caught.
- **Survivor classification (31)** — two proven equivalents and 25 pending semantic triage after the safety-batch triage below (equivalence / defensive-only / real gap) before any of them becomes a test worklist. The equivalent: `detector-regex`'s `luhn_valid` `>`→`>=` cannot be killed — the comparison only sees `digit *= 2` output, every doubled digit is even, and `> 9` and `>= 9` differ exactly at 9 (unreachable) — so `.cargo/mutants.toml` excludes it with that proof. The rest, by area: `plugin-api` (12) `Action::as_str` (2), `SemanticLabel::parse`'s `secret` arm, `placeholder.rs`'s minted-token guards (3), `spans.rs`'s `resolve_overlaps` bounds (2), `DataCategory::parse` arms (2), `audit.rs` `unix_now` (2); `vault-json` (6) `Lock::acquire`/`Drop`, `is_envelope`, `decode_hex`, `persist_locked`, `restrict_permissions`; `vault-memory` (6) the counter arithmetic and `expire`'s bounds and result; `privacy-core` (4) `expire_vault`, `canary::decode_hex`, and the two `validate_plan` disjunctions; `detector-regex` (1) `iban_valid`'s `%`; `transformer-mask` (1) one bound. **This list is neither "all gaps" nor plumbing**: the `validate_plan` pair guards the kind/span/end equality that makes the redaction postcondition trustworthy (`crates/privacy-core/src/lib.rs:397-399`), and `canary`/`vault-json` `decode_hex` and `is_envelope` validate marker and envelope input, so a survivor there is a real gap until shown equivalent; `Action::as_str` and `audit.rs` `unix_now` were guessed to be defensive-only/no-observable-difference — the triage below disproved that. The per-shard `missed.txt` files carry the exact diffs.
- **Progress (2026-10-18)**: the workflow fixes are landed (#136 treats
  mutant test timeouts as a signal, #137 tests every mutant against the whole
  workspace, #138 excludes the proven-equivalent `luhn_valid` mutant and
  reclassifies the survivors) and are already folded into the numbers above;
  the scheduled Fuzz run of 2026-10-18 is green, so the fuzz runtime fixes
  hold. The next steps below are promoted to harness tasks and snapshotted in
  `plans/tasks.json` (the state database was reset, so task ids restart; the
  titles are the stable handle).
- **Triage progress (2026-10-18, safety batch)**: five of the 30 resolved,
  each with a kill proof (mutation applied by hand, test observed failing for
  the right reason, mutation reverted). `validate_plan`'s two `||`→`&&`
  mutants were **real gaps**: nothing asserted that a mismatched kind
  (`substituted_kind_fails_closed`) or a mismatched span
  (`substituted_span_fails_closed`) fails closed. `canary::decode_hex`'s
  `||`→`&&` was a **real gap**: the width guard was untested, so a wrong-width
  payload sliced out of bounds instead of failing closed
  (`decode_hex_requires_the_exact_tag_width`,
  `wrong_width_marker_payload_fails_closed`). `is_envelope`'s `&&`→`||` was a
  **test gap**: both load paths already fail closed on a half-envelope, but
  the input class was untested and the error text diverges
  (`envelope_detection_requires_both_markers`). Vault-json `decode_hex`'s
  `|`→`^` is the **second proven equivalent** (`nibble << 4` and a hex digit
  never share a set bit), excluded in `.cargo/mutants.toml` with that proof.
  Expected survivors at re-dispatch drop from 30 to 25.
- **Triage progress (2026-10-18, second batch)**: the "defensive-only"
  candidates turned out to be plain test gaps — all four die to new contract
  tests, each kill-proven by hand like the first batch. `Action::as_str`'s
  two body-replacement mutants (`""`, `"xyzzy"`) are killed by
  `action_names_match_the_documented_wire_contract` (the lowercase names are
  the process-protocol and audit-log wire surface that `plugin-process`'s
  `parse_action` accepts), and `unix_now`'s two constant mutants (`0`, `1`)
  are killed by `audit_events_are_stamped_with_the_wall_clock` (a fixed past
  bound is not flaky because the clock only moves forward).
- **Placeholder scan bound (landed)**: `PrivacyPipeline::restore`'s scan now
  carries an explicit pass budget (`input.len() + 1`, one byte of progress
  per pass) and fails closed with a typed error when the cursor stops
  advancing. The two hanging `+`→`*` mutants (`lib.rs:221`, `:240`) go from
  hanging the suite to dying fast on the existing restore tests
  (`placeholder scan stopped making progress`), and
  `restore_scan_budget_covers_heavy_rescanning_without_dropping_late_tokens`
  pins the budget sizing (200 malformed prefixes before a real token must not
  false-trip it). Expected survivors at re-dispatch drop from 30 to 21.
- **Next**: triage the remaining 21 by area — `SemanticLabel::parse`'s
  `secret` arm, `DataCategory::parse`'s arms, `placeholder.rs`'s minted-token
  guards, `spans.rs`'s `resolve_overlaps` bounds, then the vault-json
  `Lock`/`persist_locked`/`restrict_permissions`, vault-memory counter and
  `expire` arithmetic, `expire_vault`, `iban_valid`'s `%`, and
  `transformer-mask`'s bound — then re-dispatch and expect ~21 survivors
  instead of 31. A raw mutation score is not proof of security.

## Blocked — approval-gated

### Client end-to-end checks are manual and require explicit human approval

- **Progress review (2026-10-13)**: `plans/tasks.json` reports 40 done, 0 pending, 0 in progress, and 0 failed. No implementation task remains open in the harness plan. These client checks are still outstanding: Codex is account usage-limited (`try again at Oct 15th, 2026 10:04 PM`), Claude Code `-p` produced no output and died on timeout (exit 124), and its 1.0.44 attempt returned `401 Invalid Authentication`.
- **Progress review (2026-10-18)**: the 40-task plan is complete and its
  history lives in the **Landed** sections above; the harness state database
  has been reset since, and the re-exported `plans/tasks.json` now carries the
  five promoted follow-up tasks (mutation survivor triage, restore-scan
  bound, mutation re-dispatch, action pinning, glued-only approach verdict)
  plus the deps-sensor repair tracked under **Open**.
  The Codex usage-limit window (`until Oct 15th, 2026 10:04 PM`) has elapsed,
  so the Codex probe can be re-run — still only with explicit human approval.
  Claude Code is unchanged (no output / `401 Invalid Authentication`).
- **Rule**: never invoke `claude` or `codex` in an agent session without explicit human approval. Registration mechanics are verified and documented (`docs/client-integration.md` → "Other clients"); everything beyond that is human-driven.
- **Remaining work (human-run only)**: Codex — one non-interactive turn calling `context.inspect` + `context.sanitize` (session `codex-probe-1`) and a placeholder-only reply. Claude Code — approve the project server once, then the same turn with session `cc-probe-1`.
- **Exit criteria**: a transcript proving the tool invocation and the sanitized reply, recorded here and in `docs/client-integration.md`.
