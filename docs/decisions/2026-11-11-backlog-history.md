# Completed backlog decisions and investigations (2026-11-11)

This dated archive preserves the completed entries removed from `plans/backlog.md` during issue #199. Original status dates, decisions, evidence, links, and exit criteria are retained. Active residual risks and external blockers remain in [`plans/backlog.md`](../../plans/backlog.md); detailed mutation and fuzz measurements are in [`mutation-fuzz-runs.md`](../test-evidence/mutation-fuzz-runs.md).

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

### crates.io publication and Trusted Publishing completed

- **Published (2026-11-09)**: all 18 workspace crates at `0.1.0` are on
  crates.io. The initial publish skipped 13 existing versions and published
  the remaining five: `do-context-shield-core`,
  `do-context-shield-plugin-process`, `do-context-shield-plugin-registry`,
  `do-context-shield-mcp-server`, and `do-context-shield`. A subsequent
  `scripts/publish-crates.sh --dry-run` confirmed all 18 versions.
- **Trusted Publishing configured (2026-11-09)**: all 18 crates have a GitHub
  Actions publisher for owner `d-oit`, repository `do-context-shield`, workflow
  file `release.yml`, with no environment. Each configuration was verified by
  crates.io API read-back.
- The release workflow grants `id-token: write` and uses
  `rust-lang/crates-io-auth-action`. Trusted Publishing-only enforcement was
  left disabled.
- **Published-artifact smoke added (2026-11-09)**: the release workflow now
  installs the exact tag version from crates.io into temporary Cargo and target
  directories, checks `--version` and `doctor`, then runs the existing
  zero-leak smoke against that installed binary. The local `v0.1.0` install
  smoke passed; `scripts/publish-crates.sh --dry-run` and `--needs-publish`
  confirmed all 18 versions are already published. An actual workflow rerun
  has not been dispatched because it would replace the existing GitHub release
  assets.

