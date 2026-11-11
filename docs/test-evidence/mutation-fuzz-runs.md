# Mutation and fuzz test evidence

Detailed run measurements and triage notes moved from `plans/backlog.md` under issue #199. A mutation score is not proof of security. The current glued-only detection residual remains listed in [`plans/backlog.md`](../../plans/backlog.md#residual-risks).

## Historical mutation runs

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
- **Local measurement (2026-10-18, package-scoped, NOT CI-comparable)**: a
  local `cargo mutants -p <crate>` run per package on the windows-gnu host
  toolchain. Before this batch: plugin-api 24 missed / 73 caught, vault-json
  8 / 91, vault-memory 1 / 28, transformer-mask 0 / 17, privacy-core 4 / 78.
  After the kill batch: plugin-api 0 / 97 (all killed), vault-json 6 / 93,
  vault-memory 1 / 28, transformer-mask 0 / 17, privacy-core 0 / 78 (its 4
  restore-budget mutants are now excluded with a proof in
  `.cargo/mutants.toml`). The vault-json permission mutants are `#[cfg(unix)]`
  and were not verified on this Windows host; CI's Linux run is the authority
  for them. These runs omitted `--test-workspace true`, so they overcount
  relative to CI (the scope correction above). Survivors flagged here that the CI sample
  did not list include `context.rs` `RecipientClass::parse` arms and
  `is_valid_jurisdiction`, `traits.rs` `Vault` default methods and
  `validate_judgments`, `vault-json` `next_counter` and `check_key_file_permissions`,
  and `privacy-core` `restore`'s `+`/`-=` arithmetic (the two lines that
  previously hung). The `--file` filter matched nothing on Windows paths, so
  per-package runs are the working route. `vault-memory` `expire`'s `<`→`<=`
  is a real exact-boundary gap, not an equivalent: it needs an injected clock
  to test, so it stays a survivor.
- **Triage progress (2026-10-20, third batch, package-scoped, NOT
  CI-comparable)**: three more resolved on the windows-gnu host toolchain,
  each kill-proven by hand (mutation applied, test observed failing, mutation
  reverted). `vault-memory` `expire`'s `<`→`<=` was a **real exact-boundary
  gap**: wall-clock tests can never hit `elapsed == ttl`, so the predicate
  is now the pure `MemoryVault::live(ttl, elapsed)` shared by `expired` and
  `expire`, with `ttl_boundary_is_already_expired` pinning the tie directly
  (vault-memory goes 1 missed → 0; 34 mutants, 31 caught, 3 unviable).
  `vault-json` `persist_locked`'s `delete !` was a **test gap masked by the
  lock**: every public caller holds the exclusive lock, which already creates
  the parents, so `persist_locked_creates_missing_parents_without_a_lock`
  calls it directly on a nested path (mutant observed failing).
  `detector-regex` `iban_valid`'s `%`→`+` (letter branch) is the **third
  proven equivalent**: adding 97 (≡ 0 mod 97) before later `% 97` steps that
  multiply the carry by 10/100 leaves the final `== 1` unchanged — verified
  by hand plus brute force over DE/GB/FR/ES/IT/NL valid IBANs — excluded in
  `.cargo/mutants.toml` with that proof. Remaining local survivors are the
  Unix-only permission checks (`restrict_permissions`,
  `check_key_file_permissions` ×3) plus `Lock`/`persist_locked` overlap that
  CI's Linux run arbitrates; `privacy-core` is 0 missed locally (97 mutants,
  78 caught, 19 unviable) and `transformer-mask` stays 0.
- **Re-dispatch (2026-10-20, run 39475097084 on the triage branch): 0 missed,
  0 timeouts across all 8 shards** (449 caught, 61 unviable) against the
  31/2 baseline of dispatch 39012269650. The Unix-only permission mutants
  are covered by the existing Linux tests once the workspace scope is used.
  A raw mutation score is not proof of security.

