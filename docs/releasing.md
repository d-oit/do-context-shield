# Release Contract and Automation

This document defines the release distribution contract, release verification rules, and automated workflows for `do-context-shield`.

## Distribution Channels

`do-context-shield` explicitly supports two primary release distribution paths:

1. **crates.io**:
   - Source-based installation via `cargo install do-context-shield`.
   - All 18 workspace crates published bottom-up in topological dependency order.
   - Idempotent publish workflow skips already-published versions.

2. **GitHub Release Binaries**:
   - Pre-compiled executable archives attached to version tags (`v*.*.*`).
   - Supported platform targets:
     - `x86_64-unknown-linux-gnu`
     - `x86_64-apple-darwin`
     - `aarch64-apple-darwin`
     - `x86_64-pc-windows-msvc`
   - Every release includes a verified `SHA256SUMS` file.

*Note: Operating system package managers (Homebrew, apt, etc.) are planned distribution channels and not currently active.*

## Release Preflight Verification

Before publication, the release automation enforces preflight verification (`scripts/check-release-preflight.sh`):

- **Tag Matching**: The tag version (e.g. `v0.1.0`) must match `[workspace.package].version` in `Cargo.toml`.
- **Workspace Version Agreement**: Every workspace crate under `crates/` must share the exact workspace package version.
- **Metadata Completeness**: Every published crate manifest must contain `description`, `license`, and `repository`.
- **Topological Order**: `scripts/publish-crates.sh` must maintain a complete and topologically valid publishing order (`scripts/check-publish-order.sh`).
- **Package Surface Hygiene**: Every workspace crate must satisfy `cargo package --list` without error.

## Release Smoke Testing

Release candidate binaries are tested before publishing assets (`scripts/smoke-test-release.sh`):

1. Binary execution and `--version` output.
2. `inspect` processing with synthetic sensitive data.
3. `sanitize` with session scoping and local vault.
4. **Zero-Leak Assertion**: Verifies that raw sensitive input values are never written to stdout, stderr, or log outputs during sanitization.
5. `restore` functionality from vault file.
6. `mcp-stdio` JSON-RPC tool calls over stdio.

## Triggering a Release

Releases are boundary-gated and maintainer-reviewed:

1. Merge approved PRs into `main`. Release Drafter automatically updates draft release notes.
2. Push a version tag matching the workspace package version:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
3. The `.github/workflows/release.yml` workflow executes:
   - Runs `check-release-preflight.sh v0.1.0`.
   - Compiles release binaries across supported platforms.
   - Executes `smoke-test-release.sh` against compiled binaries.
   - Uploads binary archives and `SHA256SUMS` to GitHub Release.
   - Publishes the crates bottom-up with `scripts/publish-crates.sh` using **crates.io trusted publishing**: the job requests `id-token: write`, exchanges the GitHub OIDC token with `rust-lang/crates-io-auth-action`, and passes the short-lived token to the script. No long-lived `CARGO_REGISTRY_TOKEN` secret is stored in the repository.

### Trusted publishing setup

Trusted publishing is configured per crate on crates.io for this repository and the `release.yml` workflow; it needs no repository secret. The publish job's `id-token: write` permission and the `rust-lang/crates-io-auth-action` step provide a short-lived token. **The first publish of a new crate must use a registry token** (`cargo login` locally, then `scripts/publish-crates.sh`), because crates.io can only accept a trusted-publisher configuration once the crate exists. Configure the trusted publisher for each new crate after that first publish.

The publish job checks the registry first and skips the OIDC exchange when every workspace version is already published, so re-running a release whose crates are live is green. `CARGO_REGISTRY_TOKEN` still overrides the credentials stored by `cargo login` when publishing locally.
