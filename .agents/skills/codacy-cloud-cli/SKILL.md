---
name: codacy-cloud-cli
description: Uses the Codacy Cloud CLI to query repositories, issues, security findings, pull requests, tools, and patterns on Codacy Cloud. Use whenever the user mentions Codacy, asks about code quality metrics, wants to check issues or findings in a repo, inspect a pull request analysis, browse security vulnerabilities, enable or disable tools, search patterns, trigger a reanalysis, or interact with any remote Codacy data — even if they don't say "Codacy CLI" explicitly.
license: MIT
metadata:
  author: Codacy
  version: 1.6.1
---

# Codacy Cloud CLI

> **Glossary:** See [glossary.md](../../references/glossary.md) for shared definitions of Codacy concepts (issues, findings, severity, coverage, tools, patterns, etc.).

The Codacy Cloud CLI (`codacy`) is the command-line interface for Codacy Cloud. Use it whenever the user wants to interact with remote Codacy data. This is a different tool from the Codacy Analysis CLI (`codacy-analysis`), which runs static analysis locally.

## Setup

```bash
# Install
npm install -g @codacy/codacy-cloud-cli

# Authenticate — 3 options:
# 1. Set the `CODACY_API_TOKEN` environment variable
export CODACY_API_TOKEN=<token>
# 2. Use the `codacy login` command (interactive login)
codacy login
# 3. Use the `codacy login` command (with token input)
codacy login --token <token>
# Obtain tokens: Codacy > My Account > Access Management > Account API Tokens (https://app.codacy.com/account/access-management)

# Verify
codacy info
```

**Shared session:** The Cloud CLI and the Analysis CLI (`codacy-analysis`) share the same credentials at `~/.codacy/credentials`. Logging in or out with either CLI applies to both — there is no need to authenticate separately.

## Getting help

The CLI is the authoritative source of truth. Always use `--help` to discover available commands, options, and current behavior:

```bash
codacy --help
codacy <command> --help
# e.g. codacy issues --help
```

Use `--output json` on any command for machine-readable output.

## Provider values

See the [Provider section in the glossary](../../references/glossary.md#provider) for the full table of CLI values (`gh`, `gl`, `bb`).

## Auto-detection of repository parameters

The CLI auto-detects the `provider`, `organization`, and `repository` from the git remote origin URL when run inside a repository. This means most commands work without specifying these parameters explicitly:

```bash
# Auto-detected (run inside the repo)
codacy issues
codacy repository
codacy pull-request 42

# Equivalent explicit form
codacy issues gh my-org my-repo
codacy repository gh my-org my-repo
codacy pull-request gh my-org my-repo 42
```

Auto-detection supports GitHub, GitLab, and Bitbucket remote URLs. If the remote cannot be parsed (e.g., non-standard hosting), pass the parameters explicitly. All examples in this document use the explicit form for clarity, but the short form is preferred when running inside a repo.

## How Codacy data works

- **Data reflects the HEAD commit** — issue lists, coverage, and security findings always show the state of the latest analyzed commit on the branch or pull request. There is no per-file or per-line historical view.
- **Configuration changes are not instant** — enabling/disabling tools or patterns, changing parameters, and ignoring issues only take effect after the next analysis. That means either triggering a reanalysis via `--reanalyze` or waiting for the next commit to be pushed.
- **Organization standards are enforced and cannot be overridden at repository level** — if a pattern is enforced by a Coding Standard at the organization level, its enabled/disabled state and parameters cannot be changed per-repository. To change it, the standard must be updated at the organization level.

### Reanalysis

Use `--reanalyze-and-wait` (`-w`) on the `repository` or `pull-request` commands to trigger reanalysis and block until it completes. The CLI captures a baseline, triggers reanalysis, polls every 10 seconds (up to 20 minutes), and reports issue deltas by pattern, severity, and category with timing information. Supports `--output json` for machine-readable delta reports.

```bash
# Trigger reanalysis and wait for results (preferred)
codacy repository gh my-org my-repo --reanalyze-and-wait
codacy repository gh my-org my-repo -w -o json    # JSON delta report

# Fire-and-forget reanalysis (no waiting)
codacy repository gh my-org my-repo --reanalyze
```

When using `--reanalyze` without `--and-wait`, check progress manually by re-running the command without `--reanalyze`:
- **Table output:** look at the "Analysis" field — `"Reanalysis in progress..."` means it is still running; `"Finished X ago"` means it is done
- **JSON output:** compare the `startedAnalysis` and `endedAnalysis` timestamps — complete when `startedAnalysis` > trigger time AND `endedAnalysis` > `startedAnalysis`

## Command reference

See [the full command reference](references/command-reference.md) for repository, issue, finding, pull-request, tool, pattern, and import commands.

## Common workflows

**Check critical security issues in a repo:**
```bash
codacy findings gh my-org my-repo --severities Critical,High
```

**Review what a PR introduced:**
```bash
codacy pull-request gh my-org my-repo 42
codacy pull-request gh my-org my-repo 42 --diff
```

**Understand a specific issue:**
```bash
codacy issue gh my-org my-repo <issueId>   # includes pattern docs and code context
```

**Trigger reanalysis and wait for results:**
```bash
codacy repository gh my-org my-repo --reanalyze-and-wait
codacy repository gh my-org my-repo -w -o json    # JSON delta report with issue changes by pattern/severity/category
```

**Identify and reduce noise:**
```bash
codacy issues gh my-org my-repo --overview        # see false positive counts and suggested actions to reduce noise
```

**Check whether a vulnerable dependency is actually reachable:**
```bash
codacy issue gh my-org my-repo <issueId>          # or: codacy finding gh my-org my-repo <findingId>
```
If the output includes a `Vulnerable Functions` block, search the repo for calls to those functions (including re-exports and wrapper functions). If none are found, ignore the issue/finding with `--ignore-reason NotExploitable`; otherwise recommend upgrading the dependency.

**Audit vulnerable dependencies across one or multiple repos at once:**
```bash
# one repo
codacy findings gh my-org my-repo --scan-types SCA --output json

# multiple repos
for repo in my-repo-one my-repo-two; do
  codacy findings gh my-org "$repo" --scan-types SCA --output json
done | jq -s '{findings: (map(.findings) | add)}'
```
Keep only findings where `advisoryInformation.vulnerableFunctions` is a non-empty array — it's sometimes present but empty, which means no reachability check is possible. For each, `dependencyChains` tells you Direct (a single package) vs. Transitive (2+ packages — the first package in the chain is the one to upgrade); when `dependencyChains` is missing entirely, Codacy hasn't resolved the import path, so treat it as unknown rather than assuming Direct — plenty of transitive packages (verified against real `package.json`/lockfile data) show up with no chain at all. For each repository above, search your local checkout for calls to the listed functions, then report back per repository — used/not used, chain status, recommendation — and wait for confirmation before ignoring anything with `--ignore-reason NotExploitable` or applying an upgrade.

## Rationalizations

| Rationalization | Reality |
|---|---|
| "An empty list proves there are no findings." | Verify repository identity, filters, pagination, and completed analysis before concluding. |
| "The first page is the complete pattern list." | Check command limits and use targeted queries or configuration data for full counts. |

## Red Flags

- [ ] Repository or provider was inferred but not verified.
- [ ] Reanalysis is still running or the returned data is stale.
- [ ] A paginated or truncated response is reported as complete.
