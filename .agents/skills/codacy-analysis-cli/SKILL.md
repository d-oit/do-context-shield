---
name: codacy-analysis-cli
description: Uses the Codacy Analysis CLI to run local static analysis on repositories or specific files. Handles installation, initialization, dependency management, dry-runs, and analysis with JSON output. Use whenever the user wants to analyze code locally, run static analysis, scan for bugs or security issues, lint files, check code quality without pushing to Codacy, or run tools like ESLint, Ruff, Semgrep, RuboCop, or any other supported analyzer on their machine. Also trigger when the user asks to analyze staged changes, scan a PR locally, or set up local Codacy analysis.
license: MIT
metadata:
  author: Codacy
  version: 1.5.0
---
## Guides
See references/heuristics.md for distilled heuristics.

# Codacy Analysis CLI

> **Glossary:** See [glossary.md](../../references/glossary.md) for shared definitions of Codacy concepts (issues, findings, severity, coverage, tools, patterns, etc.).

The Codacy Analysis CLI (`codacy-analysis`) runs static analysis locally on a repository. It detects languages, selects tools, and reports issues — without pushing code to Codacy. This is a different tool from the Codacy Cloud CLI (`codacy`), which queries remote Codacy data.

Always use `--output-format json` for structured output in agentic workflows.

For gating runs (pre-commit, PR review, CI), also pass `--fail-if-missing` — see [Strict mode](references/analysis-workflow.md#strict-mode).

## Setup

```bash
# Install
npm i -g @codacy/analysis-cli

# Verify
codacy-analysis --help
```

### Authentication (optional)

Authentication is only required for `init --remote` (fetching config from a Codacy repository). Local analysis works without authentication.

```bash
# Option 1: Interactive login
codacy-analysis login

# Option 2: Token flag
codacy-analysis login --token <your-api-token>

# Option 3: Environment variable
export CODACY_API_TOKEN=<your-api-token>

# Obtain tokens: Codacy > My Account > Access Management
# Remove credentials
codacy-analysis logout
```

**Shared session:** The Analysis CLI and the Cloud CLI (`codacy`) share the same credentials at `~/.codacy/credentials`. Logging in or out with either CLI applies to both — there is no need to authenticate separately.

## Getting help

```bash
codacy-analysis --help
codacy-analysis <command> --help
# e.g. codacy-analysis analyze --help
```

## Filesystem conventions

The CLI uses two managed locations:

| Location | Scope | Contents |
|----------|-------|----------|
| `.codacy/` (in repo root) | Per-project | `codacy.config.json`, `generated/` (tool configs), `.gitignore` (auto-created) |
| `~/.codacy/` (home dir) | Machine-wide | Runtimes, tool binaries, caches, logs, credentials |

The analyzed repository is **never modified outside of `.codacy/`**. The `.codacy/.gitignore` is auto-created to exclude `generated/`, logs, and other transient files.

### Key files

- `.codacy/codacy.config.json` — Main configuration: tools, patterns, excludes, metadata. See [references/config-format.md](references/config-format.md) for the full schema
- `.codacy/generated/<ToolId>/` — Materialized tool-specific configs (gitignored)
- `~/.codacy/credentials` — Stored API token
- `~/.codacy/logs/` — Structured logs (JSON lines, rotated at 10 MB)

## Provider values

Used with `init --remote`. See the [Provider section in the glossary](../../references/glossary.md#provider) for the full table of CLI values (`gh`, `gl`, `bb`).

## Detailed workflow

Use [the analysis workflow reference](references/analysis-workflow.md) for setup, strict analysis, result interpretation, common workflows, and troubleshooting.

For findings involving test secrets or subprocess commands, consult [repository-verified remediation heuristics](references/heuristics.md).

## Rationalizations

| Rationalization | Reality |
|---|---|
| "An empty issues array means the scan passed." | Verify configured tools ran; inspect `toolResults` and missing-tool errors. |
| "Local analysis proves Codacy Cloud is clean." | Local and Cloud configurations differ; scope conclusions to the data actually queried. |

## Red Flags

- [ ] No successful tool results accompany a clean issues array.
- [ ] Configured tools were skipped, unavailable, or did not cover changed files.
- [ ] Cloud status is inferred from local output, or vice versa.
