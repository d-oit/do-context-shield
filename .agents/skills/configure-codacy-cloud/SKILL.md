---
name: configure-codacy-cloud
description: Tunes an existing Codacy Cloud repository's configuration directly on the cloud, without local analysis, by importing the current config, suggesting higher-signal tools and patterns, reanalyzing, and iteratively reducing noise across two tuning passes. Requires the repository to already be on Codacy with at least one finished analysis. Uses the Codacy Analysis CLI only for config-file operations and the Codacy Cloud CLI for everything else. Produces a machine-readable JSON summary of pattern, tool, category, and severity changes plus conflicts and recommended path ignores. Use when the user wants to configure or tune Codacy directly on the cloud, reduce noise on a repository already analyzed by Codacy, optimize cloud patterns and tools, or improve the signal of cloud issues without running local analysis.
license: MIT
metadata:
  author: Codacy
  version: 1.1.0
---

# Configure Codacy (Cloud)

> **Glossary:** See [glossary.md](../../references/glossary.md) for shared definitions of Codacy concepts (issues, findings, severity, coverage, tools, patterns, etc.).

This skill tunes the Codacy configuration of a repository **directly on Codacy Cloud**, using the cloud as the source of truth. It does **not** run local analysis. It reads the current cloud issue landscape, applies a higher-signal set of tools and patterns, reanalyzes on Codacy, and iteratively cuts noise over two passes — producing a clean, high-signal configuration with a full audit trail of what changed and why.

For the local-first variant that discovers a stack from scratch and runs `codacy-analysis analyze` locally, use the `configure-codacy` skill instead. This skill is for repositories **already on Codacy with a finished analysis** where you want to tune the cloud config in place.

## Prerequisites and requirements

- **Codacy Cloud CLI** (`codacy`) — drives all cloud reads, updates, and reanalysis. See `codacy-cloud-cli` for setup.
- **Codacy Analysis CLI** (`codacy-analysis`) — used **only** for config-file operations (`init --remote`, `init --auto`, `config --merge`). See `codacy-analysis-cli` for setup.
- Both CLIs share credentials at `~/.codacy/credentials`, so a single login covers both.

This skill has **three hard requirements**. Verify all three before doing anything else and stop with clear guidance if any fails:

1. **The repository is already on Codacy.** Confirm with:
   ```bash
   codacy repo --output json
   ```
   If this fails (not on Codacy, no auth), stop. Tell the user to add the repo to Codacy first (e.g. `codacy repo --add`) — this skill does not set up a new repository.

2. **The repository has at least one finished analysis.** Inspect the `codacy repo --output json` output for a completed/last-analysis indicator, and confirm the issue overview returns data:
   ```bash
   codacy issues -O -o json 2>/dev/null | jq '.'
   ```
   If the repo was never analyzed, or analysis is still running, stop. Tell the user to wait for the first analysis to finish — the whole flow depends on cloud issue data as the baseline.

3. **The Cloud CLI is ≥ 1.3.0** (required to populate `fileCount`). Confirm with:
   ```bash
   codacy repo -o json 2>/dev/null | jq -e '.repository.fileCount != null'
   ```
   If this prints `false` (or errors), stop. The installed Cloud CLI is older than 1.3.0 and does not populate the summary's `fileCount` field. Tell the user to upgrade to at least 1.3.0 (`npm install -g @codacy/codacy-cloud-cli@latest`) and rerun. The check uses `!= null` rather than `has("fileCount")` so it rejects both absent keys and explicit nulls, and feature presence is checked rather than `--version` because the current CLI hardcodes its `--version` string.

The Cloud CLI auto-detects `provider`, `organization`, and `repository` from the git remote when run inside the repo, so the explicit `<provider> <org> <repo>` arguments shown below are optional in practice.

**CLI output caveat:** both CLIs print progress lines to stderr before their JSON output. When piping to `jq`, redirect stderr: `codacy ... -o json 2>/dev/null | jq '...'`.

**`codacy patterns` pagination caveat:** `codacy patterns <tool> [--enabled]` currently returns only the **first 100 patterns** and has **no `--limit` flag** (one is planned — until then, assume the list is truncated at 100). Never use the length of its output as a pattern count: for a tool whose enabled set exceeds 100 you will silently see only 100, which reads as a phantom "reduction" (e.g. a tool that actually has 232 enabled patterns appears to have "100"). To check or test a **specific** pattern, filter by id with `--search <patternId>` or query the single pattern with `codacy pattern <tool> <patternId> -o json`. For accurate enabled-pattern **counts**, derive them from the config file (`jq '[.tools[].patterns|length]|add' .codacy/auto.config.json`) rather than the patterns list.

**Local config is untouched.** This skill works through custom `--config-file` paths (`.codacy/remote.config.json`, `.codacy/auto.config.json`) and **never creates or modifies `.codacy/codacy.config.json`**. Any existing local config is left intact.

## How this skill works

The key principle is the same as the local variant: **start from a higher-signal set, then cut noise using data** — but every measurement and every change happens on Codacy Cloud.

Tools fall into two groups, and changes are applied through **two different mechanisms**:

- **Tools supported by the Analysis CLI** (those listed by `codacy-analysis info`, see [supported-tools.md](../codacy-analysis-cli/references/supported-tools.md)) are configured by editing the `.codacy/auto.config.json` file and importing it: `codacy tools --import .codacy/auto.config.json`. The import **reconciles supported tools to the file's contents**: a supported tool present in the file has its patterns replaced by the file's, and a supported tool **absent** from the file is **disabled** by the import (you will see `N tool will be disabled: ...` in the import plan). **Cloud-only tools** — those outside the Analysis CLI's scope — are never in the file and keep their state.
- **Cloud-only tools** (enabled in Codacy but not runnable by the Analysis CLI, e.g. SonarSharp, Codacy ScalaMeta Pro) cannot be configured via the import. Change them directly with the Cloud CLI: `codacy tool`, `codacy pattern`, `codacy patterns`.

**Cloud tool name vs config `toolId`.** The Cloud CLI commands (`codacy tool`, `codacy pattern`, `codacy patterns`) address tools by their **cloud name** as shown by `codacy tools` — which for some tools **differs** from the Analysis CLI config `toolId`. The clearest case: the config `toolId` is `Semgrep`, but the cloud tool is named `Opengrep`, so `codacy patterns Semgrep` fails with `Tool "Semgrep" not found` while `codacy patterns Opengrep` works. When a Cloud CLI command reports a tool as not found, check the name in `codacy tools -o json` and use that. (The import path, which keys by `toolId`, is unaffected.)

Read [the config format reference](../codacy-analysis-cli/references/config-format.md) before editing `auto.config.json`. Its shape: a top-level `tools[]` array where each entry is keyed by **`toolId`** (e.g. `"Biome"`, `"Semgrep"`, `"ESLint9"`) and holds a `patterns[]` array whose entries are keyed by **`patternId`** with an optional **`parameters`** object — there is **no** `uuid`, `name`, or `enabled` key on these entries, so filter and edit by `toolId` / `patternId`. To disable a pattern, remove it from the `patterns` array; to tune one, edit its `parameters`; to disable a tool, remove the whole tool entry.

## Detailed workflow

Follow [references/cloud-workflow.md](references/cloud-workflow.md) for startup checks, two-pass tuning, summary generation, and import rules.

## Rationalizations

| Rationalization | Reality |
|---|---|
| "The repository exists locally, so it is ready for Cloud tuning." | Confirm Codacy registration and a completed analysis before changing remote state. |
| "Omitting a tool from the import leaves it unchanged." | Import disables supported tools absent from the config; inspect the plan first. |

## Red Flags

- [ ] Repository identity, completed analysis, or CLI capability is unverified.
- [ ] An import would disable an omitted supported tool unexpectedly.
- [ ] Cloud tool names are guessed from Analysis CLI `toolId` values.
