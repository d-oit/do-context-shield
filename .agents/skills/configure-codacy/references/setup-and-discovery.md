# Configure Codacy

> **Glossary:** See [glossary.md](../../../references/glossary.md) for shared definitions of Codacy concepts (issues, findings, severity, coverage, tools, patterns, etc.).

This skill tailors Codacy configuration to a project's actual stack and coding conventions. It discovers the repository's languages and frameworks, initializes a broad set of tools and patterns, runs analysis, then intelligently cuts noise — producing a clean, high-signal configuration with a full audit trail of what changed and why.

## Prerequisites

- **Codacy Analysis CLI** (`codacy-analysis`) with `discover` and `init --auto` support. If the CLI does not support these commands, update it running: `npm i -g @codacy/analysis-cli`. See `codacy-analysis-cli` for setup.
- **Codacy Cloud CLI** (`codacy`) — needed to know if the repo is on Codacy Cloud and if so, fetch issues from the cloud-only tools. See `codacy-cloud-cli` for setup.

Both CLIs share credentials at `~/.codacy/credentials`, so a single login covers both.

## How configuration works

All configuration is done locally via `.codacy/codacy.config.json`. Edit the file, run analysis, see results instantly — no push or cloud reanalysis needed. Once tuned, the configuration can be imported to Codacy Cloud in one step.

The key principle: **start broad, then cut noise using data**. Initialize with maximum pattern coverage via `init --auto`, run analysis to see the full issue landscape, then use the severity/category distribution to decide what to disable or tune.


Read [the config format reference](../../codacy-analysis-cli/references/config-format.md) for the full schema before editing — field names matter (e.g., the exclusion field is `exclude`, not `excludePaths`). To disable a pattern, remove it from the `patterns` array. To disable a tool, remove the entire tool entry.

**Organization standards take precedence.** If a pattern is enforced by a Coding Standard at the organization level, it cannot be changed at the repository level.

**Local config only.** The `.codacy/codacy.config.json` file is used exclusively for local analysis. Committing or pushing it to the repository has NO effect on Codacy Cloud analysis. To apply the configuration to Codacy Cloud, use the import command (`codacy tools ... --import`).

## Invocation modes

The skill supports three modes that control whether configuration is imported to Codacy Cloud after tuning:

- **Interactive (default):** After tuning and presenting results, prompt the user via `AskUserQuestion` whether to import the configuration to Codacy Cloud. This is the default when no arguments are provided.
- **Auto-import:** If the user's invocation arguments contain the word "import" (e.g., `/configure-codacy import configuration`, `/configure-codacy --import`), skip the import prompt and import automatically after presenting results. Useful for CI runs and automation.
- **Local-only:** If the repo is not on Codacy Cloud (determined in Step 0), never ask about importing. Present results and note that the config is ready for local analysis only.

Additionally, the **force** flag controls Coding Standard handling during import:

- **Force disabled (default):** If the import encounters Coding Standard conflicts (409 errors), **do NOT automatically retry with `--force`**. Instead, present the conflicts to the user via `AskUserQuestion` and let them decide whether to unlink the Coding Standards.
- **Force enabled:** If the user's invocation arguments contain the word "force" (e.g., `/configure-codacy import force`), automatically retry with `--force` when Coding Standard conflicts occur.

Parse the invocation arguments at the very start. Set internal flags that Step 6 will reference:
- If args contain "import" → auto-import mode
- If args contain "force" → force mode (allows automatic Coding Standard unlinking)
- Else → interactive mode (may become local-only if Step 0 finds the repo is not on Cloud)

## Tailored configuration workflow

```
Configuration Progress:
- [ ] Step 0: Check environment and capture baseline
- [ ] Step 1: Discover repository stack
- [ ] Step 2: Initialize auto-tuned configuration
- [ ] Step 3: Run broad-config baseline analysis
- [ ] Step 4: Smart noise evaluation and tuning
- [ ] Step 5: Show local results
- [ ] Step 6: Cloud import (conditional)
- [ ] Step 7: Clean-up
```

### Step 0: Check environment and capture baseline

This step determines the starting point and captures the BEFORE metrics for the final summary. The flow depends on two conditions: whether the repo is on Codacy Cloud, and whether a local config already exists.

#### 0a. Create temp directory and check Codacy Cloud status

Create the temporary directory for intermediate analysis files:
```bash
mkdir -p .codacy/tmp
```

The Cloud CLI auto-detects provider, organization, and repository from the git remote origin URL — no need to derive these manually. All `codacy` commands below can be run without explicit `<provider> <org> <repo>` when inside the repo. For clarity, the examples use the explicit form; replace with auto-detected short form in practice.

**CLI output caveat:** Both `codacy` and `codacy-analysis` CLIs write progress lines (e.g., `- Fetching tools...`, `- Fetching issues...`) to stderr before the actual JSON output. When piping CLI output directly to `jq`, redirect stderr to avoid parse errors:

```bash
codacy repository --output json 2>/dev/null | jq '...'
```

Check Cloud status:
```bash
codacy repository --output json
```

If this succeeds, the repo is on Codacy Cloud. Also list enabled tools to identify cloud-only tools later:
```bash
codacy tools --output json 2>/dev/null | jq '[.[] | select(.settings.isEnabled == true) | {name, isClientSide}]'
```

If it fails (repo not on Codacy, no auth, or no Cloud CLI), note that cloud features will be skipped — the local workflow is fully self-contained. Set the invocation mode to local-only (see "Invocation modes" section).

#### 0b. Capture baseline (BEFORE reference)

Branch based on Cloud status and local config existence. The baseline captured here is the true BEFORE reference for the summary in Step 5.

**Track A — Repo is on Codacy Cloud (authoritative baseline):**

The Cloud configuration is the authoritative source. Use `init --remote` to fetch it.

**Important:** `init --remote` will fail if `.codacy/codacy.config.json` already exists. Always delete it first (the backup copy step happens before the delete):

```bash
# Delete any existing config first — init --remote refuses to overwrite
rm -f .codacy/codacy.config.json

# Fetch the current Cloud configuration
codacy-analysis init --remote <provider> <org> <repo>

# Store a copy for later merging and comparison
cp .codacy/codacy.config.json .codacy/tmp/codacy-remote-config.json

# Record BEFORE metrics
jq '[.tools[].patterns | length] | add' .codacy/codacy.config.json
jq '.tools | length' .codacy/codacy.config.json

# Run analysis with the Cloud config to capture the BEFORE issue landscape
codacy-analysis analyze --install-dependencies --output-format json --output .codacy/tmp/codacy-remote-results.json

# Record BEFORE issue count and runtime
jq '.issues | length' .codacy/tmp/codacy-remote-results.json
jq '.metadata.durationMs' .codacy/tmp/codacy-remote-results.json
```

Fetch the Cloud issue overview — this gives per-pattern issue counts, false positive counts, and suggested actions across the entire repository without downloading every individual issue:
```bash
codacy issues -O -o json > .codacy/tmp/codacy-cloud-overview.json
```
This overview data is valuable for tuning decisions in Step 4: it shows which patterns produce the most issues on Cloud (the production truth), includes false positive rates per pattern, and generates suggested actions to reduce noise (identifying patterns accounting for 10%+ of all issues or 3x the average). The suggested actions include ready-to-run disable commands, adapted for coding standard or config-file constraints. Save it for later comparison.

Also check for cloud-only tools — tools enabled in Cloud but not available in the local Analysis CLI. Get the local CLI's supported tools via `codacy-analysis info`, then compare against the Cloud-enabled tools list above. Any Cloud-enabled tool not in the `info` output is cloud-only (e.g., SonarSharp, Codacy ScalaMeta Pro). If cloud-only tools exist and have issues, fetch them:
```bash
codacy issues --output json > .codacy/tmp/codacy-remote-cloud-results.json
```

**Track B — NOT on Cloud, but local `.codacy/codacy.config.json` exists:**

```bash
# Store a copy for later merging and comparison
cp .codacy/codacy.config.json .codacy/tmp/codacy-previous-config.json

# Record BEFORE metrics
jq '[.tools[].patterns | length] | add' .codacy/codacy.config.json
jq '.tools | length' .codacy/codacy.config.json

# Run analysis with the existing local config
codacy-analysis analyze --install-dependencies --output-format json --output .codacy/tmp/codacy-previous-results.json

# Record BEFORE issue count and runtime
jq '.issues | length' .codacy/tmp/codacy-previous-results.json
jq '.metadata.durationMs' .codacy/tmp/codacy-previous-results.json
```

**Track C — No Cloud, no local config:**

Record BEFORE as unconfigured: 0 patterns, 0 tools, 0 issues, `null` runtime. No analysis to run.

Save the BEFORE metrics from whichever track ran. The broad config metrics from Steps 2-3 are internal only — they are NOT reported to the user.

#### 0c. Cloud noise pre-evaluation (Track A only)

If the Cloud overview was fetched (`.codacy/tmp/codacy-cloud-overview.json` exists), analyze it now to identify patterns that are already known to be noisy based on Cloud production data. This saves time by pre-disabling known noise before running local analysis.

Start by checking the overview's **suggested actions** — the CLI already identifies patterns accounting for 10%+ of all issues or 3x the average per-pattern count and provides ready-to-run disable commands. Use these suggestions as the primary signal, then supplement with the criteria below.

Parse the overview's `patterns` array (each entry has `{id, title, total}`) and false positive counts:

```bash
# Issue counts per pattern
jq '[.overview.patterns[] | {id, title, total}] | sort_by(-.total)' .codacy/tmp/codacy-cloud-overview.json

# Patterns with potential false positives (count > 0)
jq '[.overview.patterns[] | select(.potentialFalsePositives > 0) | {id, title, total, potentialFalsePositives, falsePositiveRatio: ((.potentialFalsePositives / .total) * 100 | round)}] | sort_by(-.falsePositiveRatio)' .codacy/tmp/codacy-cloud-overview.json
```

**Identify noisy patterns using these criteria:**

1. **Wrong-language patterns** — cross-reference pattern IDs against the discovered stack (Step 1 runs next, but the Cloud tools list from Step 0a gives a rough language picture). Pattern IDs often contain the target language (e.g., `python.`, `java.`, `ruby.`). Mark patterns for languages clearly not in the project.

2. **Convention/style noise** — patterns with very high issue counts (top 5% by count) in categories like CodeStyle, Documentation, or Comprehensibility are likely convention mismatches. Mark these as candidates.

3. **High false-positive ratio patterns** — patterns where a significant proportion of issues are flagged as potential false positives (e.g., `potentialFalsePositives / total > 30%`) are strong candidates for pre-disabling. These patterns are producing results that Codacy's own heuristics consider unreliable. Store the false positive data for use in Step 4b rule 7, where patterns with high false-positive ratios get additional scrutiny during local verification.

4. **Never pre-disable Security patterns** — security patterns are never marked for pre-disabling regardless of count or false-positive ratio. They are handled in Step 4 with full context.

5. **Never pre-disable Critical/High severity patterns** — these require local verification before any action.

**Classify each noisy pattern into two lists:**

- **`cloudNoiseLocal`** — noisy patterns from tools supported by the local Analysis CLI. These will be removed from `.codacy/codacy.config.json` immediately after `init --auto` in Step 2.
- **`cloudNoiseCloudOnly`** — noisy patterns from cloud-only tools (identified in Step 0b). These will be disabled via Cloud CLI during Step 6 (import), only if the import is performed.

Store both lists for use in Steps 2 and 6. This is a pre-filter — Step 4 will perform deeper noise evaluation on the local analysis results.

### Step 1: Discover repository stack

Run discovery to understand the repository's languages, frameworks, and libraries:

```bash
codacy-analysis discover --output-format json --output .codacy/tmp/codacy-discover.json
```

Parse the output to understand:
- Languages present in the project
- Frameworks and libraries in use (e.g., React, Django, Spring Boot)
- This informs noise evaluation in Step 4 (e.g., knowing a project uses React means JSX-related patterns are relevant)

Note: The Codacy Cloud check already happened in Step 0.

### Step 2: Initialize auto-tuned configuration

First, remove the existing `.codacy/codacy.config.json` if any (the backup copy was already stored in Step 0):

```bash
rm -f .codacy/codacy.config.json
```

Initialize with the broadest useful pattern set, filtered by the discovered stack:

```bash
codacy-analysis init --auto "Critical,High,Warning,Minor,AllSecurity,ErrorProne,Performance,BestPractice,UnusedCode,Compatibility,Complexity,Comprehensibility,CodeStyle,Documentation"
```

This filter means:
- `Critical` — Codacy-recommended (default) Critical-severity patterns
- `AllSecurity` — ALL Security-category patterns (including non-defaults)
- Everything else — Codacy-recommended (default) patterns at High, Warning, and Minor severity across all categories

The intent is to start broad and cut in Step 4 based on actual analysis data.

**Apply Cloud noise pre-filter (Track A only):** If `cloudNoiseLocal` patterns were identified in Step 0c, remove them from the newly created config now. For each pattern in `cloudNoiseLocal`, find it in `.codacy/codacy.config.json` under its tool's `patterns` array and remove it. This avoids wasting local analysis time on patterns already known to be noisy from Cloud production data. Track these removals for the summary (they are pre-filter changes, reported in `patternChanges` with reason referencing Cloud data).

**Merge preserved configuration** from the baseline stored in Step 0:
- **Track A** (Cloud): Merge from `.codacy/tmp/codacy-remote-config.json`
- **Track B** (local config): Merge from `.codacy/tmp/codacy-previous-config.json`
- **Track C** (no prior config): No merge needed

For the applicable track:
1. Read the newly created `.codacy/codacy.config.json`
2. Merge the global `exclude` array from the stored config (merge, don't replace — the new config may have its own excludes)
3. For each tool that exists in both stored and new config, merge its per-tool `exclude` array
4. For tools where `useLocalConfigurationFile` was `true` in the stored config and the tool still exists, restore that setting along with the `localConfigurationFile` path

**Record broad-config metrics** (internal — not the BEFORE reference for the summary):
```bash
# Count enabled patterns across all tools in the broad config
jq '[.tools[].patterns | length] | add' .codacy/codacy.config.json

# Count enabled tools in the broad config
jq '.tools | length' .codacy/codacy.config.json
```

### Step 3: Run broad-config baseline analysis

Run analysis with the broad config to see the full issue landscape. This is an internal step for tuning decisions — the BEFORE reference for the user-facing summary comes from Step 0.

```bash
codacy-analysis analyze --install-dependencies --output-format json --output .codacy/tmp/codacy-baseline.json
```

Always use `--output <file>` to avoid broken JSON from stdout buffering.

**Record broad-config metrics** (used for tuning decisions in Step 4, not for the summary):
```bash
# Total issues in broad config
jq '.issues | length' .codacy/tmp/codacy-baseline.json

# Total runtime in milliseconds
jq '.metadata.durationMs' .codacy/tmp/codacy-baseline.json
```

**Parse the issue distribution** — this is the basis for all tuning decisions:

```bash
# Issues grouped by pattern (noise detection)
jq '[.issues | group_by(.patternId) | .[] | {patternId: .[0].patternId, toolId: .[0].toolId, severity: .[0].severity, category: .[0].category, count: length}] | sort_by(-.count)' .codacy/tmp/codacy-baseline.json

# Issues by severity
jq '.issues | group_by(.severity) | map({severity: .[0].severity, count: length})' .codacy/tmp/codacy-baseline.json

# Issues by category
jq '.issues | group_by(.category) | map({category: .[0].category, count: length})' .codacy/tmp/codacy-baseline.json

# Top 20 files by issue count
jq '[.issues | group_by(.filePath) | .[] | {filePath: .[0].filePath, count: length}] | sort_by(-.count) | .[0:20]' .codacy/tmp/codacy-baseline.json

# Per-tool results
jq '.toolResults | map({toolId, status, issueCount, durationMs, filesAnalyzed})' .codacy/tmp/codacy-baseline.json
```

