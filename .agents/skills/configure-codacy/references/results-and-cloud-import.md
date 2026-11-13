# Results, cloud import, and cleanup
### Step 5: Show local results

#### 5a. Generate summary JSON

Write `.codacy/configure-codacy-summary.json` with the before/after metrics, a detailed change log, and supporting context. Runtime values are in milliseconds (raw `durationMs` from the CLI).

**The `before` values come from Step 0** (the baseline captured before any changes — Cloud config for Track A, local config for Track B, or unconfigured for Track C). **The `after` values come from Step 4f** (the final tuned configuration). If no initial config existed (Track C), `before` values reflect an unconfigured state — use `null` for metrics that cannot be measured (e.g., runtime) and `0` for counts (patterns, tools, issues).

```json
{
  "summary": {
    "enabledPatterns": { "before": 1000, "after": 300 },
    "enabledTools": { "before": 34, "after": 15 },
    "issues": { "before": 7000, "after": 550 },
    "analysisRuntime": { "before": 240000, "after": 60000 }
  },
  "toolChanges": [
    {
      "toolId": "Biome",
      "action": "disabled",
      "reason": "Project uses ESLint9 with local config; Biome is redundant and produced 16K false positives in TypeScript",
      "patternsAffected": 232
    },
    {
      "toolId": "markdownlint",
      "action": "enabled",
      "reason": "New tool added for Markdown linting; README.md excluded per-tool to avoid inline HTML noise",
      "patternsAffected": 43
    }
  ],
  "patternChanges": [
    {
      "patternId": "Semgrep_python.lang.security.audit.xss.template-injection",
      "toolId": "Semgrep",
      "action": "disabled",
      "reason": "Wrong stack — pattern for Python; project is JavaScript-only",
      "delta": -45,
      "parameters": []
    },
    {
      "patternId": "Lizard_ccn-medium",
      "toolId": "Lizard",
      "action": "updated",
      "reason": "Raised threshold from 10 to 20 to match codebase complexity profile",
      "delta": -120,
      "parameters": [
        { "id": "threshold", "before": "10", "after": "20" }
      ]
    },
    {
      "patternId": "Semgrep_codacy.javascript.security.hard-coded-password",
      "toolId": "Semgrep",
      "action": "enabled",
      "reason": "New High Security pattern — detects hardcoded passwords; found 101 issues across 41 files for review",
      "delta": 101,
      "parameters": []
    }
  ],
  "fileExclusions": {
    "global": ["src/routeTree.gen.ts"],
    "perTool": {
      "markdownlint": ["README.md"]
    }
  },
  "securityCoverage": {
    "deduplication": [
      "Semgrep slack-webhook-url disabled — same concern covered by Semgrep detected-slack-webhook"
    ],
    "newCoverage": [
      "unsafe-dynamic-method (Critical, 5 issues)",
      "open-redirect-from-function (Critical, 4 issues)",
      "hard-coded-password (High, 101 issues)"
    ],
    "noisyButKept": [
      "Semgrep hard-coded-password (101 issues) — kept per security guardrail, file exclusions preferred over disabling"
    ]
  },
  "keyImprovements": [
    "Lizard complexity thresholds tuned to match mature React SPA — 576 fewer noise issues while keeping genuinely complex functions flagged",
    "6 new security patterns detecting open redirects, unsafe dynamic methods, hardcoded passwords, and React href injection (119 new findings)",
    "markdownlint added for Markdown quality",
    "Checkov expanded from 6 to 1358 IaC security patterns"
  ],
  "localConfigTools": [
    {
      "toolId": "ESLint9",
      "configFile": "eslint.config.js",
      "issueCount": 42,
      "note": "Issues from this tool are controlled by the project's ESLint config, not Codacy patterns. Edit eslint.config.js to reduce noise."
    }
  ],
  "codacyYaml": null,
  "importResults": null,
  "cloudVerification": null
}
```

**Field reference:**

**`summary`** — before/after metrics (same as before).

**`toolChanges`** — one entry per tool added or removed. Each entry:
- `toolId` — the tool identifier
- `action` — `"enabled"` (tool was added) or `"disabled"` (tool was removed)
- `reason` — why the tool was added or removed
- `patternsAffected` — number of patterns in the tool that was added/removed

**`patternChanges`** — one entry per individual pattern change. Each entry:
- `patternId` — the pattern identifier
- `toolId` — which tool this pattern belongs to
- `action` — `"enabled"`, `"disabled"`, or `"updated"`
- `reason` — why this change was made (auditability)
- `delta` — the change in issue count for this pattern, comparing INITIAL state (Step 0) vs FINAL tuned state (Step 4f). If the pattern was not enabled in the initial config, the delta is the full issue count from the tuned analysis (positive if newly enabled, 0 if disabled during tuning).
- `parameters` — parameter changes (empty array if not applicable)

Do NOT include individual pattern entries inside `patternChanges` for patterns that were added/removed as part of a whole tool change. Those are covered by the `toolChanges` entry. `patternChanges` is for surgical, individual pattern changes within a tool that remains enabled.

Do NOT include `"restored"` patterns here. Restoration (Step 4e) is an internal mechanism to ensure patterns from the baseline config that had Critical/High/Security results aren't lost by `init --auto`. It preserves what was already there — it's not a user-facing change.

**`fileExclusions`** — only lists **new** exclusions added during this tuning run. Exclusions already present in the baseline config are preserved automatically but not listed here (they are not changes).
- `global` — new global exclusion globs added during tuning
- `perTool.<toolId>` — new per-tool exclusion globs added during tuning

Omit `fileExclusions` entirely if no new exclusions were added.

**`securityCoverage`** — documents how security concerns are handled:
- `deduplication` — security patterns that were disabled because another pattern covers the same concern (list the kept pattern and the disabled one)
- `newCoverage` — new security patterns enabled that were NOT in the baseline config, with issue count
- `noisyButKept` — security patterns that are noisy but were kept active per the security guardrail

**`keyImprovements`** — array of 3–6 human-readable sentences summarizing the most impactful improvements. Focus on what changed and the quantitative impact. These should be suitable for presenting to the user as a summary.

**`localConfigTools`** — array of tools that have `useLocalConfigurationFile: true`. Each entry includes:
- `toolId` — the tool identifier
- `configFile` — path to the project's config file used by this tool
- `issueCount` — number of issues this tool produced in the tuned analysis
- `note` — human-readable explanation that noise from this tool is governed by the project's own config, not Codacy patterns

Empty array if no tools use local configuration files.

**`codacyYaml`** — string containing the generated `.codacy.yaml` file content if file exclusions were added (see Step 5c). `null` if no `.codacy.yaml` was generated.

**`importResults`** — `null` until Step 6 runs. If Cloud import is performed, this is populated with the results (see Step 6f for the schema).

**`cloudVerification`** — `null` unless Step 6e runs. Contains post-import Cloud verification results: whether reanalysis completed, issue counts before/after, patterns disabled on Cloud, and warnings. See Step 6e for the schema.

#### 5b. Present local results

Display a clear before/after summary to the user:

1. **Metrics table** — enabled patterns, enabled tools, total issues, and runtime (before vs after, with reduction %). The "before" is the baseline from Step 0. If no prior config existed (Track C), note "No prior configuration" in the before column.
2. **Tool changes** — tools added or removed, with reasons
3. **Top pattern changes by impact** — the `patternChanges` entries with the largest `|delta|`, sorted descending
4. **New security coverage** — new security patterns that were not in the baseline config
5. **Security deduplication** — any security patterns that were deduplicated (which was kept, which was disabled)
6. **Key improvements** — the `keyImprovements` array from the summary JSON, presented as a bulleted list
7. **Warnings** — failed tools, Semgrep parsing errors, tools with 0 files matched, any other issues encountered
8. **Local config file limitations** — for tools with `useLocalConfigurationFile: true`, note that their issues are controlled by the project's own config file (e.g., `.eslintrc`, `.rubocop.yml`), not by Codacy's managed patterns. Noise from these tools can only be reduced by editing the project's own config. List each such tool and the number of issues it produced, so the user knows where to look if they want further noise reduction.

#### 5c. Generate `.codacy.yaml` for Cloud file exclusions

File exclusions in `.codacy/codacy.config.json` only apply to local analysis. Codacy Cloud does not support importing file exclusions via the API or CLI. To apply file exclusions on Codacy Cloud, they must be defined in a `.codacy.yaml` file committed to the repository root (see [Codacy configuration file](https://docs.codacy.com/repositories-configure/codacy-configuration-file/)).

**If any new file exclusions were added during tuning** (global or per-tool), generate a `.codacy.yaml` file:

1. Read the existing `.codacy.yaml` from the repo root (if it exists) to preserve any existing configuration
2. Merge the new exclusions with any existing `exclude_paths` and per-engine `exclude_paths`
3. Write the updated `.codacy.yaml` to the repo root

The `.codacy.yaml` format uses Java glob syntax:
```yaml
---
exclude_paths:
  - "src/routeTree.gen.ts"
  - "vendor/**"
engines:
  markdownlint:
    exclude_paths:
      - "CHANGELOG.md"
  stylelint:
    exclude_paths:
      - "assets/vendor/**"
```

**Engine name mapping:** The engine names in `.codacy.yaml` may differ from the tool IDs in `.codacy/codacy.config.json`. Use the tool ID in lowercase as the engine name (e.g., `ESLint9` → `eslint9`, `Semgrep` → `semgrep`, `markdownlint` → `markdownlint`). If unsure, the tool ID in lowercase is the safe default.

4. Store the full content of the generated `.codacy.yaml` as a string in the `codacyYaml` field of the summary JSON
5. Present to the user:
   - Note that file exclusions cannot be imported to Codacy Cloud via API
   - The `.codacy.yaml` file has been created/updated in the repo root
   - The user should commit and push this file to apply the exclusions on Codacy Cloud
   - Codacy Cloud always reads `.codacy.yaml` from the default branch

If no new file exclusions were added, skip this step and leave `codacyYaml` as `null`.

### Step 6: Cloud import (conditional)

#### 6a. Check Cloud status

If the repo is NOT on Codacy Cloud (from Step 0): skip this step entirely. Note in the results: "The configuration is ready for local analysis. To use it on Codacy Cloud, first add the repository to Codacy."

#### 6b. Determine import behavior

Based on invocation mode (see "Invocation modes" section):

1. **Auto-import mode** (user invoked with "import" argument): Proceed directly to 6c.
2. **Interactive mode** (default): Use `AskUserQuestion` to ask the user: "Want to update these configurations in Codacy Cloud?" If the user declines, skip to Step 7.
3. **Local-only mode**: Already handled in 6a (skipped).

#### 6c. Cloud-only tools noise evaluation

Only if cloud-only tools had issues fetched in Step 0 (`.codacy/tmp/codacy-remote-cloud-results.json` exists):

Apply the same noise evaluation framework from Step 4 to the cloud-fetched issues. For each noisy pattern from a cloud-only tool:
- Check if its parameters can be tweaked to return fewer results → `codacy pattern <toolName> <patternId> --parameter key=value`
- If not tweakable → try to disable it: `codacy pattern <toolName> <patternId> --disable`
- If disable fails (Coding Standard enforcement) → note it for the results

#### 6d. Import local config

```bash
codacy tools --import .codacy/codacy.config.json -y
```

If the import encounters Coding Standard conflicts (409 errors — patterns/tools enforced at org level cannot be overridden):

1. **If force mode is enabled** (user invoked with "force" argument): Automatically retry with `--force`:
   ```bash
   codacy tools --import .codacy/codacy.config.json --force -y
   ```
   Note in the results that `--force` was used and which Coding Standards were unlinked.

2. **If force mode is NOT enabled** (default): Do **NOT** automatically retry with `--force`. Instead:
   - Report which tools/patterns could not be changed due to Coding Standard enforcement
   - List the specific Coding Standards that are blocking the changes
   - Use `AskUserQuestion` to ask the user: "The import was partially blocked by Coding Standards [list names]. Would you like to unlink these Coding Standards and retry with --force? This will sever the link between this repository and the organization-level standards."
   - If the user accepts → retry with `--force`
   - If the user declines → keep the partial import as-is and note the blocked changes in the results

**NEVER unlink Coding Standards without explicit user consent or the "force" invocation flag.**

**Important:** The `.codacy/codacy.config.json` file is for local use only. Committing or pushing it to the repository has NO effect on Codacy Cloud. The import command is the only way to sync local config to Cloud.

#### 6e. Post-import Cloud verification

After a successful import (or partial import), trigger reanalysis and wait for Cloud results to verify the configuration works as expected in the Cloud environment. Cloud analysis may differ from local analysis (different tool versions, containerized execution, file visibility).

**1. Trigger reanalysis and wait for completion:**

Use `--reanalyze-and-wait` to trigger reanalysis, poll automatically (every 10 seconds, up to 20 minutes), and get a delta report of issue changes by pattern, severity, and category:

```bash
codacy repository --reanalyze-and-wait -o json > .codacy/tmp/codacy-reanalysis-delta.json
```

This replaces manual polling. The CLI captures a baseline before reanalysis, waits for completion, and reports the full delta. If it times out after 20 minutes, it reports what it knows and exits — note the timeout in warnings and proceed without full Cloud verification.

**2. Fetch fresh Cloud overview and evaluate:**

Once reanalysis is complete (check the delta report), get the updated issue overview:
```bash
codacy issues -O -o json > .codacy/tmp/codacy-post-import-overview.json
```

Compare the post-import overview against the pre-import overview (`.codacy/tmp/codacy-cloud-overview.json`). For each pattern in the new overview, sorted by issue count (highest first):

- If a pattern has a **high issue count** and is **not** in the Security category and **not** Critical/High severity → it is a candidate for Cloud-side disabling
- Apply the same noise framework from Step 4b (wrong-language, convention mismatch, deduplication) using Cloud data
- For patterns that should be disabled, use the Cloud CLI:
  ```bash
  codacy pattern <toolId> <patternId> --disable
  ```
- If a disable fails due to Coding Standard enforcement, note it in warnings
- Also disable any patterns in the `cloudNoiseCloudOnly` list from Step 0c that were deferred for this moment

**4. Record Cloud verification results:**

Track all Cloud-side pattern changes in the summary under a new `cloudVerification` field:
```json
{
  "cloudVerification": {
    "reanalysisCompleted": true,
    "issuesBefore": 375,
    "issuesAfter": 280,
    "patternsDisabled": [
      {
        "patternId": "markdownlint_MD033",
        "toolId": "markdownlint",
        "reason": "Convention mismatch — 150 inline HTML issues in documentation files",
        "issueCount": 150
      }
    ],
    "warnings": []
  }
}
```

If reanalysis timed out or Cloud verification was skipped, set `reanalysisCompleted: false` and note the reason in warnings.

#### 6f. Show Cloud import results

Update the `importResults` field in `.codacy/configure-codacy-summary.json` with the import outcome:

```json
{
  "importResults": {
    "status": "success | completed_with_errors | failed",
    "toolsConfigured": 10,
    "toolsEnabled": ["markdownlint"],
    "toolsDisabled": ["PMD"],
    "errors": [
      {
        "toolId": "ESLint9",
        "error": "Conflict (409)",
        "detail": "Unable to update Project Tool Patterns, repository is using a Configuration File"
      },
      {
        "toolId": "PMD",
        "error": "Conflict (409)",
        "detail": "Cannot disable a tool that is enabled by a standard"
      }
    ],
    "warnings": [
      "7 Semgrep pattern parsing errors (non-blocking)",
      "Agentlinter: 0 files matched — no agent config files in this SPA"
    ],
    "codingStandards": ["AI Policy", "Our Default + SOC2"],
    "forceUsed": false
  }
}
```

**`importResults` field reference:**
- `status` — `"success"` if all tools imported without errors, `"completed_with_errors"` if some tools failed but others succeeded, `"failed"` if the import command itself failed
- `toolsConfigured` — number of tools successfully configured
- `toolsEnabled` — tools that were newly enabled in Cloud (were disabled before)
- `toolsDisabled` — tools that were disabled in Cloud (were enabled before) — may be empty if Coding Standard prevents disabling
- `errors` — array of per-tool errors, each with `toolId`, `error` (HTTP status or error type), and `detail` (the error message from the CLI)
- `warnings` — array of non-blocking warnings (analysis errors, tools with 0 files, etc.)
- `codingStandards` — names of Coding Standards linked to the repository (from Step 0), or empty array if none
- `forceUsed` — whether `--force` was used to unlink a Coding Standard

Present the import results to the user:
- What was updated successfully
- What couldn't be changed (Coding Standard enforcement) — list each error with its detail
- Cloud-only tool pattern changes (from 6c)
- Whether `--force` was used and what that implies

### Step 7: Clean-up

Remove the temporary directory and all intermediate files:

```bash
rm -rf .codacy/tmp
```

