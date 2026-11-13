# Tool-specific tuning and security guardrail
## Per-tool tuning tips

### Semgrep

Semgrep ships patterns for 30+ languages. After init, many patterns will be for languages not in the project. In Step 4, **disable patterns for languages not found by `discover`** — this is usually the single biggest noise reduction. Cross-reference the pattern ID prefix (e.g., `python.`, `javascript.`, `java.`) against the discovered languages.

### Lizard (complexity)

Lizard has rules for cyclomatic complexity (CCN), lines of code (NLOC), and parameter count, each at three severity levels (Critical, Medium, Minor) with configurable `threshold` parameters.

For **established/mature codebases**, the default Medium thresholds produce hundreds of hits on legacy code. Options:
- Disable Medium-level rules and keep only Critical
- Or raise Medium thresholds to match the project's actual complexity profile (better — preserves visibility)

For **greenfield projects**, the default thresholds are reasonable.

### ESLint9

ESLint loads the project's own config file (e.g., `eslint.config.js`), which may import packages. If the project has an existing ESLint config, the `--install-dependencies` flag in Step 3 should handle this. If ESLint still fails with `InvocationError`, the project may need `npm install` or equivalent before analysis.

If the project has a pre-existing ESLint configuration and the user wants to keep it, set `useLocalConfigurationFile: true` on the ESLint9 tool entry instead of using Codacy's managed patterns.

### markdownlint

Rules like MD034 (bare URLs), MD024 (duplicate headings), MD010 (hard tabs), MD004 (list style), MD033 (inline HTML), and MD036 (emphasis as heading) fire heavily on CHANGELOGs and auto-generated docs. These are stylistic, not bugs. Prefer excluding the noisy files (via per-tool `exclude`) over disabling the rules entirely.

### Stylelint

Review results in context — some CSS rules that look like violations may be intentional (e.g., apps that override third-party styles often need `!important` and qualified selectors). When the project has a pre-existing Stylelint config, consider using `useLocalConfigurationFile: true`.

## Security guardrail

> **Every security concern must be covered by at least one active pattern.** This is a hard rule with no exceptions.

The guardrail operates at the **concern level**, not the individual pattern level. If two tools both detect "hardcoded secrets," disabling the less precise one is acceptable because the concern remains covered. However, if a security concern (e.g., SQL injection, XSS, path traversal, hardcoded secrets) would lose ALL active pattern coverage, the disable must be reverted.

When a security pattern is noisy and cannot be deduplicated:
- **Exclude specific files** where it triggers false positives (e.g., test fixtures, mock data)
- **Leave the false positives** for the user to triage in Codacy Cloud (they can ignore individual instances with a reason)
- **Never remove the last pattern covering a security concern** — it must stay active to catch real vulnerabilities in future code

For Critical/High severity patterns in non-Security categories, apply the same caution: prefer file exclusion over pattern disabling. Only disable these if they are clearly for the wrong stack (e.g., a Java Critical pattern in a pure Python project).
