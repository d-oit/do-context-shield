---
name: configure-codacy
description: Tailors Codacy configuration to a project by discovering its stack, enabling the right tools and patterns, running analysis, and intelligently reducing noise — disabling irrelevant or noisy patterns, tuning thresholds, and excluding files that shouldn't be analyzed. Produces a machine-readable summary of all changes. Use whenever the user wants to configure Codacy, reduce noise, fix false positives, enable or disable tools or patterns, tune code quality rules, deal with too many warnings, or align Codacy with their project's conventions. Also trigger when the user complains about irrelevant issues, noisy linters, or wants to set up Codacy for the first time on a repo.
license: MIT
metadata:
  author: Codacy
  version: 4.3.0
---

# Configure Codacy

Configure local Codacy analysis from repository evidence. Use `configure-codacy-cloud` only for a repository already registered and analyzed on Codacy Cloud.

## Workflow

- Read [setup and discovery](references/setup-and-discovery.md) before choosing local or Cloud behavior.
- Use [data-driven tuning](references/tuning.md) and preserve at least one active pattern for every security concern.
- Follow [results and Cloud import](references/results-and-cloud-import.md) for validation, reporting, and optional import.
- Read [tool-specific guidance](references/tool-tuning.md) when changing thresholds, exclusions, or security patterns.

Keep local `.codacy/` artifacts separate from Cloud configuration. Never disable the last active pattern covering a security concern or hide valid Critical/High findings to reduce noise.

## Rationalizations

| Rationalization | Reality |
|---|---|
| "Disabling noisy patterns is the fastest way to get a clean report." | Tune only after reviewing evidence; preserve active coverage for every security concern. |
| "A local config change also updates Codacy Cloud." | Local and Cloud configurations are separate; import only through the documented flow. |

## Red Flags

- [ ] A valid Critical/High finding or the last security pattern is being hidden.
- [ ] Exclusions or thresholds are proposed without repository evidence.
- [ ] Organization-enforced rules are changed or a Cloud import is assumed.
