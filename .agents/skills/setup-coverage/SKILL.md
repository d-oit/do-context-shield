---
name: setup-coverage
description: Sets up test coverage reporting in a repository and configures upload to Codacy. Detects testing frameworks, CI/CD pipelines, and coverage gaps, then adds the missing pieces to generate and upload coverage reports. Use whenever the user wants to set up coverage, add coverage reporting, integrate coverage with Codacy, fix missing coverage uploads, troubleshoot coverage not showing up, or configure CI to send coverage data. Also trigger when the user mentions test coverage, code coverage, coverage reports, or wants to know why Codacy shows no coverage for their repo.
license: MIT
metadata:
  author: Codacy
  version: 1.2.0
---

# Setup Coverage

> **Glossary:** See [glossary.md](../../references/glossary.md) for shared definitions of Codacy concepts (issues, findings, severity, coverage, tools, patterns, etc.).

This skill sets up test coverage reporting in a repository and configures automatic upload to Codacy. It detects what exists, identifies what is missing, and fills the gaps.

## Prerequisites

- `CODACY_PROJECT_TOKEN` or `CODACY_API_TOKEN` must be available for coverage uploads (see [Authentication](references/workflow.md#authentication))
- The repository must be added to Codacy

## Workflow details

Use [the coverage workflow reference](references/workflow.md) for test and CI discovery, coverage generation, secure upload, verification, and troubleshooting.

## Rationalizations

| Rationalization | Reality |
|---|---|
| "Tests pass, so coverage must be uploaded." | Verify report generation, upload status, and the result shown by Codacy. |
| "A token in a workflow file is convenient." | Keep credentials in the CI secret store; never commit tokens. |

## Red Flags

- [ ] The report path, format, or upload step is not verified in CI.
- [ ] A token is hard-coded, echoed, or included in an artifact.
- [ ] Coverage is claimed from test execution alone without a confirmed upload.
