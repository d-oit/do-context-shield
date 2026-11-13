# Codacy glossary

This project-local excerpt keeps the imported skill references resolvable. For full and current definitions, see the [upstream Codacy glossary](https://github.com/codacy/codacy-skills/blob/master/references/glossary.md).

## Provider

The Git hosting service connected to Codacy. CLI values: GitHub `gh`, GitLab `gl`, and Bitbucket `bb`.

## Organization

The Codacy organization corresponding to a Git provider organization or a user's personal account. It contains repositories and members.

## Repository

A source repository registered with a Codacy organization and analyzed by Codacy Cloud.

## Issue

A code-quality problem reported by an analysis tool and pattern. Issues have severity and category; Codacy's local JSON uses values such as `Error`, `High`, `Warning`, and `Info`.

## Severity

A priority assigned to an issue or security finding. Issue values are `Error` (Critical), `High`, `Warning` (Medium), and `Info` (Minor). Security findings use `Critical`, `High`, `Medium`, and `Low`.

## Finding

A security-specific result, tracked separately from general code-quality issues. Finding sources include SAST, software composition analysis, exposed secrets, infrastructure-as-code, and dynamic scanning.

## Tool

A static-analysis engine such as Semgrep, ESLint, or Trivy. A tool can be configured but unavailable locally; inspect `toolResults` and `capability.unavailable` before claiming an analysis is complete.

## Pattern

A rule within a tool that detects a particular issue. Patterns may have severity, category, and tunable parameters.

## Coverage

The fraction of coverable source lines exercised by tests. Codacy displays uploaded reports; the project must generate and upload coverage data through its CI workflow.

## Local and Cloud CLIs

`codacy-analysis` runs configured tools locally and returns machine-readable analysis results. `codacy` queries and manages remote Codacy Cloud data, including PR coverage, quality gates, findings, tools, and patterns. Local analysis does not prove Cloud status or results.
