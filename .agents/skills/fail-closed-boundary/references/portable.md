# Portable Fail-Closed Boundary Review Checklist

Language-neutral safety checklist for reviewing and implementing fail-closed privacy boundaries in context sanitization pipelines.

## Scope & Applicability

Use this checklist when changing, extending, or reviewing privacy boundary layers (detection, semantic judging, policy evaluation, transformation, vault persistence, or pipeline orchestration).

## Stage Ownership

| Stage | Responsible For | Never Allowed To |
|---|---|---|
| Detector | Identifying candidate entity spans, kinds, and confidence scores | Invent replacement values or modify text |
| Semantic Judge (Optional) | Classifying candidates with labels and confidence scores | Return text/spans or loosen secret redaction |
| Policy | Deterministically deciding actions per entity | Leave entities undecided or loosen secret redaction |
| Transformer | Rewriting text and emitting vault mappings | Keep values flagged for replacement or leak raw values |
| Vault | Scope-isolated reversible token store | Resolve tokens across different session scopes |
| Pipeline | Stage validation and error handling | Pass unvalidated text or swallow stage failures |

## Fail-Closed Method & Rules

1. **Deterministic Decision Priority**:
   - Secrets and credentials always redact first regardless of judge or policy input.
   - Judge labels (`test`/`business`) may keep non-secret entities only when confidence thresholds are satisfied.
   - Abstention or judge errors fall back to kind-based redaction/pseudonymization — never keep.

2. **Strict Output Validation**:
   - Validate stage output before downstream consumption.
   - Reject out-of-bounds spans, non-UTF-8 boundaries, mismatched slice values, duplicate decisions, or unresolvable placeholders.
   - Any stage error, timeout, or invalid output must halt execution immediately (fail closed).

3. **Egress & Log Protection**:
   - Never echo raw matched values in error messages, logs, or diagnostic stderr.
   - Scrub stage error strings of known original values before surfacing them.

4. **Scope Isolation**:
   - Placeholder restoration must be strictly scoped to the exact session ID and vault instance.

## Environment & Adopter Adaptations

- **Language Neutrality**: Adapt pipeline error types and stage contracts to adopter runtime paradigms (e.g. exceptions, Result types, or status codes).
- **No-Shell / Container Policies**: Implement process communication via structured IPC (e.g. JSON over stdio) bounded by strict timeouts and message size caps.

## Boundary Disclaimer

This checklist establishes architectural requirements for fail-closed privacy boundaries. Checklist adherence alone does not prove all runtime code paths fail closed without automated unit, integration, and fuzz testing.
