# Portable Private Data Handling Checklist

Language-neutral, tool-agnostic safety checklist for sanitizing sensitive coding context locally before sending it to an external model or tool, and restoring placeholders only after the response returns.

## Scope & Applicability

Use this checklist whenever agent workflows handle personal data, credentials, secrets, customer data, internal URLs, or private system metadata, regardless of programming language or client framework.

## Abstract Workflow

1. **Local-First Pre-Flight Scan**:
   - Keep raw source text local.
   - Identify sensitive categories (credentials, secrets, PII, special-category data).
   - Check destination trust context (local same-device vs. external model/tool).

2. **Sanitization Prior to Egress**:
   - Sanitize text locally using a local boundary process, MCP stdio tool, or native runtime adapter before sending it to an external endpoint.
   - Treat credentials and secrets as non-reversible redacted data (never reversible pseudonyms).
   - Treat personal identifiers as reversible pseudonyms bound to a stable session identifier.
   - Transmit **only the sanitized payload** to external models or tools.

3. **Response Handling & Post-Processing**:
   - Treat model-returned or user-supplied text containing placeholders as untrusted.
   - Perform placeholder restoration strictly harness-side (outside the model's direct context window) only when raw values are required by local execution.
   - Ensure placeholder resolution matches exact tokens minted in the same explicit session scope. Un-minted or fabricated tokens must not resolve.

4. **Session Lifecycle & Cleanup**:
   - Delete session vault mappings (`forget` / purge) immediately upon task conclusion or session timeout.

## Environment & Adopter Adaptations

- **Language & Command Neutrality**: Adopters adapt invocation mechanics to their environment (e.g., CLI subprocesses, MCP stdio tools, or language bindings). Do not assume Rust CLI availability or shell execution support.
- **No-Shell Policies**: In environments prohibiting shell execution (e.g. strict TypeScript or container environments), context sanitization must run via direct stdio RPC, process IPC, or linked library bindings.

## Boundary Disclaimer

This portable checklist guides local agent behavior and sanitization rules. Following this generic checklist does not mechanically guarantee or prove that client integrations are actually sanitizing context; adopters must verify their specific runtime integration through computational tests.
