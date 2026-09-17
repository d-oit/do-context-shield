---
name: private-data
description: >
  Sanitize sensitive coding context locally before sending it to an external model or tool,
  then restore placeholders only after the response returns. Use when context may contain
  personal data, credentials, secrets, customer data, or private URLs, or when asked to
  "sanitize context", "redact PII", "inspect sensitivity", or "restore placeholders".
category: security
license: MIT
compatibility: Works with any coding client that can execute shell tools or MCP stdio servers. Requires the do-context-shield binary. No network access.
metadata:
  author: d-oit
  version: "2.0"
  tags: privacy sanitization pii secrets mcp local-first
---

# Private Data Skill

Use `do-context-shield` as a local privacy boundary when coding context may contain personal data, credentials, secrets, customer data, private URLs, or other sensitive information.

## Default workflow

1. Keep source text local.
2. Prefer the `private.inspect`, `private.sanitize`, and `private.restore` MCP tools when the coding client supports MCP (register `do-context-shield mcp-stdio` as a local stdio server, see `docs/client-integration.md`).
3. Otherwise call `do-context-shield inspect` when sensitivity is unclear.
4. Call `do-context-shield sanitize --session <stable-session-id>` before sending context to an external model/tool. Add `--detector gliner2 --model-dir <dir>` for local NER instead of regex (requires a local ONNX export and a binary built with `--features gliner2`; see below).
5. Send **only the sanitized text** to the model/tool.
6. After the response, call `private.restore` or `do-context-shield restore --session <same-session-id>` only when placeholders need to become original values again.
7. Never paste the vault mappings into model context.

## Important rules

- Never send the raw input to a remote model before sanitization.
- Never log raw input, mappings, or restored secrets.
- Treat secrets as redacted data, not reversible pseudonyms.
- Keep one stable session id per agent task so repeated entities get stable pseudonyms.
- Do not assume regex detection is complete. For names, addresses, source-code secrets, or domain-specific entities, install a stronger detector plugin (see `plugin-development` skill).
- The skill does not choose an LLM provider. The coding client remains responsible for model selection.

## GLiNER2 detector (optional, Rust-only)

```bash
printf '%s' 'Email Alice at alice@example.com' \
  | do-context-shield sanitize --session issue-123 \
      --detector gliner2 --model-dir ~/.local/share/do-context-shield/gliner2-onnx
```

- The model directory must hold a local single-file token-classification ONNX export (`model.onnx`, `tokenizer.json`, `config.json`); multi-fragment boundary exports are rejected with guidance. Models are never fetched automatically — expect roughly 600MB–1.1GB downloaded once, outside this tool.
- With the `load-dynamic` ONNX backend, point `ORT_DYLIB_PATH` at a local ONNX Runtime 1.23+ library when the session fails to load.
- Without a configured model the detector fails closed (non-zero exit, no entities) rather than passing text through unsanitized. Fall back to `--detector regex` explicitly if no model is available.

## Example

```bash
printf '%s' 'Email Alice at alice@example.com' \
  | do-context-shield sanitize --session issue-123
```

Expected shape:

```text
Email Alice at __DO_PRIVATE_EMAIL_1__
```

The agent may send that sanitized value to the selected model. A long-running MCP server keeps mappings in-process; separate CLI processes require the same explicit `--vault-file` for restoration.
