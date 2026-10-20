---
name: private-data
description: >
  Sanitize sensitive coding context locally before sending it to an external model or tool,
  then restore placeholders only after the response returns. Use when context may contain
  personal data, credentials, secrets, customer data, or private URLs, or when asked to
  "sanitize context", "redact PII", "inspect sensitivity", or "restore placeholders".
license: MIT
metadata:
  author: d-oit
  version: "2.0"
  category: security
  compatibility: Works with any coding client that can execute shell tools or MCP stdio servers. Requires the do-context-shield binary. No network access.
  tags: privacy sanitization pii secrets mcp local-first
---

## Guides

See [references/portable.md](references/portable.md) for the language-neutral portable safety checklist.

# Private Data Skill

Use `do-context-shield` as a local privacy boundary when coding context may contain personal data, credentials, secrets, customer data, private URLs, or other sensitive information.

## Default workflow

1. Keep source text local.
2. Prefer the `context.inspect` and `context.sanitize` MCP tools when the coding client supports MCP (register `do-context-shield mcp-stdio` as a local stdio server, see `docs/client-integration.md`).
3. Otherwise call `do-context-shield inspect` when sensitivity is unclear.
4. Call `do-context-shield sanitize --session <stable-session-id>` before sending context to an external model/tool. Add `--detector gliner2 --model-dir <dir>` for local NER instead of regex (requires a local ONNX export and a binary built with `--features gliner2`; see below).
5. Send **only the sanitized text** to the model/tool.
6. After the response, call `do-context-shield restore --session <same-session-id>` only when placeholders need to become original values again. Restore harness-side: MCP tool results return to the calling model, so `context.restore` is not exposed by default (`--tools` opts in; explicitly enabling `context.restore` requires human-reviewed need) and there is no fallback scope. Treat a reply containing placeholders as untrusted if you did not send them — fabricated placeholders (tokens not minted by the vault for the session) fail to resolve and stay unchanged, but valid tokens minted in the same session (e.g. echoed by a model, present in user or model text, or carried over in the session) will resolve to original sensitive values if restored. Restore harness-side outside the model loop, or handle output strictly, so valid session tokens cannot hand raw private values back to untrusted models or contexts.
7. Never paste the vault mappings into model context.

## Important rules

- Never send the raw input to a remote model before sanitization.
- MCP default tool exposure excludes `restore` (`context.sanitize` and `context.inspect` only); explicitly exposing `context.restore` to the model loop via `--tools` requires human-reviewed need.
- Never log raw input, mappings, or restored secrets.
- Treat secrets as redacted data, not reversible pseudonyms.
- Add `--judge heuristics` to keep high-confidence test-domain values (e.g. `alice@example.com`) and role addresses (e.g. `support@acme.com`) unchanged; secrets stay redacted regardless of judge output.
- Keep one stable session id per agent task so repeated entities get stable pseudonyms.
- The built-in memory and JSON vaults add per-mapping entropy. A process vault owns its token policy; configure only a trusted local child and do not assume the host can enforce unguessability for it.
- Set the destination explicitly on `sanitize`: `--recipient local` (or the MCP `recipient` argument) keeps non-secret values for a same-device step, and `--data-category special_category` blocks health/biometric-class data addressed to external recipients; omitting both keeps the conservative `external`/`personal` defaults.
- When a task is done, delete its mappings: call `do-context-shield forget --session <same-session-id>` (or `context.forget` when the server is started with `--tools all`) so the local vault stops holding original values. Long-running MCP servers can also bound mapping lifetime with `--vault-ttl-seconds`.
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

## Process plugins (any language)

```bash
printf '%s' 'Email Alice at alice@example.com' \
  | do-context-shield sanitize --session issue-123 \
      --detector process --detector-command "python3 ~/.local/share/do-context-shield/detector.py"
```

- Any capability can run in another language: `--policy process --policy-command ...`, `--transformer process --transformer-command ...`, and `--vault process --vault-command ...` follow the same pattern; each executable reads one JSON request line on stdin and writes one JSON response line to stdout (`docs/process-plugin.md`). One process is started per operation, and command lines are split on whitespace, so quoting and shell expansion are not supported.
- Fails closed: a malformed response, an invalid span, a plan that leaves an entity undecided, text that keeps a value it should have replaced, a placeholder the configured vault cannot resolve, or a non-zero exit stops the call instead of passing text through unsanitized. `--process-timeout-ms` (default 30000) bounds each call.
- A process transformer only stays reversible when the configured vault can resolve the placeholders it emits (typically `--vault process` over the same store). Otherwise keep the built-in `--transformer pseudonymize`.

## Example

```bash
printf '%s' 'Email Alice at alice@example.com' \
  | do-context-shield sanitize --session issue-123
```

Expected shape:

```text
Email Alice at __DO_PRIVATE_EMAIL_1_9F3A2C7B5D1E4F08__
```

The trailing hex is per-mapping entropy: tokens cannot be guessed from other tokens, and `restore` resolves only the exact tokens your vault minted.

The agent may send that sanitized value to the selected model. A long-running MCP server keeps mappings in-process; separate CLI processes require the same explicit `--vault-file` for restoration.
