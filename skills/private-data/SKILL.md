---
name: private-data
description: Sanitize sensitive coding context locally before sending it to an external model or tool, then restore placeholders only after the response returns.
---

# Private Data Skill

Use `do-context-shield` as a local privacy boundary when coding context may contain personal data, credentials, secrets, customer data, private URLs, or other sensitive information.

## Default workflow

1. Keep source text local.
2. Prefer the `private.inspect`, `private.sanitize`, and `private.restore` MCP tools when the coding client supports MCP.
3. Otherwise call `do-context-shield inspect` when sensitivity is unclear.
4. Call `do-context-shield sanitize --session <stable-session-id>` before sending context to an external model/tool.
5. Send **only the sanitized text** to the model/tool.
6. After the response, call `private.restore` or `do-context-shield restore --session <same-session-id>` only when placeholders need to become original values again.
7. Never paste the vault mappings into model context.

## Important rules

- Never send the raw input to a remote model before sanitization.
- Never log raw input, mappings, or restored secrets.
- Treat secrets as redacted data, not reversible pseudonyms.
- Keep one stable session id per agent task so repeated entities get stable pseudonyms.
- Do not assume regex detection is complete. For names, addresses, source-code secrets, or domain-specific entities, install a stronger detector plugin.
- The skill does not choose an LLM provider. The coding client remains responsible for model selection.

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
