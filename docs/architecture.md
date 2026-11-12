# Architecture

## Boundary

The project has four layers:

1. `plugin-api` — stable contracts.
2. concrete plugins — detection, judging, policy, transformation, vault implementations.
3. `do-context-shield-core` — composition and invariants.
4. adapters — CLI and MCP stdio.

No provider SDK belongs in the runtime core.

## Replacement model

A plugin is selected by logical name in `plugin-registry` (the file-backed JSON vault additionally takes its storage path, `registry::json_vault(path)`). Detection, policy, transformation, and storage all ship compiled-in implementations, which keeps the ABI surface small and portable.

Any of them can instead run behind a process protocol (newline-delimited JSON over stdin/stdout, `docs/process-plugin.md`) rather than a Rust dynamic-library ABI: `crates/plugin-process` provides detector, judge, policy, transformer, and vault adapters that drive a user-configured local executable, so an implementation stays replaceable across Rust, compiler, and libc versions — and across languages. The CLI exposes them per subcommand rather than everywhere: `sanitize` and `mcp-stdio` carry the detector/policy/transformer/judge selection plus `--vault`, `inspect` carries the detector selection, and `restore`/`forget` carry the vault selection — every subcommand takes `--process-timeout-ms`.

## Semantic judging

Detection is context-blind by nature: a regex cannot tell a private address from a role address or a reserved test domain. An optional `SemanticJudge` stage between detection and policy lets a local rules engine, a local model, or a hosted judge label, score, or abstain per candidate. Models may classify, select, score, or abstain — they never generate the protected value: deterministic code owns spans, transformations, policy, and restoration. Judging is off by default and selected with `--judge`; it can never weaken secret redaction.

## Agent integration

The agent remains authoritative:

```text
agent loop
   |
   +-- context.sanitize --> local process
   |
   +-- remote model/tool receives sanitized context
   |
   +-- context.restore  --> local process
```

MCP and skill files are adapters, not a second agent runtime.

## Threat model

Integrators should read this section before deploying any adapter. It states what
the engine protects, from whom, and — just as importantly — what it does not.

### Assets

- **Original sensitive values** in coding context: personal data, credentials and
  secrets, special-category data, private URLs.
- **Vault mappings** that map placeholders back to originals.
- **Audit records**, which describe operations without carrying the values.
- **Boundary integrity**: no stage silently degrades into a passthrough.

### Trust boundaries

```text
untrusted: coding context, model output, MCP request payloads, plugin responses
trusted:   the operator's machine and account, the configured binary,
           the plugin executables the operator installs, the local vault and key files
```

The engine mediates text *inside* one machine. It does not mediate the network,
the model provider, or the coding client's tool-authorization decisions.

### Attacker capabilities in scope

- Text reaching `sanitize`/`inspect` is attacker-chosen: fake credentials and
  secrets, prompt-injection instructions, text crafted to evade detection.
- An MCP client sends malformed, oversized, batched, or metadata-inconsistent
  JSON-RPC frames, and makes concurrent or repeated calls.
- A configured process plugin returns malformed, oversized, delayed, or hostile
  responses (keeping a secret, inventing tokens, editing text outside the planned
  spans).
- A model returns placeholders it did not receive, attempting to make `restore`
  resolve a real value.

### Guarantees (each maps to an invariant or test)

- **Fail closed.** Every stage either produces a validated result or the call
  fails; text never continues unchecked.
- **Secrets redact first.** A judge label or policy decision cannot keep or
  pseudonymize a secret-like kind.
- **Validation before use.** Detector spans, judge indices and confidences,
  policy decisions, and transformer output are validated before the next stage,
  and plugin output is validated before anything is stored.
- **Scope isolation.** Mappings resolve only in the session scope that created
  them; `delete_scope` and TTL expiry remove them.
- **Redacted observability.** CLI and MCP results, audit events, and stage error
  text never carry matched values; a plugin that formats input into its error
  cannot leak it.
- **Tamper-evident audit.** The opt-in audit file is a versioned SHA-256 hash
  chain (sequence, previous hash, record hash) verified in full before any
  append; `verify-audit` detects modification, deletion, truncation, and
  reordering and reports only a record index plus a safe category. Legacy v1
  files are never rewritten or upgraded, and rotation is opt-in.
- **Bounded transports.** MCP stdio frames are bounded
  (`DEFAULT_MAX_REQUEST_BYTES`, 4 MiB) before JSON parsing, JSON-RPC batch arrays
  are rejected, and method parameters are validated before dispatch.
- **No network.** Runtime crates perform no network calls and carry no hosted
  model SDK.

### Capability matrix

| Capability | What it is | What it is not |
|---|---|---|
| Structured PII/credential detection | `detector-regex` recognizes selected formats (emails, checksum-gated card numbers, many credential shapes) and reports spans | not complete DLP; unknown formats and free-form names are missed |
| Local semantic NER | `detector-gliner2`/`hybrid` add model-dependent entity recall from a local ONNX export | recall depends on the model and label set; no guarantee of complete coverage |
| Prompt-injection / untrusted-instruction handling | **not a security boundary**; sanitization rewrites detected spans only and leaves instructions intact | does not neutralize prompt injection, jailbreaks, or hidden instructions |
| Authorization of downstream tool calls | outside this product | does not decide which tools a model may call or which data a tool may read |
| Model-output handling | caller/harness responsibility | does not validate the model's answer, proposed tool arguments, or the truth of returned data |
| Protection at rest | encrypted JSON vault (opt-in key file), owner-private audit file | does not protect against the same local user/process, a compromised account, backups, or swap |

### Deployment profiles

| Profile | Useful for | Operator responsibilities |
|---|---|---|
| CLI one-shot (`sanitize`/`restore`/`inspect`/`forget`) | scripts and harness code that can hold the raw text | keep the vault path and any key file owner-only; delete mappings with `forget` when a task ends |
| MCP stdio server | model-facing sanitize/inspect inside a coding client | leave the default `--tools` surface; restore harness-side; pin `--config` and use an absolute binary path; do not let a project directory configure the server |
| Encrypted JSON vault (`--vault-file` + `--vault-key-file`) | restoration across process restarts | key file mode `0600`; exclude the vault, key, backups, and snapshots from anything that leaves the machine; treat encryption as at-rest only |
| Audit logging (`--audit-file`) | operator review of operations | keep it owner-private; use `verify-audit` to detect tampering; set `--audit-max-records`/`--audit-max-bytes` to rotate (otherwise it grows without bound); a same-account attacker can rebuild the whole chain, so integrity is tamper-evident, not tamper-proof |
| Process plugins (`--*-program`/`--*-arg`) | non-Rust or custom stages | install only trusted executables from paths only you can write; process isolation is not sandboxing; a process transformer may edit text outside planned spans |
| `gliner2`/`hybrid` detector | local semantic NER | provide a local model export and ONNX Runtime; run the readiness probe before routing private content; a missing model fails closed, it does not fall back to regex |

### Additional trust notes

- **Plugins are trusted local software.** A plugin's executable path and code are
  as trusted as the binary itself. Responses are validated and the child gets no
  shell, but *process isolation is not sandboxing*: the child runs with the same
  user's filesystem and network permissions and can read the vault and key files.
  A transformer receives text outside the planned entities as **trusted** input
  and may rewrite it (`docs/process-plugin.md`); do not point a process
  transformer at a plugin you would not trust with the raw text.
- **`context.restore` returns originals.** MCP tool results go back to the calling
  model, so restore is off in the model-facing default (`--tools` opts in) and
  `context.restore` requires an explicit session. Restoration belongs in trusted
  harness code after the model reply returns; treat a reply containing
  placeholders you did not send as hostile, because `restore` resolves any
  well-formed token the vault holds.
- **Encryption is at-rest only.** An encrypted JSON vault protects the file on
  disk, not a running process or the account that can read the key file. On Unix
  the key file must be owner-only (mode `0600`).
- **Audit files are tamper-evident, not tamper-proof.** Each record is
  hash-chained and the chain is verified before every append and by
  `verify-audit`, so modification, deletion, truncation, and reordering are
  detected — but a writer with the same account can rewrite the whole file and
  rebuild a consistent chain. Unbounded logging grows without limit unless the
  operator configures rotation.
- **Preflight is diagnostic.** A readiness probe reports whether a local model is
  configured and loadable; it never downloads assets, never prints model
  contents, and never downgrades a missing detector to regex.

## Non-goals

- LLM routing.
- Provider billing/quotas.
- Cloud telemetry.
- Owning the coding agent's plan/execute loop.
- Detecting or neutralizing prompt injection.
- Authorizing downstream tool calls.
