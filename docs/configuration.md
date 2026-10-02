# Configuration file

Status: implemented (`crates/do-context-shield-cli/src/config.rs`). Every option here also has a CLI flag; the file only supplies defaults.

## Where the file is found

1. `--config <path>` (accepted before or after the subcommand),
2. `./do-context-shield.toml`,
3. `$HOME/.config/do-context-shield/config.toml`.

The first existing candidate wins. Without any file, every option keeps its built-in default. A candidate that exists but cannot be read or parsed is an error — the tool never falls back to defaults silently, and a candidate of that name that is not a regular file (a directory, a dangling symlink) is such an error rather than an absent one. A missing `--config` path is an error too: the explicit path is an instruction, while an absent auto-discovery candidate is simply not selected.

The one-shot commands use this search. `mcp-stdio` reads a file only when `--config <path>` names it: MCP clients spawn the server with the project as its working directory, so a repository shipping `do-context-shield.toml` could otherwise select `process` plugins, loosen `[context]`, or expose `context.restore` merely by being the server's cwd. Without `--config` the MCP server starts from the built-in defaults (trusted `DO_CONTEXT_SHIELD_*` environment overrides still apply); register it as `do-context-shield mcp-stdio --config /absolute/trusted/config.toml`.

Paths in the file are literal: environment variables and `~` are not expanded.

## Precedence

CLI flag > environment variable > file value > built-in default. A flag passed for one invocation therefore overrides the file without editing it, and the environment overrides below cover container/CI deployments that cannot mount a file.

## Environment overrides

Every variable is optional; an unset or empty variable keeps the file value. Values are validated exactly like file values, with the error naming the variable.

| Variable | Field |
| --- | --- |
| `DO_CONTEXT_SHIELD_DETECTOR` | `[plugins] detector` |
| `DO_CONTEXT_SHIELD_POLICY` | `[plugins] policy` |
| `DO_CONTEXT_SHIELD_TRANSFORMER` | `[plugins] transformer` |
| `DO_CONTEXT_SHIELD_JUDGE` | `[plugins] judge` |
| `DO_CONTEXT_SHIELD_TOOLS` | `[plugins] tools` (`mcp-stdio` only) |
| `DO_CONTEXT_SHIELD_VAULT` | `[vault] vault` |
| `DO_CONTEXT_SHIELD_VAULT_FILE` | `[vault] vault_file` |
| `DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS` | `[vault] vault_ttl_seconds` |
| `DO_CONTEXT_SHIELD_VAULT_KEY_FILE` | `[vault] vault_key_file` |
| `DO_CONTEXT_SHIELD_AUDIT_FILE` | `[audit] audit_file` |
| `DO_CONTEXT_SHIELD_RECIPIENT` | `[context] recipient` |
| `DO_CONTEXT_SHIELD_DATA_CATEGORY` | `[context] data_category` |
| `DO_CONTEXT_SHIELD_PURPOSE` | `[context] purpose` |
| `DO_CONTEXT_SHIELD_JURISDICTION` | `[context] jurisdiction` |

## Reference

### `[plugins]`

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `detector` | `regex`, `gliner2`, `hybrid`, `process` | `regex` | |
| `policy` | `default`, `matrix`, `process` | `default` | `matrix` reads `[policy_matrix]` |
| `transformer` | `pseudonymize`, `generalize`, `mask`, `process` | `pseudonymize` | `generalize`/`mask` are non-reversible: no vault writes, no restorable output |
| `judge` | `heuristics`, `process` | unset | judging is optional and off by default |
| `tools` | `sanitize`, `restore`, `inspect`, `forget`, `all` (comma-separated) | `sanitize,inspect` | `mcp-stdio` only; pins the exposed MCP tool surface in the file (equivalent to `--tools`) |
| `model_dir` | path | unset | `gliner2`/`hybrid` ONNX export directory |
| `detector_command` | command line | unset | required with `detector = "process"` |
| `policy_command` | command line | unset | required with `policy = "process"` |
| `transformer_command` | command line | unset | required with `transformer = "process"` |
| `judge_command` | command line | unset | required with `judge = "process"` |

Command lines are split on whitespace; quoting and shell expansion are not supported (`docs/process-plugin.md`).

### `[policy_matrix]`

Configuration for the opt-in `matrix` policy (`plugins.policy = "matrix"`, or
`--policy matrix` on the command line). It is never the built-in default: the
conservative `default` policy makes no adequacy or purpose assumptions. The
matrix implements the jurisdiction-pairing and purpose-mapping decisions the
default deliberately leaves to an operator.

| Key | Values | Default |
| --- | --- | --- |
| `origin` | ISO 3166-1 alpha-2 code | unset |
| `adequate_jurisdictions` | list of ISO 3166-1 alpha-2 codes | empty |
| `enforce_adequacy_for_trusted` | boolean | `true` |
| `purpose_rules` | array of tables (below) | empty |

Adequacy is a **pair** decision: a destination is adequate for
special-category data only when it is the declared `origin` itself (not a
cross-border transfer) or a member of `adequate_jurisdictions`. With
`origin` unset no destination is adequate, so special-category data to a
trusted recipient fails closed — an unconfigured matrix is never looser than
the default policy. Codes are normalized to uppercase, so `fr` and `FR` are
the same destination. External and unknown recipients always block
special-category data, and unknown recipients block every non-secret entity
except explicitly `non_personal` data.

`purpose_rules` are matched in declaration order for non-secret entities; the
first match decides. Each rule is a table:

| Key | Values | Default |
| --- | --- | --- |
| `purpose` | string, matched exactly against the enforcement context `purpose` | required |
| `data_category` | `non_personal`, `personal`, `special_category` | any |
| `recipients` | list of `local`, `trusted`, `external`, `unknown` | any |
| `action` | `keep`, `pseudonymize`, `block` | required |

```toml
[plugins]
policy = "matrix"

[policy_matrix]
origin = "DE"
adequate_jurisdictions = ["FR", "GB"]
enforce_adequacy_for_trusted = true

[[policy_matrix.purpose_rules]]
purpose = "internal_analytics"
recipients = ["local", "trusted"]
action = "keep"

[[policy_matrix.purpose_rules]]
purpose = "forbidden_marketing"
action = "block"
```

Two invariants hold across every rule: a secret-kind entity (or one the judge
labels `Secret`) always redacts, whatever a purpose rule says; and a
`[policy_matrix]` section requires that the matrix policy is actually
selected — a file that configures the matrix while `[plugins] policy` names
another policy is rejected at startup rather than silently ignoring the
section. `purpose` text is never reported by the `config` diagnostic.

### `[vault]`

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `vault` | `memory`, `json`, `process` | `memory` | `json` when `vault_file` is set and `vault` is omitted |
| `vault_file` | path | unset | required by `vault = "json"`; selects the JSON vault on its own |
| `vault_command` | command line | unset | required with `vault = "process"` |
| `vault_ttl_seconds` | seconds | unset | memory or JSON vault; a one-shot process exits before a memory-vault lifetime matters, while a persisted JSON mapping is bounded across processes |
| `vault_key_file` | path | unset | 64-hex-character key that encrypts the JSON vault at rest; requires `vault_file`, and on Unix the key file must be owner-only |

A `vault_ttl_seconds` on the JSON vault bounds how long a persisted original
stays resolvable: every mapping is written with its timestamp, `restore` (and
any read) hides a mapping older than the TTL, and the next locked write or
`expire` purges it from the file — nothing is deleted before a full TTL
elapsed. Counters are never reset, so an expired token is never reissued for a
different value. Mappings written before a TTL was configured carry no
timestamp; they keep resolving until the first locked write stamps them, after
which the TTL applies normally. `forget` remains the immediate eraser.
### `[audit]`

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `audit_file` | path | unset | Private local append-only JSONL audit destination (`0600` on Unix). Fails closed before input if inaccessible, insecure, or aliasing vault paths |

An explicit `audit_file` records structure-only operational events (`sanitize`,
`restore`, `forget`, policy blocks) without original text, minted tokens,
vault mappings, or free-form purpose text. Retention is strictly
operator-controlled (no automatic rotation or silent truncation). On non-Unix
platforms, opting into file audit logging fails explicitly.


### `[context]`

Default enforcement context. It applies to the CLI `sanitize` call and supplies the `mcp-stdio` server default for `context.sanitize` requests that omit the arguments; a per-call argument (or CLI flag) overrides the file value field by field.

| Key | Values | Default |
| --- | --- | --- |
| `recipient` | `local`, `trusted`, `external`, `unknown` | `external` |
| `data_category` | `non_personal`, `personal`, `special_category` | `personal` |
| `purpose` | free-form string | unset |
| `jurisdiction` | ISO 3166-1 alpha-2 code | unset |

Field semantics: `recipient` and `data_category` drive the built-in default policy. `jurisdiction` is the governing regime of the transfer when the caller knows it; unset means unknown, and unknown fails closed — special-category data to a non-local recipient is blocked (external and unknown recipients always block, and a trusted recipient blocks while the jurisdiction is unset or malformed). `purpose` is free-form intent forwarded to policy plugins; the built-in default policy does not read it, and it never loosens a decision.

### `[process]`

| Key | Values | Default |
| --- | --- | --- |
| `timeout_ms` | milliseconds | 30000 |

Bounds one process-plugin response; the child is killed and reaped on timeout (`docs/process-plugin.md`).

## Per-command applicability

| Command | Reads from the file |
| --- | --- |
| `sanitize` | all sections |
| `restore` | `[vault]`, `[audit]`, `[process]`; detector/policy/transformer selections are ignored (only the vault is built, and restore only resolves placeholders) |
| `inspect` | detector keys of `[plugins]` (`detector`, `model_dir`, `detector_command`) and `[process]`; policy, transformer, audit, and vault selections are ignored |
| `forget` | `[vault]`, `[audit]`, `[process]`; detector/policy/transformer selections are ignored |
| `mcp-stdio` | all sections, but only from a file selected with `--config <path>` (auto-discovery is off); `[context]` becomes the server default for `context.sanitize` and per-call arguments override it (field by field); `[plugins] tools` sets the exposed tool surface |
| `config` | all sections: it reports the merged one-shot view (the same merge `sanitize` uses) without building a plugin or reading stdin |
| `encrypt-vault` | nothing: both paths are explicit flags, so an ambient file can never trigger an in-place rewrite |

A selection a command does not use is not built, so a plugin that cannot be constructed there (a `process` policy without a command, a JSON vault without a file) fails only the commands that run that stage — `inspect` still works with a broken `[vault]`, `forget` with a broken `[plugins]`.

The session scope never comes from the file: the vault-scoping commands (`sanitize`, `restore`, `forget`) require `--session` explicitly so mappings cannot leak across implicit scopes.

## Effective-configuration diagnostics

`do-context-shield config` prints the configuration the one-shot commands
would resolve, without running a plugin, spawning a process, reading stdin, or
touching a vault:

```bash
do-context-shield config --vault-file ~/vault.json
do-context-shield config --detector hybrid --recipient local   # inspect one invocation
```

The output is a JSON report of whitelisted settings, each with the layer that
supplied it: `cli`, `environment`, `file`, `default` (or `none` for optional
settings). The plugin names and vault kind come from the same resolution the
executing commands use, and `effective_vault` is derived from the same
classifier `sanitize` uses, so the report cannot drift from the runtime
selection; a contradictory selection fails with the identical error the
executing command would print.

```json
{
  "detector": {"value": "regex", "source": "default"},
  "judge": {"value": "heuristics", "source": "file"},
  "effective_vault": "json",
  "vault_file": {"configured": true, "source": "cli"},
  "context": {"recipient": {"value": "local", "source": "environment"}, "...": "..."},
  "process_timeout_ms": {"value": 30000, "source": "default"}
}
```

**The report is a whitelist.** It contains validated plugin and vault names,
the enforcement-context values (`recipient`, `data_category`, and the
shape-checked `jurisdiction`), numeric limits, and *presence booleans* for
path-shaped and command-shaped settings. It never contains the matched text,
raw process commands (`detector_command`, `policy_command`, … are reported as
`configured: true/false` only), filesystem paths (`vault_file`,
`vault_key_file`, `audit_file`, `model_dir`), or the free-form `purpose` value (reported as
a presence boolean), so the report is safe to paste into an agent context. The
MCP tool surface does not expose it: `config` is a CLI diagnostic, and
`[plugins] tools` is not part of this report (`mcp-stdio --help` and
`tools/list` cover the MCP surface).

## At-rest encryption

Pointing the JSON vault at a key file encrypts every write with
XChaCha20-Poly1305 (fresh 192-bit nonce per write; the format version is bound
as associated data). The file becomes a small JSON envelope holding the format
version, the cipher name, the nonce, and the ciphertext, so original values are
never on disk in the clear.

- The key file holds exactly 64 hex characters (`openssl rand -hex 32` writes
  one). On Unix it must not be readable or writable by group or others —
  `chmod 600` — and the tool refuses a key file that is.
- `--vault-key-file <path>`, `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`, or
  `[vault] vault_key_file` select it; it requires a `vault_file`.
- A plaintext vault with a key configured is **not** rewritten silently: the
  call fails and names the migration command:

  ```bash
  do-context-shield encrypt-vault \
      --vault-file ~/.local/share/do-context-shield/vault.json \
      --vault-key-file ~/.config/do-context-shield/vault.key
  ```

  The rewrite goes through the same temporary-file-and-rename path as a normal
  save (a failure cannot corrupt the existing vault) and preserves every
  mapping.
- An encrypted file opened without a key, a plaintext file opened with one, a
  wrong key, and a modified envelope all fail closed with a named reason.

## Validation (fail closed)

Startup fails, naming the offending field, when

- the file contains an unknown key,
- a plugin, recipient, or data-category name is unknown (the error lists the accepted values),
- the `[plugins] tools` list is empty or names an unknown tool (the error lists the accepted values),
- `jurisdiction` is not a two-letter ISO 3166-1 alpha-2 code (the value is forwarded to policies as written, so a typo must not reach them). The same shape predicate guards every layer: the file and the environment fail at load, `sanitize --jurisdiction` fails at argument parsing with exit 2 before stdin is read, and `context.sanitize` returns an `isError` result — a malformed value never falls back to a valid server default,
- the `[vault]` combination cannot select one consistent vault:
  - `vault = "json"` without `vault_file`,
  - `vault_file` together with `vault = "memory"` or `vault = "process"`,
  - `vault_ttl_seconds` with the process vault (memory and JSON vaults both have a lifetime policy),
  - `vault_key_file` without a `vault_file`, or with `vault = "memory"`/`"process"` — only the JSON vault encrypts at rest.

Plugin names are validated at load time against the same set the CLI flags accept, so a typo cannot silently select a different plugin.

## Examples

Keep values on-device for a local workflow:

```toml
[context]
recipient = "local"
```

Share one JSON vault across `sanitize`/`restore` processes:

```toml
[vault]
vault = "json"
vault_file = "/home/user/.local/share/do-context-shield/vault.json"
```

Path values are TOML basic strings, so a Windows path needs its backslashes doubled (`vault_file = "C:\\Users\\me\\vault.json"`) or a literal string (`vault_file = 'C:\Users\me\vault.json'`); a single-backslash path fails to parse.

Same vault, encrypted at rest:

```toml
[vault]
vault_file = "/home/user/.local/share/do-context-shield/vault.json"
vault_key_file = "/home/user/.config/do-context-shield/vault.key"
```

`openssl rand -hex 32 > vault.key && chmod 600 vault.key` creates the key; an existing plaintext vault at `vault_file` must be migrated once with `do-context-shield encrypt-vault --vault-file … --vault-key-file …` (see "At-rest encryption").

MCP server with a local judge and a bounded memory vault:

```toml
[plugins]
judge = "heuristics"

[vault]
vault = "memory"
vault_ttl_seconds = 3600
```

Registered as `do-context-shield mcp-stdio --config /path/to/do-context-shield.toml` (`docs/client-integration.md`).

## See also

- `do-context-shield.toml.example` — commented starting point.
- `docs/plugins.md` — capability model and plugin selection.
- `docs/process-plugin.md` — the process-plugin protocol behind `*_command` keys.
- `docs/client-integration.md` — MCP client registration.
