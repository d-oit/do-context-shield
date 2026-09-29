# Configuration file

Status: implemented (`crates/do-context-shield-cli/src/config.rs`). Every option here also has a CLI flag; the file only supplies defaults.

## Where the file is found

1. `--config <path>` (accepted before or after the subcommand),
2. `./do-context-shield.toml`,
3. `$HOME/.config/do-context-shield/config.toml`.

The first existing candidate wins. Without any file, every option keeps its built-in default. A candidate that exists but cannot be read or parsed is an error — the tool never falls back to defaults silently, and a candidate of that name that is not a regular file (a directory, a dangling symlink) is such an error rather than an absent one. A missing `--config` path is an error too: the explicit path is an instruction, while an absent auto-discovery candidate is simply not selected.

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
| `DO_CONTEXT_SHIELD_RECIPIENT` | `[context] recipient` |
| `DO_CONTEXT_SHIELD_DATA_CATEGORY` | `[context] data_category` |
| `DO_CONTEXT_SHIELD_PURPOSE` | `[context] purpose` |
| `DO_CONTEXT_SHIELD_JURISDICTION` | `[context] jurisdiction` |

## Reference

### `[plugins]`

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `detector` | `regex`, `gliner2`, `hybrid`, `process` | `regex` | |
| `policy` | `default`, `process` | `default` | |
| `transformer` | `pseudonymize`, `generalize`, `mask`, `process` | `pseudonymize` | `generalize`/`mask` are non-reversible: no vault writes, no restorable output |
| `judge` | `heuristics`, `process` | unset | judging is optional and off by default |
| `tools` | `sanitize`, `restore`, `inspect`, `forget`, `all` (comma-separated) | `sanitize,inspect` | `mcp-stdio` only; pins the exposed MCP tool surface in the file (equivalent to `--tools`) |
| `model_dir` | path | unset | `gliner2`/`hybrid` ONNX export directory |
| `detector_command` | command line | unset | required with `detector = "process"` |
| `policy_command` | command line | unset | required with `policy = "process"` |
| `transformer_command` | command line | unset | required with `transformer = "process"` |
| `judge_command` | command line | unset | required with `judge = "process"` |

Command lines are split on whitespace; quoting and shell expansion are not supported (`docs/process-plugin.md`).

### `[vault]`

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `vault` | `memory`, `json`, `process` | `memory` | `json` when `vault_file` is set and `vault` is omitted |
| `vault_file` | path | unset | required by `vault = "json"`; selects the JSON vault on its own |
| `vault_command` | command line | unset | required with `vault = "process"` |
| `vault_ttl_seconds` | seconds | unset | memory vault only; only takes effect for `mcp-stdio` — one-shot commands exit before a mapping lifetime matters |
| `vault_key_file` | path | unset | 64-hex-character key that encrypts the JSON vault at rest; requires `vault_file`, and on Unix the key file must be owner-only |

### `[context]`

Default enforcement context. It applies to the CLI `sanitize` call and supplies the `mcp-stdio` server default for `context.sanitize` requests that omit the arguments; a per-call argument (or CLI flag) overrides the file value field by field.

| Key | Values | Default |
| --- | --- | --- |
| `recipient` | `local`, `trusted`, `external`, `unknown` | `external` |
| `data_category` | `non_personal`, `personal`, `special_category` | `personal` |
| `purpose` | free-form string | unset |
| `jurisdiction` | ISO 3166-1 alpha-2 code | unset |

### `[process]`

| Key | Values | Default |
| --- | --- | --- |
| `timeout_ms` | milliseconds | 30000 |

Bounds one process-plugin response; the child is killed and reaped on timeout (`docs/process-plugin.md`).

## Per-command applicability

| Command | Reads from the file |
| --- | --- |
| `sanitize` | all sections |
| `restore` | `[vault]`, `[process]`; the plugin selections are still merged into the pipeline, but restore only resolves placeholders |
| `inspect` | detector keys of `[plugins]` (`detector`, `model_dir`, `detector_command`) and `[process]`; the vault is constructed but not queried |
| `forget` | `[vault]`, `[process]` |
| `mcp-stdio` | all sections; `[context]` becomes the server default for `context.sanitize` and per-call arguments override it (field by field); `[plugins] tools` sets the exposed tool surface |
| `encrypt-vault` | nothing: both paths are explicit flags, so an ambient file can never trigger an in-place rewrite |

The session scope never comes from the file: the vault-scoping commands (`sanitize`, `restore`, `forget`) require `--session` explicitly so mappings cannot leak across implicit scopes.

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
- `jurisdiction` is not a two-letter ISO 3166-1 alpha-2 code (the value is forwarded to policies as written, so a typo must not reach them),
- the `[vault]` combination cannot select one consistent vault:
  - `vault = "json"` without `vault_file`,
  - `vault_file` together with `vault = "memory"` or `vault = "process"`,
  - `vault_ttl_seconds` with anything but the memory vault (`json`, `process`, or a lone `vault_file`, which selects the JSON vault),
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
