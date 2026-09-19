# Configuration file

Status: implemented (`crates/do-context-shield-cli/src/config.rs`). Every option here also has a CLI flag; the file only supplies defaults.

## Where the file is found

1. `--config <path>` (accepted before or after the subcommand),
2. `./do-context-shield.toml`,
3. `$HOME/.config/do-context-shield/config.toml`.

The first existing candidate wins. Without any file, every option keeps its built-in default. A file that exists but cannot be read or parsed is an error — the tool never falls back to defaults silently.

Paths in the file are literal: environment variables and `~` are not expanded.

## Precedence

CLI flag > file value > built-in default. A flag passed for one invocation therefore overrides the file without editing it.

## Reference

### `[plugins]`

| Key | Values | Default | Notes |
| --- | --- | --- | --- |
| `detector` | `regex`, `gliner2`, `hybrid`, `process` | `regex` | |
| `policy` | `default`, `process` | `default` | |
| `transformer` | `pseudonymize`, `process` | `pseudonymize` | |
| `judge` | `heuristics`, `process` | unset | judging is optional and off by default |
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

### `[context]`

Default enforcement context for `sanitize`; `mcp-stdio` takes these per `context.sanitize` call instead.

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
| `mcp-stdio` | all sections except `[context]` (enforcement context arrives per `context.sanitize` argument) |

The session scope never comes from the file: every command takes `--session` explicitly so mappings cannot leak across implicit scopes.

## Validation (fail closed)

Startup fails, naming the offending field, when

- the file contains an unknown key,
- a plugin, recipient, or data-category name is unknown (the error lists the accepted values),
- the `[vault]` combination cannot select one consistent vault:
  - `vault = "json"` without `vault_file`,
  - `vault_file` together with `vault = "memory"` or `vault = "process"`,
  - `vault_ttl_seconds` with anything but the memory vault (`json`, `process`, or a lone `vault_file`, which selects the JSON vault).

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
