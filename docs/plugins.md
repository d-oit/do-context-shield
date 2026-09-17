# Plugin model

The core does not know which detector, policy, transformer, or vault is used.

| Capability | Contract | Initial plugin | Future replacements |
| --- | --- | --- | --- |
| detection | `Detector` | regex, `detector-gliner2` (local ONNX NER), `plugin-process` (`detect`) | custom local NER, rules |
| policy | `Policy` | default, `plugin-process` (`plan`) | project policy, enterprise DLP |
| transformation | `Transformer` | pseudonymize, `plugin-process` (`transform`) | redact, generalize, encrypt, format-preserving |
| storage | `Vault` | memory / JSON file, `plugin-process` (`vault_get_or_insert`, `vault_resolve`) | SQLite, OS keychain, encrypted local DB |

Implementations are selected by logical plugin name. Every capability can also run behind a process boundary: `crates/plugin-process` speaks newline-delimited JSON to a user-configured local executable (`docs/process-plugin.md`), so an implementation written in another language needs no Rust dynamic-library ABI. Compiled-in plugins remain the default; the process boundary is opt-in per capability (`--detector`/`--policy`/`--transformer`/`--vault process` with the matching `--*-command` flag).
