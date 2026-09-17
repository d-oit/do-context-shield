# Plugin model

The core does not know which detector, policy, transformer, or vault is used.

| Capability | Contract | Initial plugin | Future replacements |
| --- | --- | --- | --- |
| detection | `Detector` | regex, `detector-gliner2` (local ONNX NER), `detector-process` (NDJSON child process) | custom local NER, rules |
| policy | `Policy` | default | project policy, enterprise DLP |
| transformation | `Transformer` | pseudonymize | redact, generalize, encrypt, format-preserving |
| storage | `Vault` | memory / JSON file | SQLite, OS keychain, encrypted local DB |

Implementations are selected by logical plugin name and compiled in, except detection: `detector-process` runs a user-configured local executable over the newline-delimited JSON protocol in `docs/process-plugin.md`, so a detector written in another language needs no Rust dynamic-library ABI. Policy, transformer, and vault remain compiled-in; the same protocol is their intended next boundary.
