# Plugin model

The core does not know which detector, policy, transformer, or vault is used.

| Capability | Contract | Initial plugin | Future replacements |
| --- | --- | --- | --- |
| detection | `Detector` | regex | `detector-gliner2` (local ONNX NER), custom local NER, rules |
| policy | `Policy` | default | project policy, enterprise DLP |
| transformation | `Transformer` | pseudonymize | redact, generalize, encrypt, format-preserving |
| storage | `Vault` | memory / JSON file | SQLite, OS keychain, encrypted local DB |

The first implementation is compiled-in by logical plugin name. The next boundary should be a process-level JSONL plugin protocol rather than a Rust dynamic-library ABI.
