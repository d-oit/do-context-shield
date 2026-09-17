# Process plugin protocol

The compiled-in plugin registry is the first implementation. For cross-language replacement, use a process boundary rather than a Rust ABI.

Transport: newline-delimited JSON on stdin/stdout.

Detector request:

```json
{"method":"detect","input":"email alice@example.com"}
```

Detector response:

```json
{"entities":[{"kind":"email","start":6,"end":23,"value":"alice@example.com","confidence":0.99}]}
```

The same contract can later carry policy, transformer, or vault operations. A Python CPU model, a Rust model, or another executable can therefore replace an implementation without changing `do-context-shield-core`.
