# Process plugin protocol

Status: implemented for detectors (`crates/detector-process`, CLI `--detector process`, registry name `process`). Policy, transformer, and vault still ship compiled-in; the same wire contract is their intended boundary.

Transport: newline-delimited JSON on the child's stdin/stdout. One child process is started per `detect` call: the request is written as a single line, exactly one response line is read, and the child is terminated as soon as its answer has been read. A long-lived server mode is not part of this version.

Detector request:

```json
{"method":"detect","input":"email alice@example.com"}
```

Detector response:

```json
{"entities":[{"kind":"email","start":6,"end":23,"value":"alice@example.com","confidence":0.99}]}
```

Field rules:

- `start` / `end`: byte offsets into the exact input of the request. `start < end` is required and both offsets must fall on UTF-8 character boundaries.
- `kind`: required. Normalized to lowercase with spaces replaced by underscores, so `API Key` becomes `api_key`; the default policy matches kinds by lowercase substring.
- `value`: optional. When present it must equal `input[start..end]`; the pipeline always takes the value from the input, never from the child.
- `confidence`: optional, defaults to `1.0`, and must be within `0..=1`.

Selection:

```bash
printf '%s' 'email alice@example.com' \
  | do-context-shield sanitize --session s1 \
      --detector process --detector-command "python3 detector.py"
```

`--detector-command` is split on whitespace — no shell and no quoting; point it at a wrapper script for anything more elaborate. The MCP adapter takes the same flags (`mcp-stdio --detector process --detector-command "<program> [args]"`). A missing or blank command fails at startup, not on the first detection call.

Guarantees:

- Fail closed: a missing command, a spawn failure, an empty or oversized response, malformed JSON (including a missing `entities` key), an invalid span, a value mismatch, an out-of-range confidence, a read error, or a non-zero exit all fail the detection instead of returning a reduced entity list. A non-zero exit fails even when a response line was printed.
- Response cap: one response line may not exceed 8 MiB.
- Timeout: `--detector-timeout-ms` (default 30 000) bounds the wait for the response line. The child is killed and reaped on timeout, on every other error path, and after its answer has been read.
- Overlaps: entities are resolved longest-span-wins after sorting by start offset; the first reported entity wins when two spans are identical.
- stderr is discarded and never logged, and error messages carry no input text, so a failing detector cannot print sensitive context into agent logs.

The same contract can later carry policy, transformer, or vault operations. A Python CPU model, a Rust model, or another executable can therefore replace an implementation without changing `do-context-shield-core`.
