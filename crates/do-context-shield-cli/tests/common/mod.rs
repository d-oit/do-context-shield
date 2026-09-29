//! Helpers shared by the binary-level CLI integration tests.

// Each test binary uses only a subset of the shared helpers.
#![allow(dead_code)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Assert `text` is exactly one minted placeholder for `kind`/`counter`
/// (`__DO_PRIVATE_<KIND>_<counter>_<16 hex>__`).
pub fn assert_placeholder(text: &str, kind: &str, counter: u64) {
    let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
    let Some(rest) = text.strip_prefix(&prefix) else {
        panic!("`{text}` does not start with `{prefix}`");
    };
    assert_token_entropy(rest, text);
}

/// Assert `text` contains a minted placeholder for `kind`/`counter`.
pub fn assert_contains_placeholder(text: &str, kind: &str, counter: u64) {
    let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
    let Some(start) = text.find(&prefix) else {
        panic!("`{text}` does not contain `{prefix}`");
    };
    assert_token_entropy(&text[start + prefix.len()..], text);
}

/// The remainder after a placeholder prefix: 16 hex characters and `__`.
fn assert_token_entropy(rest: &str, text: &str) {
    let Some(entropy) = rest.strip_suffix("__") else {
        panic!("`{text}` is missing the closing `__`");
    };
    assert_eq!(entropy.len(), 16, "unexpected token entropy in `{text}`");
    assert!(
        entropy.chars().all(|c| c.is_ascii_hexdigit()),
        "unexpected token entropy in `{text}`"
    );
}

/// Every environment variable the binary reads. Cleared by [`cmd`] so an
/// ambient value can never change a test.
pub const CONFIG_ENV_VARS: [&str; 13] = [
    "DO_CONTEXT_SHIELD_DATA_CATEGORY",
    "DO_CONTEXT_SHIELD_DETECTOR",
    "DO_CONTEXT_SHIELD_JUDGE",
    "DO_CONTEXT_SHIELD_JURISDICTION",
    "DO_CONTEXT_SHIELD_POLICY",
    "DO_CONTEXT_SHIELD_PURPOSE",
    "DO_CONTEXT_SHIELD_RECIPIENT",
    "DO_CONTEXT_SHIELD_TOOLS",
    "DO_CONTEXT_SHIELD_TRANSFORMER",
    "DO_CONTEXT_SHIELD_VAULT",
    "DO_CONTEXT_SHIELD_VAULT_FILE",
    "DO_CONTEXT_SHIELD_VAULT_KEY_FILE",
    "DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS",
];

/// The compiled `do-context-shield` binary, started with a hermetic working
/// directory, `$HOME`, and `DO_CONTEXT_SHIELD_*` environment so an ambient
/// `do-context-shield.toml` or config override can never change a test.
pub fn cmd(dir: &Path) -> assert_cmd::Command {
    let mut command = match assert_cmd::Command::cargo_bin("do-context-shield") {
        Ok(command) => command,
        Err(error) => panic!("binary `do-context-shield` is not built: {error}"),
    };
    command.current_dir(dir).env("HOME", dir);
    for name in CONFIG_ENV_VARS {
        command.env_remove(name);
    }
    command
}

/// Command line invoking the process-protocol fixture in `mode`.
///
/// The fixture belongs to the protocol implementation
/// (`crates/plugin-process/tests/fixtures/plugin.sh`), which asserts the wire
/// format itself; the CLI tests reuse it to drive the documented
/// `--detector`/`--policy`/`--transformer`/`--vault process` selections through
/// the compiled binary.
pub fn process_command(mode: &str) -> String {
    format!(
        "sh {}/../plugin-process/tests/fixtures/plugin.sh {mode}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Fresh temporary directory, removed when the returned handle is dropped.
pub fn temp_dir() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    }
}

/// The configured ONNX Runtime and model directory, or `None` when the
/// model-backed tests should skip.
///
/// Both `ORT_DYLIB_PATH` (the runtime pinned in `docs/plugins.md`) and
/// `DO_CONTEXT_SHIELD_E2E_MODEL_DIR` (an absolute fragment export) are needed.
/// Neither set: skip with a note. Only the model directory set: fail, because
/// that is a half-configured run rather than an unconfigured one. CI sets
/// `DO_HARNESS_REQUIRE_ORT=1` after provisioning the runtime, which turns an
/// unset runtime into a failure so a broken download cannot silently skip the
/// runtime-backed tests.
pub fn model_setup() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let (ort, model) = (
        std::env::var_os("ORT_DYLIB_PATH"),
        std::env::var_os("DO_CONTEXT_SHIELD_E2E_MODEL_DIR"),
    );
    assert!(
        !(ort.is_none() && model.is_some()),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR is set but ORT_DYLIB_PATH is not; provide both or neither"
    );
    assert!(
        !(ort.is_none() && std::env::var("DO_HARNESS_REQUIRE_ORT").is_ok_and(|value| value == "1")),
        "DO_HARNESS_REQUIRE_ORT=1 but ORT_DYLIB_PATH is unset; CI must provision the pinned ONNX Runtime (docs/plugins.md)"
    );
    let (Some(ort), Some(model)) = (ort, model) else {
        eprintln!(
            "skip: set ORT_DYLIB_PATH and DO_CONTEXT_SHIELD_E2E_MODEL_DIR to run the model-backed E2E tests"
        );
        return None;
    };
    let (ort, model) = (
        std::path::PathBuf::from(ort),
        std::path::PathBuf::from(model),
    );
    assert!(
        ort.is_file(),
        "ORT_DYLIB_PATH is not a file: {}",
        ort.display()
    );
    assert!(
        model.is_absolute(),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR must be absolute (the binary runs in a temp directory): {}",
        model.display()
    );
    assert!(
        model.is_dir(),
        "DO_CONTEXT_SHIELD_E2E_MODEL_DIR is not a directory: {}",
        model.display()
    );
    Some((ort, model))
}

/// One running `mcp-stdio` server with piped stdio.
pub struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Hermetic `$HOME`, kept alive for as long as the child runs.
    _home: tempfile::TempDir,
}

impl McpSession {
    /// Spawn `do-context-shield mcp-stdio` with pipes for both directions
    /// (default tool set: `sanitize` and `inspect`).
    pub fn start() -> Self {
        Self::start_with(&[])
    }

    /// Spawn with extra arguments after `mcp-stdio` (e.g. `--tools all`).
    pub fn start_with(extra: &[&str]) -> Self {
        let home = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("cannot create a temp directory: {error}"),
        };
        Self::start_configured(home, extra, &[])
    }

    /// Spawn in a caller-prepared `$HOME`/working directory with environment
    /// overrides, for tests that pin configuration before startup. `HOME` and
    /// the working directory are the caller's `home`; every
    /// `DO_CONTEXT_SHIELD_*` variable the binary reads is cleared first so an
    /// ambient value cannot change the test, then `envs` are applied.
    pub fn start_configured(
        home: tempfile::TempDir,
        extra: &[&str],
        envs: &[(&str, &str)],
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_do-context-shield"));
        command
            .arg("mcp-stdio")
            .args(extra)
            .current_dir(home.path())
            .env("HOME", home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for name in CONFIG_ENV_VARS {
            command.env_remove(name);
        }
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => panic!("cannot spawn `do-context-shield mcp-stdio`: {error}"),
        };
        let Some(stdin) = child.stdin.take() else {
            panic!("piped stdin missing");
        };
        let Some(stdout) = child.stdout.take() else {
            panic!("piped stdout missing");
        };
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            _home: home,
        }
    }

    /// Send one JSON-RPC message and return the response line that follows.
    pub fn send(&mut self, request: &str) -> Value {
        self.write_line(request);
        self.read_response()
    }

    /// Send a JSON-RPC notification, which must not produce a response.
    pub fn send_notification(&mut self, request: &str) {
        self.write_line(request);
    }

    /// Close stdin (EOF) and assert the server shut down cleanly.
    pub fn close(mut self) {
        drop(self.stdin);
        match self.child.wait() {
            Ok(status) => assert!(status.success(), "mcp-stdio exited with {status}"),
            Err(error) => panic!("cannot wait for mcp-stdio: {error}"),
        }
    }

    pub fn write_line(&mut self, request: &str) {
        if let Err(error) = writeln!(self.stdin, "{request}") {
            panic!("cannot write request: {error}");
        }
        if let Err(error) = self.stdin.flush() {
            panic!("cannot flush request: {error}");
        }
    }

    pub fn read_response(&mut self) -> Value {
        let mut line = String::new();
        match self.stdout.read_line(&mut line) {
            Ok(0) => panic!("server closed stdout before answering"),
            Ok(_) => {}
            Err(error) => panic!("cannot read response: {error}"),
        }
        match serde_json::from_str(&line) {
            Ok(response) => response,
            Err(error) => panic!("response is not valid JSON: {error} (line: {line:?})"),
        }
    }
}

/// A `tools/call` request line for `name` with `arguments`.
pub fn tool_call(name: &str, arguments: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    .to_string()
}

/// Text payload of a successful `tools/call` response.
pub fn content_text(response: &Value) -> String {
    match response
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
    {
        Some(text) => text.to_owned(),
        None => panic!("missing content text in {response}"),
    }
}

/// JSON-RPC error code, if the response is an error.
pub fn error_code(response: &Value) -> Option<i64> {
    response.pointer("/error/code").and_then(Value::as_i64)
}

/// Names of the tools in a `tools/list` response.
pub fn tool_names(response: &Value) -> Vec<String> {
    match response.pointer("/result/tools").and_then(Value::as_array) {
        Some(tools) => tools
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect(),
        None => panic!("missing tools in {response}"),
    }
}

/// Write `content` to `path`, naming the path on failure.
pub fn write_config(path: &std::path::Path, content: &str) {
    if let Err(error) = std::fs::write(path, content) {
        panic!("cannot write {}: {error}", path.display());
    }
}
