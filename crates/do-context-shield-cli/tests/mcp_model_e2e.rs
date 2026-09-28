//! Model-backed end-to-end test for the MCP stdio server: a real `GLiNER2`
//! export plus ONNX Runtime, with the hybrid detector selected through a
//! config file — the path a registered `context.sanitize`/`context.inspect`
//! call actually takes.
//!
//! Runs only when `ORT_DYLIB_PATH` and `DO_CONTEXT_SHIELD_E2E_MODEL_DIR` are
//! set (see `docs/plugins.md`); skips with a note otherwise, and fails loudly
//! on a partially configured setup. The test target only builds with
//! `--features gliner2`.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

mod common;
use common::model_setup;

/// `path` as a TOML basic-string literal: backslashes are escape characters,
/// so Windows paths must be doubled or TOML fails with a unicode-escape error.
fn toml_literal(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

/// One running `mcp-stdio` server with piped stdio and a hermetic home.
struct McpSession {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Hermetic `$HOME` and the generated config, kept alive while the child runs.
    _home: tempfile::TempDir,
}

impl McpSession {
    /// Spawn `mcp-stdio --config <generated>` selecting the hybrid detector
    /// with `model_dir`, and the ONNX Runtime from `ort`.
    fn start(ort: &Path, model_dir: &Path) -> Self {
        let home = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("cannot create a temp directory: {error}"),
        };
        let config = home.path().join("config.toml");
        let content = format!(
            "[plugins]\ndetector = \"hybrid\"\nmodel_dir = {}\n",
            toml_literal(model_dir)
        );
        if let Err(error) = std::fs::write(&config, content) {
            panic!("cannot write {}: {error}", config.display());
        }
        let mut child = match Command::new(env!("CARGO_BIN_EXE_do-context-shield"))
            .arg("mcp-stdio")
            .arg("--config")
            .arg(&config)
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("ORT_DYLIB_PATH", ort)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
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
    fn send(&mut self, request: &str) -> Value {
        if let Err(error) = writeln!(self.stdin, "{request}") {
            panic!("cannot write request: {error}");
        }
        if let Err(error) = self.stdin.flush() {
            panic!("cannot flush request: {error}");
        }
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

    /// Close stdin (EOF) and assert the server shut down cleanly.
    fn close(mut self) {
        drop(self.stdin);
        match self.child.wait() {
            Ok(status) => assert!(status.success(), "mcp-stdio exited with {status}"),
            Err(error) => panic!("cannot wait for mcp-stdio: {error}"),
        }
    }
}

/// A `tools/call` request line for `name` with `arguments`.
fn tool_call(name: &str, arguments: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
    .to_string()
}

/// Text payload of a successful `tools/call` response.
fn content_text(response: &Value) -> String {
    match response
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
    {
        Some(text) => text.to_owned(),
        None => panic!("missing content text in {response}"),
    }
}

#[test]
fn hybrid_detector_over_stdio_with_a_real_model() {
    let Some((ort, model)) = model_setup() else {
        return;
    };
    let mut session = McpSession::start(&ort, &model);

    // The model supplies the linguistic span, the regex half the identifier.
    let inspected = content_text(&session.send(&tool_call(
        "context.inspect",
        &json!({"text": "Jane Doe, SSN 123-45-6789."}),
    )));
    assert!(!inspected.contains("Jane Doe"), "{inspected}");
    assert!(!inspected.contains("123-45-6789"), "{inspected}");
    assert!(inspected.contains("\"full_name\""), "{inspected}");
    assert!(inspected.contains("\"ssn\""), "{inspected}");

    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "Jane Doe, SSN 123-45-6789.", "session": "m1"}),
    )));
    assert!(
        sanitized.starts_with("__DO_PRIVATE_FULL_NAME_1_"),
        "{sanitized}"
    );
    assert!(
        sanitized.contains(", SSN __DO_PRIVATE_SSN_1_"),
        "{sanitized}"
    );
    assert!(sanitized.ends_with("__."), "{sanitized}");
    assert!(!sanitized.contains("Jane Doe"), "{sanitized}");
    assert!(!sanitized.contains("123-45-6789"), "{sanitized}");
    session.close();
}
