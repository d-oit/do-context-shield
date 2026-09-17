//! MCP stdio adapter. The privacy engine itself remains transport-agnostic.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use do_context_shield_plugin_process::{
    DEFAULT_TIMEOUT_MS, ProcessDetector, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

const MODERN_VERSION: &str = "2026-07-28";
const LEGACY_VERSION: &str = "2025-11-25";

/// Server configuration: persistence and plugin selection.
pub struct ServerConfig {
    /// Optional local file for persistence across MCP process restarts (JSON vault).
    pub vault_file: Option<PathBuf>,
    /// Vault plugin: `memory` (default without `vault_file`), `json`, or `process`.
    pub vault: Option<String>,
    /// Command line of a local vault executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub vault_command: Option<String>,
    /// Detector plugin name: `regex` (built-in), `gliner2` (local ONNX NER), or `process`
    /// (local executable over newline-delimited JSON).
    pub detector: String,
    /// Local directory holding the `GLiNER2` ONNX export; only used with `gliner2`.
    pub model_dir: Option<PathBuf>,
    /// Command line of a local detector executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub detector_command: Option<String>,
    /// Policy plugin name: `default` or `process`.
    pub policy: String,
    /// Command line of a local policy executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub policy_command: Option<String>,
    /// Transformer plugin name: `pseudonymize` or `process`.
    pub transformer: String,
    /// Command line of a local transformer executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub transformer_command: Option<String>,
    /// Milliseconds to wait for one process-plugin response (detector, policy, transformer, vault).
    pub process_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            vault_file: None,
            vault: None,
            vault_command: None,
            detector: "regex".to_owned(),
            model_dir: None,
            detector_command: None,
            policy: "default".to_owned(),
            policy_command: None,
            transformer: "pseudonymize".to_owned(),
            transformer_command: None,
            process_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// Run the MCP server over newline-delimited JSON-RPC on stdio.
///
/// # Errors
///
/// Returns an error when stdio I/O fails, a request cannot be answered, or a plugin cannot be constructed.
pub fn run_stdio(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(config.process_timeout_ms);
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match config.vault.as_deref() {
        Some("process") => {
            if config.vault_file.is_some() {
                return Err("`--vault-file` cannot be combined with `--vault process`".into());
            }
            Box::new(ProcessVault::from_selection(
                config.vault_command.as_deref(),
                timeout,
            )?)
        }
        Some("json") => {
            let path = config
                .vault_file
                .take()
                .ok_or("`--vault json` requires `--vault-file <path>`")?;
            Box::new(do_context_shield_vault_json::JsonVault::open(path)?)
        }
        Some("memory") => do_context_shield_plugin_registry::vault("memory")?,
        Some(other) => return Err(format!("unknown vault plugin `{other}`").into()),
        None => match config.vault_file.take() {
            Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
            None => do_context_shield_plugin_registry::vault("memory")?,
        },
    };
    let detector: Box<dyn do_context_shield_plugin_api::Detector> = match config.detector.as_str() {
        "gliner2" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
            let detector_config = match config.model_dir.take() {
                Some(dir) => Gliner2Config::with_model_dir(dir),
                None => Gliner2Config::default(),
            };
            Box::new(Gliner2Detector::new(detector_config))
        }
        "process" => Box::new(ProcessDetector::from_selection(
            config.detector_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::detector(name)?,
    };
    let policy: Box<dyn do_context_shield_plugin_api::Policy> = match config.policy.as_str() {
        "process" => Box::new(ProcessPolicy::from_selection(
            config.policy_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::policy(name)?,
    };
    let transformer: Box<dyn do_context_shield_plugin_api::Transformer> =
        match config.transformer.as_str() {
            "process" => Box::new(ProcessTransformer::from_selection(
                config.transformer_command.as_deref(),
                timeout,
            )?),
            name => do_context_shield_plugin_registry::transformer(name)?,
        };
    let mut pipeline = PrivacyPipeline::new(detector, policy, transformer, vault);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut line = String::new();

    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_request(&mut pipeline, &line)?;
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

fn response(id: Value, mut result: Value) -> Value {
    if let Value::Object(map) = &mut result {
        map.insert(
            "_meta".to_owned(),
            json!({"io.modelcontextprotocol/serverInfo":{"name":"do-context-shield","version":"0.1.0"}}),
        );
    }
    let mut envelope = json!({"jsonrpc":"2.0","result":result});
    if let Value::Object(map) = &mut envelope {
        map.insert("id".to_owned(), id);
    }
    envelope
}

fn error_response(id: Value, message: &str) -> Value {
    let mut envelope = json!({"jsonrpc":"2.0","error":{"code":-32000,"message":message}});
    if let Value::Object(map) = &mut envelope {
        map.insert("id".to_owned(), id);
    }
    envelope
}

fn handle_request(
    pipeline: &mut PrivacyPipeline,
    line: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    let request: Value = match serde_json::from_str(line.trim()) {
        Ok(value) => value,
        Err(error) => return Ok(Some(error_response(Value::Null, &error.to_string()))),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    let result = match method {
        // Modern MCP 2026-07-28: no initialize handshake; clients may discover first.
        "server/discover" => response(
            id,
            json!({
                "supportedVersions":[MODERN_VERSION, LEGACY_VERSION],
                "capabilities":{"tools":{}},
                "instructions":"Local privacy boundary. Sanitize sensitive coding context before external model/tool calls; use the same explicit session value when restoring placeholders."
            }),
        ),
        // Legacy clients can still negotiate the 2025-era handshake.
        "initialize" => response(
            id,
            json!({
                "protocolVersion":LEGACY_VERSION,
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"do-context-shield","version":"0.1.0"},
                "instructions":"Local privacy boundary for coding agents."
            }),
        ),
        "notifications/initialized" => return Ok(None),
        // Tools are returned in a fixed order so clients can cache reliably.
        // `cacheScope` follows the 2026-07-28 `CacheableResult` vocabulary
        // (`public`/`private`): results are session-scoped, so `private`.
        "tools/list" => response(
            id,
            json!({
                "tools":[
                    {"name":"private.sanitize","description":"Detect and sanitize sensitive coding context locally.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"}},"required":["text","session"]}},
                    {"name":"private.restore","description":"Restore locally stored placeholders in a session.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"}},"required":["text","session"]}},
                    {"name":"private.inspect","description":"Inspect detected sensitive entities without transforming them.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}
                ],
                "ttlMs":300_000,
                "cacheScope":"private"
            }),
        ),
        "tools/call" => {
            let name = request
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = request
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            // Schemas require `session`, but the server still falls back to
            // `default` so older clients that send only `text` keep working.
            let session = args
                .get("session")
                .and_then(Value::as_str)
                .unwrap_or("default");
            match name {
                "private.sanitize" => match pipeline.sanitize(&ScopeId(session.to_owned()), text) {
                    Ok(result) => {
                        response(id, json!({"content":[{"type":"text","text":result.text}]}))
                    }
                    Err(error) => error_response(id, &error.to_string()),
                },
                "private.restore" => match pipeline.restore(&ScopeId(session.to_owned()), text) {
                    Ok(result) => response(id, json!({"content":[{"type":"text","text":result}]})),
                    Err(error) => error_response(id, &error.to_string()),
                },
                "private.inspect" => match pipeline.inspect(text) {
                    Ok(result) => response(
                        id,
                        json!({"content":[{"type":"text","text":serde_json::to_string(&result)?}]}),
                    ),
                    Err(error) => error_response(id, &error.to_string()),
                },
                _ => error_response(id, "unknown tool"),
            }
        }
        _ => error_response(id, "unknown method"),
    };
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipeline() -> PrivacyPipeline {
        let vault = match do_context_shield_plugin_registry::vault("memory") {
            Ok(vault) => vault,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let detector = match do_context_shield_plugin_registry::detector("regex") {
            Ok(detector) => detector,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let policy = match do_context_shield_plugin_registry::policy("default") {
            Ok(policy) => policy,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let transformer = match do_context_shield_plugin_registry::transformer("pseudonymize") {
            Ok(transformer) => transformer,
            Err(error) => panic!("unexpected error: {error}"),
        };
        PrivacyPipeline::new(detector, policy, transformer, vault)
    }

    fn request(pipeline: &mut PrivacyPipeline, body: &str) -> Option<Value> {
        match handle_request(pipeline, body) {
            Ok(response) => response,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn tool_call(name: &str, text: &str, session: Option<&str>) -> String {
        let session_arg = match session {
            Some(session) => format!(r#","session":"{session}""#),
            None => String::new(),
        };
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{{"text":{text:?}{session_arg}}}}}}}"#
        )
    }

    fn content_text(response: Option<Value>) -> String {
        let Some(value) = response else {
            panic!("expected a response");
        };
        value
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing content text in {value}"))
            .to_owned()
    }

    #[test]
    fn discover_advertises_modern_and_legacy() {
        let mut pipeline = pipeline();
        let response = request(
            &mut pipeline,
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#,
        );
        let Some(value) = response else {
            panic!("expected a response");
        };
        let versions = value
            .pointer("/result/supportedVersions")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing supportedVersions in {value}"));
        assert!(versions.iter().any(|version| version == MODERN_VERSION));
        assert!(versions.iter().any(|version| version == LEGACY_VERSION));
    }

    #[test]
    fn legacy_initialize_and_notification() {
        let mut pipeline = pipeline();
        let response = request(
            &mut pipeline,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        );
        let Some(value) = response else {
            panic!("expected a response");
        };
        assert_eq!(
            value
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str),
            Some(LEGACY_VERSION)
        );
        let notified = request(
            &mut pipeline,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        );
        assert_eq!(notified, None);
    }

    #[test]
    fn tools_list_is_deterministic_and_cacheable() {
        let mut pipeline = pipeline();
        let response = request(
            &mut pipeline,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        );
        let Some(value) = response else {
            panic!("expected a response");
        };
        let names: Vec<&str> = value
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing tools in {value}"))
            .iter()
            .map(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("tool without name in {tool}"))
            })
            .collect();
        assert_eq!(
            names,
            vec!["private.sanitize", "private.restore", "private.inspect"]
        );
        assert_eq!(
            value.pointer("/result/ttlMs").and_then(Value::as_u64),
            Some(300_000)
        );
        assert_eq!(
            value.pointer("/result/cacheScope").and_then(Value::as_str),
            Some("private")
        );
    }

    #[test]
    fn sanitize_restore_round_trip_is_scope_limited() {
        let mut pipeline = pipeline();
        let sanitized = content_text(request(
            &mut pipeline,
            &tool_call("private.sanitize", "alice@example.com", Some("s")),
        ));
        assert!(!sanitized.contains("alice@example.com"));
        let restored = content_text(request(
            &mut pipeline,
            &tool_call("private.restore", &sanitized, Some("s")),
        ));
        assert_eq!(restored, "alice@example.com");
        let blocked = content_text(request(
            &mut pipeline,
            &tool_call("private.restore", &sanitized, Some("other")),
        ));
        assert_eq!(blocked, sanitized);
    }

    #[test]
    fn missing_session_falls_back_to_default_scope() {
        let mut pipeline = pipeline();
        let sanitized = content_text(request(
            &mut pipeline,
            &tool_call("private.sanitize", "alice@example.com", None),
        ));
        let restored = content_text(request(
            &mut pipeline,
            &tool_call("private.restore", &sanitized, None),
        ));
        assert_eq!(restored, "alice@example.com");
    }

    #[test]
    fn inspect_reports_entities_as_json() {
        let mut pipeline = pipeline();
        let text = content_text(request(
            &mut pipeline,
            &tool_call("private.inspect", "alice@example.com", None),
        ));
        assert!(text.contains(r#""kind":"email""#));
        assert!(text.contains("alice@example.com"));
    }

    #[test]
    fn unknown_tool_method_and_malformed_json_are_errors() {
        let mut pipeline = pipeline();
        for body in [
            tool_call("private.nope", "x", None),
            r#"{"jsonrpc":"2.0","id":2,"method":"bogus/method","params":{}}"#.to_owned(),
            r#"{"jsonrpc": broken"#.to_owned(),
        ] {
            let response = request(&mut pipeline, &body);
            let Some(value) = response else {
                panic!("expected an error response for {body}");
            };
            assert!(value.get("error").is_some(), "expected error in {value}");
        }
    }
}
