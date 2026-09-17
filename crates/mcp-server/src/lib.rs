//! MCP stdio adapter. The privacy engine itself remains transport-agnostic.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

const MODERN_VERSION: &str = "2026-07-28";
const LEGACY_VERSION: &str = "2025-11-25";

/// Run the MCP server over newline-delimited JSON-RPC on stdio.
///
/// # Errors
///
/// Returns an error when stdio I/O fails, a request cannot be answered, or a plugin cannot be constructed.
pub fn run_stdio(vault_file: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match vault_file {
        Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
        None => do_context_shield_plugin_registry::vault("memory")?,
    };
    let mut pipeline = PrivacyPipeline::new(
        do_context_shield_plugin_registry::detector("regex")?,
        do_context_shield_plugin_registry::policy("default")?,
        do_context_shield_plugin_registry::transformer("pseudonymize")?,
        vault,
    );
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
        "tools/list" => response(
            id,
            json!({
                "tools":[
                    {"name":"private.sanitize","description":"Detect and sanitize sensitive coding context locally.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"}},"required":["text"]}},
                    {"name":"private.restore","description":"Restore locally stored placeholders in a session.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"}},"required":["text"]}},
                    {"name":"private.inspect","description":"Inspect detected sensitive entities without transforming them.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}
                ],
                "ttlMs":300_000,
                "cacheScope":"process"
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
