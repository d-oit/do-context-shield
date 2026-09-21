//! JSON-RPC request handling for the MCP stdio adapter.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::{DataCategory, ProcessingContext, RecipientClass, ScopeId};
use serde_json::{Value, json};

use crate::{ToolName, ToolSet};

const MODERN_VERSION: &str = "2026-07-28";
const LEGACY_VERSION: &str = "2025-11-25";

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

/// Parse the optional enforcement-context arguments of `context.sanitize`.
///
/// Omitted fields fall back to the most restrictive defaults (external
/// recipient, personal data, no purpose or jurisdiction). An unknown enum name
/// or a wrong JSON type is an error, never a silent downgrade to a weaker
/// context.
fn processing_context(args: &Value) -> Result<ProcessingContext, String> {
    let recipient = match args.get("recipient") {
        None | Some(Value::Null) => RecipientClass::default(),
        Some(Value::String(name)) => RecipientClass::parse(name).ok_or_else(|| {
            format!("recipient must be one of local, trusted, external, unknown; got `{name}`")
        })?,
        Some(_) => return Err("recipient must be a string".to_owned()),
    };
    let data_category = match args.get("data_category") {
        None | Some(Value::Null) => DataCategory::default(),
        Some(Value::String(name)) => DataCategory::parse(name).ok_or_else(|| {
            format!(
                "data_category must be one of non_personal, personal, special_category; got `{name}`"
            )
        })?,
        Some(_) => return Err("data_category must be a string".to_owned()),
    };
    Ok(ProcessingContext {
        purpose: optional_string(args, "purpose")?,
        recipient,
        jurisdiction: optional_string(args, "jurisdiction")?,
        data_category,
    })
}

/// Read an optional string argument, rejecting a present non-string value.
fn optional_string(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

pub(crate) fn handle_request(
    pipeline: &mut PrivacyPipeline,
    tools: ToolSet,
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
        "tools/list" => response(id, tools_list(tools)),
        "tools/call" => {
            let name = request
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = request
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            tool_call(pipeline, tools, id, name, &args)?
        }
        _ => error_response(id, "unknown method"),
    };
    Ok(Some(result))
}

/// Tool catalogue. Only enabled tools are listed, in a fixed order so clients
/// can cache reliably; `cacheScope` follows the 2026-07-28 `CacheableResult`
/// vocabulary (`public`/`private`) because results are session-scoped.
fn tools_list(tools: ToolSet) -> Value {
    let catalogue: Vec<Value> = ToolName::ALL
        .into_iter()
        .filter(|tool| tools.contains(*tool))
        .map(ToolName::schema)
        .collect();
    json!({
        "tools": catalogue,
        "ttlMs":300_000,
        "cacheScope":"private"
    })
}

impl ToolName {
    /// Full JSON-RPC tool name.
    const fn full(self) -> &'static str {
        match self {
            Self::Sanitize => "context.sanitize",
            Self::Restore => "context.restore",
            Self::Inspect => "context.inspect",
            Self::Forget => "context.forget",
        }
    }

    fn from_full(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.full() == name)
    }

    /// Catalogue entry: name, description, and input schema.
    fn schema(self) -> Value {
        match self {
            Self::Sanitize => {
                json!({"name":"context.sanitize","description":"Detect and sanitize sensitive coding context locally. Optional recipient/data_category/purpose/jurisdiction arguments select the enforcement context; unknown values are rejected.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"},"recipient":{"type":"string","enum":["local","trusted","external","unknown"],"default":"external"},"data_category":{"type":"string","enum":["non_personal","personal","special_category"],"default":"personal"},"purpose":{"type":"string"},"jurisdiction":{"type":"string"}},"required":["text","session"]}})
            }
            Self::Restore => {
                json!({"name":"context.restore","description":"Restore locally stored placeholders in an explicit session. Requires `session`; there is no fallback scope for restore. Not exposed by default: results return to the calling model, so restore harness-side unless the boundary allows otherwise.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"}},"required":["text","session"]}})
            }
            Self::Inspect => {
                json!({"name":"context.inspect","description":"Inspect detected sensitive entities (kind, byte span, confidence) without transforming them or returning the matched text.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}})
            }
            Self::Forget => {
                json!({"name":"context.forget","description":"Delete all locally stored placeholders for an explicit session. Requires `session`; there is no fallback scope.","inputSchema":{"type":"object","properties":{"session":{"type":"string"}},"required":["session"]}})
            }
        }
    }
}

/// Dispatch one `tools/call`. A tool disabled by the server's [`ToolSet`] is
/// rejected before any argument handling, and arguments are enforced, not just
/// declared: a non-object `arguments`, or a missing/non-string `text` for the
/// tools that declare it, is an error instead of a silent empty-input call.
/// Sanitize still falls back to the `default` scope for older clients; restore
/// and forget never do, because they resolve or delete raw values and must name
/// their session explicitly.
fn tool_call(
    pipeline: &mut PrivacyPipeline,
    tools: ToolSet,
    id: Value,
    name: &str,
    args: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    if let Some(tool) = ToolName::from_full(name) {
        if !tools.contains(tool) {
            return Ok(error_response(
                id,
                &format!(
                    "{name} is not enabled on this server (allow it with `--tools {}` or `--tools all`)",
                    tool.short()
                ),
            ));
        }
    }
    if !args.is_object() {
        return Ok(error_response(id, "`arguments` must be a JSON object"));
    }
    Ok(match name {
        "context.sanitize" => {
            let text = match text_argument(args, "context.sanitize") {
                Ok(text) => text,
                Err(message) => return Ok(error_response(id, &message)),
            };
            let session = match optional_string(args, "session") {
                Ok(session) => session,
                Err(message) => return Ok(error_response(id, &message)),
            };
            let context = match processing_context(args) {
                Ok(context) => context,
                Err(message) => return Ok(error_response(id, &message)),
            };
            // Long-running servers drop expired in-process mappings before
            // each mutation; vaults without a TTL no-op.
            if let Err(error) = pipeline.expire_vault() {
                return Ok(error_response(id, &error.to_string()));
            }
            let scope = ScopeId(session.unwrap_or_else(|| "default".to_owned()));
            match pipeline.sanitize(&scope, &text, &context) {
                Ok(result) => response(id, json!({"content":[{"type":"text","text":result.text}]})),
                Err(error) => error_response(id, &error.to_string()),
            }
        }
        "context.restore" => {
            let text = match text_argument(args, "context.restore") {
                Ok(text) => text,
                Err(message) => return Ok(error_response(id, &message)),
            };
            let session = match required_session(args, "context.restore") {
                Ok(session) => session,
                Err(message) => return Ok(error_response(id, &message)),
            };
            match pipeline.restore(&ScopeId(session), &text) {
                Ok(result) => response(id, json!({"content":[{"type":"text","text":result}]})),
                Err(error) => error_response(id, &error.to_string()),
            }
        }
        "context.inspect" => {
            let text = match text_argument(args, "context.inspect") {
                Ok(text) => text,
                Err(message) => return Ok(error_response(id, &message)),
            };
            match pipeline.inspect(&text) {
                Ok(result) => response(
                    id,
                    json!({"content":[{"type":"text","text":serde_json::to_string(&result)?}]}),
                ),
                Err(error) => error_response(id, &error.to_string()),
            }
        }
        "context.forget" => {
            let session = match required_session(args, "context.forget") {
                Ok(session) => session,
                Err(message) => return Ok(error_response(id, &message)),
            };
            match pipeline.forget(&ScopeId(session.clone())) {
                Ok(()) => response(
                    id,
                    json!({"content":[{"type":"text","text":json!({"session":session,"forgotten":true}).to_string()}]}),
                ),
                Err(error) => error_response(id, &error.to_string()),
            }
        }
        _ => error_response(id, "unknown tool"),
    })
}

/// Read the required `text` argument of a tool that declares it.
fn text_argument(args: &Value, tool: &str) -> Result<String, String> {
    match optional_string(args, "text") {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Err(format!("{tool} requires a string `text` argument")),
        Err(message) => Err(message),
    }
}

/// Read the explicit `session` that resolving and deleting tools require.
fn required_session(args: &Value, tool: &str) -> Result<String, String> {
    match optional_string(args, "session") {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(format!("{tool} requires an explicit session")),
        Err(message) => Err(message),
    }
}

#[cfg(test)]
mod tests;
