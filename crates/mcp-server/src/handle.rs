//! JSON-RPC request handling for the MCP stdio adapter.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::{
    DataCategory, ProcessingContext, RecipientClass, ScopeId, is_valid_jurisdiction,
};
use serde_json::{Value, json};

use crate::{ToolName, ToolSet};

const MODERN_VERSION: &str = "2026-07-28";
const LEGACY_VERSION: &str = "2025-11-25";

fn response(id: Value, mut result: Value) -> Value {
    if let Value::Object(map) = &mut result {
        map.insert(
            "resultType".to_owned(),
            Value::String("complete".to_owned()),
        );
        map.insert(
            "_meta".to_owned(),
            json!({"io.modelcontextprotocol/serverInfo":{"name":"do-context-shield","version":env!("CARGO_PKG_VERSION")}}),
        );
    }
    let mut envelope = json!({"jsonrpc":"2.0","result":result});
    if let Value::Object(map) = &mut envelope {
        map.insert("id".to_owned(), id);
    }
    envelope
}

/// A JSON-RPC protocol error.
///
/// `code` is the JSON-RPC 2.0 / MCP code: `-32700` parse error, `-32600`
/// invalid request, `-32601` unknown method or tool, `-32602` invalid params.
/// Failures inside a tool call never come through here — they are
/// [`tool_error`] results, so a model sees them as tool output.
fn error_response(id: Value, code: i32, message: &str) -> Value {
    let mut envelope = json!({"jsonrpc":"2.0","error":{"code":code,"message":message}});
    if let Value::Object(map) = &mut envelope {
        map.insert("id".to_owned(), id);
    }
    envelope
}

/// The 2026-07-28 rejection of a requested protocol version this server does
/// not support.
///
/// `data.supported` lists the accepted versions and `data.requested` echoes
/// the version from the request. Nothing else from the request enters the
/// error, so tool input can never leak through it.
fn unsupported_version(id: Value, requested: &str) -> Value {
    let mut envelope = json!({
        "jsonrpc":"2.0",
        "error":{
            "code":-32022,
            "message":"Unsupported protocol version",
            "data":{"supported":[MODERN_VERSION, LEGACY_VERSION],"requested":requested}
        }
    });
    if let Value::Object(map) = &mut envelope {
        map.insert("id".to_owned(), id);
    }
    envelope
}

/// A tool execution failure as a successful JSON-RPC result.
///
/// MCP 2026-07-28 separates protocol errors (malformed JSON-RPC, unknown
/// method, wrong `params` shape) from failures inside a tool call: invalid
/// arguments and pipeline failures reach the caller as a `CallToolResult` with
/// `isError: true`, so the model sees them as tool output instead of a
/// transport error.
fn tool_error(id: Value, message: &str) -> Value {
    response(
        id,
        json!({"content":[{"type":"text","text":message}],"isError":true}),
    )
}

/// The namespaced MCP request-metadata keys (2026-07-28).
const PROTOCOL_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// A structurally valid JSON-RPC request, after envelope and metadata checks.
struct ValidRequest<'a> {
    id: Value,
    method: &'a str,
    params: Option<&'a Value>,
}

/// A valid JSON-RPC request id is a string or an integer number.
fn valid_id(value: &Value) -> bool {
    value.is_string() || value.is_i64() || value.is_u64()
}

/// Validate one parsed line as a JSON-RPC 2.0 request for this server.
///
/// Returns `Ok(None)` for a notification — a structurally valid message with
/// no `id` — so it can never reach dispatch, and with it never sanitize,
/// restore, or delete state. `Err(response)` carries the protocol error to
/// emit. Checks run in wire order: envelope (`-32600`), `id` (`-32600`),
/// `params` shape (`-32602`), then the namespaced protocol metadata
/// (`-32602`/`-32022`).
fn validate_request(request: &Value) -> Result<Option<ValidRequest<'_>>, Value> {
    let Some(object) = request.as_object() else {
        return Err(error_response(
            Value::Null,
            -32600,
            "request must be a JSON object",
        ));
    };
    // The id to echo on an envelope error: only a valid id is echoed.
    let echoed = match object.get("id") {
        Some(id) if valid_id(id) => id.clone(),
        _ => Value::Null,
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(error_response(echoed, -32600, "`jsonrpc` must be \"2.0\""));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Err(error_response(echoed, -32600, "`method` must be a string"));
    };
    let id = match object.get("id") {
        Some(id) if valid_id(id) => id.clone(),
        Some(_) => {
            return Err(error_response(
                Value::Null,
                -32600,
                "`id` must be a string or an integer",
            ));
        }
        // No `id`: a notification, never dispatched.
        None => return Ok(None),
    };
    let params = object.get("params");
    if let Some(params) = params
        && !params.is_object()
    {
        return Err(error_response(id, -32602, "`params` must be a JSON object"));
    }
    check_protocol_metadata(&id, params)?;
    Ok(Some(ValidRequest { id, method, params }))
}

/// Enforce the namespaced protocol metadata of a request.
///
/// The version and capabilities keys are read only from `params._meta`; the
/// pre-2026 bare `protocolVersion` is not the wire contract. A request that
/// carries the version key must name a supported version and come with
/// capabilities; the checks run before dispatch, so a `tools/call` for an
/// unnegotiated revision never executes. A request without the key keeps the
/// legacy behavior and gets one stderr warning naming the wire key.
fn check_protocol_metadata(id: &Value, params: Option<&Value>) -> Result<(), Value> {
    let meta = params.and_then(|params| params.get("_meta"));
    let Some(version) = meta.and_then(|meta| meta.get(PROTOCOL_VERSION_KEY)) else {
        eprintln!(
            "do-context-shield: request without `params._meta[\"{PROTOCOL_VERSION_KEY}\"]`; assuming a pre-2026 client"
        );
        return Ok(());
    };
    let Some(version) = version.as_str() else {
        return Err(error_response(
            id.clone(),
            -32602,
            "`io.modelcontextprotocol/protocolVersion` must be a string",
        ));
    };
    if version != MODERN_VERSION && version != LEGACY_VERSION {
        return Err(unsupported_version(id.clone(), version));
    }
    let capabilities = meta.and_then(|meta| meta.get(CLIENT_CAPABILITIES_KEY));
    if !capabilities.is_some_and(Value::is_object) {
        return Err(error_response(
            id.clone(),
            -32602,
            "`io.modelcontextprotocol/clientCapabilities` must be an object",
        ));
    }
    Ok(())
}

/// Parse the optional enforcement-context arguments of `context.sanitize`.
///
/// Omitted fields fall back to `base`, the server's configured context (by
/// default the most restrictive one: external recipient, personal data, no
/// purpose or jurisdiction). An unknown enum name, a wrong JSON type, or a
/// malformed jurisdiction is an error, never a silent downgrade to a weaker
/// context: an invalid explicit override does not fall back to a valid server
/// default either.
fn processing_context(args: &Value, base: &ProcessingContext) -> Result<ProcessingContext, String> {
    let recipient = match args.get("recipient") {
        None | Some(Value::Null) => base.recipient,
        Some(Value::String(name)) => RecipientClass::parse(name).ok_or_else(|| {
            format!("recipient must be one of local, trusted, external, unknown; got `{name}`")
        })?,
        Some(_) => return Err("recipient must be a string".to_owned()),
    };
    let data_category = match args.get("data_category") {
        None | Some(Value::Null) => base.data_category,
        Some(Value::String(name)) => DataCategory::parse(name).ok_or_else(|| {
            format!(
                "data_category must be one of non_personal, personal, special_category; got `{name}`"
            )
        })?,
        Some(_) => return Err("data_category must be a string".to_owned()),
    };
    let jurisdiction = optional_string(args, "jurisdiction")?.or_else(|| base.jurisdiction.clone());
    if let Some(value) = jurisdiction.as_deref()
        && !is_valid_jurisdiction(value)
    {
        return Err("jurisdiction must be an ISO 3166-1 alpha-2 code".to_owned());
    }
    Ok(ProcessingContext {
        purpose: optional_string(args, "purpose")?.or_else(|| base.purpose.clone()),
        recipient,
        jurisdiction,
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
    default_context: &ProcessingContext,
    line: &str,
) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    let line: Value = match serde_json::from_str(line.trim()) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Some(error_response(
                Value::Null,
                -32700,
                &error.to_string(),
            )));
        }
    };
    let ValidRequest { id, method, params } = match validate_request(&line) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(None),
        Err(response) => return Ok(Some(response)),
    };

    let result = match method {
        // Modern MCP 2026-07-28: no initialize handshake; clients may discover first.
        "server/discover" => response(
            id,
            json!({
                "supportedVersions":[MODERN_VERSION, LEGACY_VERSION],
                "capabilities":{"tools":{}},
                "instructions":"Local privacy boundary. Sanitize sensitive coding context before external model/tool calls; use the same explicit session value when restoring placeholders.",
                "ttlMs":300_000,
                "cacheScope":"private"
            }),
        ),
        // Legacy clients can still negotiate the 2025-era handshake.
        "initialize" => response(
            id,
            json!({
                "protocolVersion":LEGACY_VERSION,
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"do-context-shield","version":env!("CARGO_PKG_VERSION")},
                "instructions":"Local privacy boundary for coding agents."
            }),
        ),
        "tools/list" => response(id, tools_list(tools)),
        "tools/call" => {
            let name = params
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = params
                .and_then(|params| params.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            tool_call(pipeline, tools, default_context, id, name, &args)?
        }
        _ => error_response(id, -32601, "unknown method"),
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
                json!({"name":"context.sanitize","description":"Detect and sanitize sensitive coding context locally. Optional recipient/data_category/purpose/jurisdiction arguments select the enforcement context; unknown values are rejected. The built-in policy reads recipient and data_category, requires a declared jurisdiction for special-category data to a trusted recipient, and forwards purpose to policy plugins without letting it loosen a decision.","inputSchema":{"type":"object","properties":{"text":{"type":"string"},"session":{"type":"string"},"recipient":{"type":"string","enum":["local","trusted","external","unknown"],"default":"external"},"data_category":{"type":"string","enum":["non_personal","personal","special_category"],"default":"personal"},"purpose":{"type":"string"},"jurisdiction":{"type":"string","pattern":"^[A-Za-z]{2}$"}},"required":["text","session"]}})
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
/// rejected before any argument handling with a JSON-RPC error, as are a
/// non-object `arguments` value and an unknown tool name: those are protocol
/// failures. Everything inside a known tool — argument validation, vault
/// expiry, and pipeline failures — is reported as a [`tool_error`] result so
/// the caller sees a tool execution failure, not a transport failure.
/// Sanitize still falls back to the `default` scope for older clients; restore
/// and forget never do, because they resolve or delete raw values and must name
/// their session explicitly.
fn tool_call(
    pipeline: &mut PrivacyPipeline,
    tools: ToolSet,
    default_context: &ProcessingContext,
    id: Value,
    name: &str,
    args: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    if let Some(tool) = ToolName::from_full(name) {
        if !tools.contains(tool) {
            return Ok(error_response(
                id,
                -32601,
                &format!(
                    "{name} is not enabled on this server (allow it with `--tools {}` or `--tools all`)",
                    tool.short()
                ),
            ));
        }
    }
    if !args.is_object() {
        return Ok(error_response(
            id,
            -32602,
            "`arguments` must be a JSON object",
        ));
    }
    Ok(match name {
        "context.sanitize" => {
            let text = match text_argument(args, "context.sanitize") {
                Ok(text) => text,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            let session = match optional_string(args, "session") {
                Ok(session) => session,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            let context = match processing_context(args, default_context) {
                Ok(context) => context,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            // Long-running servers drop expired in-process mappings before
            // each mutation; vaults without a TTL no-op.
            if let Err(error) = pipeline.expire_vault() {
                return Ok(tool_error(id, &error.to_string()));
            }
            let scope = ScopeId(session.unwrap_or_else(|| "default".to_owned()));
            match pipeline.sanitize(&scope, &text, &context) {
                Ok(result) => response(id, json!({"content":[{"type":"text","text":result.text}]})),
                Err(error) => tool_error(id, &error.to_string()),
            }
        }
        "context.restore" => {
            let text = match text_argument(args, "context.restore") {
                Ok(text) => text,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            let session = match required_session(args, "context.restore") {
                Ok(session) => session,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            match pipeline.restore(&ScopeId(session), &text) {
                Ok(result) => response(id, json!({"content":[{"type":"text","text":result}]})),
                Err(error) => tool_error(id, &error.to_string()),
            }
        }
        "context.inspect" => {
            let text = match text_argument(args, "context.inspect") {
                Ok(text) => text,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            match pipeline.inspect(&text) {
                Ok(result) => response(
                    id,
                    json!({"content":[{"type":"text","text":serde_json::to_string(&result)?}]}),
                ),
                Err(error) => tool_error(id, &error.to_string()),
            }
        }
        "context.forget" => {
            let session = match required_session(args, "context.forget") {
                Ok(session) => session,
                Err(message) => return Ok(tool_error(id, &message)),
            };
            match pipeline.forget(&ScopeId(session.clone())) {
                Ok(()) => response(
                    id,
                    json!({"content":[{"type":"text","text":json!({"session":session,"forgotten":true}).to_string()}]}),
                ),
                Err(error) => tool_error(id, &error.to_string()),
            }
        }
        _ => error_response(id, -32601, "unknown tool"),
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
