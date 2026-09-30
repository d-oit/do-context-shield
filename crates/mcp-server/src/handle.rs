//! JSON-RPC request handling for the MCP stdio adapter.
//!
//! Split by concern: [`envelope`] builds results and errors, [`protocol`]
//! validates the wire contract, [`tools`] owns the tool catalogue, [`args`]
//! parses `tools/call` arguments, and this module dispatches.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::{ProcessingContext, ScopeId};
use serde_json::{Value, json};

use crate::handle::args::{optional_string, processing_context, required_session, text_argument};
use crate::handle::envelope::{error_response, response, tool_error};
use crate::handle::protocol::{LEGACY_VERSION, MODERN_VERSION, ValidRequest, validate_request};
use crate::handle::tools::tools_list;
use crate::{ToolName, ToolSet};

mod args;
mod envelope;
mod protocol;
mod tools;

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

#[cfg(test)]
mod tests;
