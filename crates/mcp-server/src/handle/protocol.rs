//! Wire protocol: accepted MCP versions, request validation, and the
//! namespaced negotiation metadata.

use serde_json::Value;

use crate::handle::envelope::{error_response, unsupported_version};

/// Modern MCP revision: no initialize handshake, clients may discover first.
pub(super) const MODERN_VERSION: &str = "2026-07-28";
/// Legacy revision kept for the 2025-era handshake.
pub(super) const LEGACY_VERSION: &str = "2025-11-25";

/// The namespaced MCP request-metadata keys (2026-07-28).
const PROTOCOL_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// A structurally valid JSON-RPC request, after envelope and metadata checks.
pub(super) struct ValidRequest<'a> {
    pub(super) id: Value,
    pub(super) method: &'a str,
    pub(super) params: Option<&'a Value>,
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
pub(super) fn validate_request(request: &Value) -> Result<Option<ValidRequest<'_>>, Value> {
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
