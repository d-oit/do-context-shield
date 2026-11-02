//! Wire protocol: accepted MCP versions, request validation, and the
//! namespaced negotiation metadata.

use serde_json::{Map, Value};

use crate::handle::envelope::{error_response, unsupported_version};

/// Modern MCP revision: no initialize handshake, clients may discover first.
pub(super) const MODERN_VERSION: &str = "2026-07-28";
/// Legacy revision kept for the 2025-era handshake.
pub(super) const LEGACY_VERSION: &str = "2025-11-25";

/// The namespaced MCP request-metadata keys (2026-07-28).
const PROTOCOL_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO_KEY: &str = "io.modelcontextprotocol/clientInfo";

/// Bounds on client-supplied identity metadata. The values are informational
/// only: the server never uses them for authorization or policy.
const MAX_CLIENT_NAME_BYTES: usize = 128;
const MAX_CLIENT_VERSION_BYTES: usize = 64;
/// Bound on a `tools/call` tool name.
const MAX_TOOL_NAME_BYTES: usize = 128;

/// Which protocol era a request selected with its namespaced metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Revision {
    /// `io.modelcontextprotocol/protocolVersion` names the 2026-07-28 revision.
    Modern,
    /// The key names the 2025-11-25 revision.
    Legacy,
    /// No key: a deliberately supported pre-modern client, still answered.
    PreModern,
}

/// A structurally valid JSON-RPC request, after envelope, metadata, and
/// method-parameter checks.
pub(super) struct ValidRequest<'a> {
    pub(super) id: Value,
    pub(super) method: Method<'a>,
}

/// The request method, with its method-specific parameters already validated.
///
/// Dispatch matches this enum rather than the raw method string, so a request
/// that would reach a tool has a tool name and an object `arguments` value by
/// construction; nothing here is re-derived from unvalidated input.
pub(super) enum Method<'a> {
    /// `server/discover`: no parameters beyond `_meta`.
    Discover,
    /// `initialize`: the legacy handshake, absent from the modern revision.
    Initialize,
    /// `tools/list`: no parameters beyond `_meta` (pagination is not offered).
    ToolsList,
    /// `tools/call`: a bounded non-empty tool name and optional object arguments.
    ToolsCall {
        name: &'a str,
        arguments: Option<&'a Value>,
    },
    /// An unknown method; dispatch answers `-32601` without touching a plugin.
    Unknown,
}

/// A valid JSON-RPC request id is a string or an integer number.
fn valid_id(value: &Value) -> bool {
    value.is_string() || value.is_i64() || value.is_u64()
}

/// A non-empty client string within its byte bound.
fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

/// Validate one parsed line as a JSON-RPC 2.0 request for this server.
///
/// Returns `Ok(None)` for a notification — a structurally valid message with
/// no `id` — so it can never reach dispatch, and with it never sanitize,
/// restore, or delete state. `Err(response)` carries the protocol error to
/// emit. Checks run in wire order: envelope (`-32600`), `id` (`-32600`),
/// `params` shape (`-32602`), the namespaced protocol metadata
/// (`-32602`/`-32022`), then the method-specific parameter schema
/// (`-32602`), so invalid parameters are rejected before dispatch and can
/// never reach the sanitizer, vault, plugins, or audit sink.
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
    let revision = check_protocol_metadata(&id, params)?;
    let method = check_method_params(&id, method, params, revision)?;
    Ok(Some(ValidRequest { id, method }))
}

/// Enforce the namespaced protocol metadata of a request.
///
/// The version and capabilities keys are read only from `params._meta`; the
/// pre-2026 bare `protocolVersion` is not the wire contract. A request that
/// carries the version key must name a supported version and come with
/// capabilities; the checks run before dispatch, so a `tools/call` for an
/// unnegotiated revision never executes. `clientInfo` is validated when
/// supplied — an object with non-empty bounded `name` and `version` strings —
/// but remains informational: it never selects a tool, scope, or policy. A
/// request without the version key keeps the legacy behavior and gets one
/// stderr warning naming the wire key.
fn check_protocol_metadata(id: &Value, params: Option<&Value>) -> Result<Revision, Value> {
    let meta = params.and_then(|params| params.get("_meta"));
    let meta = match meta {
        Some(meta) if meta.is_object() => Some(meta),
        Some(_) => {
            return Err(error_response(
                id.clone(),
                -32602,
                "`params._meta` must be a JSON object",
            ));
        }
        None => None,
    };
    check_client_info(id, meta.and_then(|meta| meta.get(CLIENT_INFO_KEY)))?;
    let Some(version) = meta.and_then(|meta| meta.get(PROTOCOL_VERSION_KEY)) else {
        eprintln!(
            "do-context-shield: request without `params._meta[\"{PROTOCOL_VERSION_KEY}\"]`; assuming a pre-2026 client"
        );
        return Ok(Revision::PreModern);
    };
    let Some(version) = version.as_str() else {
        return Err(error_response(
            id.clone(),
            -32602,
            "`io.modelcontextprotocol/protocolVersion` must be a string",
        ));
    };
    let revision = match version {
        MODERN_VERSION => Revision::Modern,
        LEGACY_VERSION => Revision::Legacy,
        _ => return Err(unsupported_version(id.clone(), version)),
    };
    let capabilities = meta.and_then(|meta| meta.get(CLIENT_CAPABILITIES_KEY));
    if !capabilities.is_some_and(Value::is_object) {
        return Err(error_response(
            id.clone(),
            -32602,
            "`io.modelcontextprotocol/clientCapabilities` must be an object",
        ));
    }
    Ok(revision)
}

/// Validate client identity metadata when it is supplied.
///
/// `clientInfo` is optional, but when present it must be an object with
/// non-empty bounded `name` and `version` strings. Unknown sibling keys are
/// extensions and stay accepted; the identity itself is untrusted metadata and
/// is never used for authorization.
fn check_client_info(id: &Value, info: Option<&Value>) -> Result<(), Value> {
    let Some(info) = info else {
        return Ok(());
    };
    let Some(info) = info.as_object() else {
        return Err(error_response(
            id.clone(),
            -32602,
            "client identity metadata must be a JSON object",
        ));
    };
    let name = info.get("name").and_then(Value::as_str);
    let version = info.get("version").and_then(Value::as_str);
    let valid = name.is_some_and(|name| bounded(name, MAX_CLIENT_NAME_BYTES))
        && version.is_some_and(|version| bounded(version, MAX_CLIENT_VERSION_BYTES));
    if !valid {
        return Err(error_response(
            id.clone(),
            -32602,
            "client identity metadata requires non-empty bounded `name` and `version` strings",
        ));
    }
    Ok(())
}

/// Reject parameters the method does not implement.
///
/// `_meta` is always accepted: it carries the namespaced protocol metadata and
/// extension fields, which are deliberately not over-validated. The message
/// names the accepted parameters instead of echoing the submitted key, so a
/// request cannot smuggle text into an error.
fn reject_extra_params(
    id: &Value,
    params: Option<&Map<String, Value>>,
    allowed: &[&str],
    message: &str,
) -> Result<(), Value> {
    let Some(params) = params else {
        return Ok(());
    };
    if params
        .keys()
        .any(|key| key != "_meta" && !allowed.contains(&key.as_str()))
    {
        return Err(error_response(id.clone(), -32602, message));
    }
    Ok(())
}

/// Validate the method-specific parameter schema.
fn check_method_params<'a>(
    id: &Value,
    method: &'a str,
    params: Option<&'a Value>,
    revision: Revision,
) -> Result<Method<'a>, Value> {
    let params = params.and_then(Value::as_object);
    match method {
        "server/discover" => {
            reject_extra_params(
                id,
                params,
                &[],
                "`server/discover` accepts no parameters besides `_meta`",
            )?;
            Ok(Method::Discover)
        }
        "initialize" => check_initialize(id, params, revision),
        "tools/list" => {
            reject_extra_params(
                id,
                params,
                &[],
                "`tools/list` implements no pagination and accepts no parameters besides `_meta`",
            )?;
            Ok(Method::ToolsList)
        }
        "tools/call" => check_tools_call(id, params),
        _ => Ok(Method::Unknown),
    }
}

/// Validate the legacy `initialize` parameters.
///
/// The modern revision removed the handshake, so a request that negotiated
/// modern metadata may not call it. Legacy fields are typed when present;
/// clients commonly send `{}`, which stays accepted.
fn check_initialize(
    id: &Value,
    params: Option<&Map<String, Value>>,
    revision: Revision,
) -> Result<Method<'static>, Value> {
    if revision == Revision::Modern {
        return Err(error_response(
            id.clone(),
            -32602,
            "`initialize` is not part of the 2026-07-28 revision; use `server/discover` instead",
        ));
    }
    reject_extra_params(
        id,
        params,
        &["protocolVersion", "capabilities", "clientInfo"],
        "`initialize` accepts only `protocolVersion`, `capabilities`, `clientInfo`, and `_meta`",
    )?;
    let Some(params) = params else {
        return Ok(Method::Initialize);
    };
    if let Some(version) = params.get("protocolVersion") {
        let Some(version) = version.as_str() else {
            return Err(error_response(
                id.clone(),
                -32602,
                "`protocolVersion` must be a string",
            ));
        };
        if version != MODERN_VERSION && version != LEGACY_VERSION {
            return Err(unsupported_version(id.clone(), version));
        }
    }
    if let Some(capabilities) = params.get("capabilities")
        && !capabilities.is_object()
    {
        return Err(error_response(
            id.clone(),
            -32602,
            "`capabilities` must be a JSON object",
        ));
    }
    check_client_info(id, params.get("clientInfo"))?;
    Ok(Method::Initialize)
}

/// Validate `tools/call` parameters: a required bounded `name`, an optional
/// object `arguments`, and no unsupported task/request fields.
fn check_tools_call<'a>(
    id: &Value,
    params: Option<&'a Map<String, Value>>,
) -> Result<Method<'a>, Value> {
    let Some(params) = params else {
        return Err(error_response(
            id.clone(),
            -32602,
            "`tools/call` requires `name` and optional `arguments` parameters",
        ));
    };
    reject_extra_params(
        id,
        Some(params),
        &["name", "arguments"],
        "`tools/call` accepts only `name`, `arguments`, and `_meta`; tasks and request fields are not implemented",
    )?;
    let name = params.get("name").and_then(Value::as_str);
    let Some(name) = name.filter(|name| bounded(name, MAX_TOOL_NAME_BYTES)) else {
        return Err(error_response(
            id.clone(),
            -32602,
            "`tools/call` requires a non-empty bounded string `name`",
        ));
    };
    let arguments = match params.get("arguments") {
        None => None,
        Some(arguments) if arguments.is_object() => Some(arguments),
        Some(_) => {
            return Err(error_response(
                id.clone(),
                -32602,
                "`arguments` must be a JSON object",
            ));
        }
    };
    Ok(Method::ToolsCall { name, arguments })
}
