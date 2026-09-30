//! JSON-RPC envelope builders, shared by request validation and dispatch.

use serde_json::{Value, json};

use crate::handle::protocol::{LEGACY_VERSION, MODERN_VERSION};

/// A successful JSON-RPC result: `resultType` and `_meta` are added when the
/// result is an object, `id` is echoed.
pub(super) fn response(id: Value, mut result: Value) -> Value {
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
pub(super) fn error_response(id: Value, code: i32, message: &str) -> Value {
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
pub(super) fn unsupported_version(id: Value, requested: &str) -> Value {
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
pub(super) fn tool_error(id: Value, message: &str) -> Value {
    response(
        id,
        json!({"content":[{"type":"text","text":message}],"isError":true}),
    )
}
