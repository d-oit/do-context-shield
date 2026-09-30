//! Tool catalogue: `context.*` names, JSON schemas, and the `tools/list`
//! payload.

use serde_json::{Value, json};

use crate::{ToolName, ToolSet};

/// Tool catalogue. Only enabled tools are listed, in a fixed order so clients
/// can cache reliably; `cacheScope` follows the 2026-07-28 `CacheableResult`
/// vocabulary (`public`/`private`) because results are session-scoped.
pub(super) fn tools_list(tools: ToolSet) -> Value {
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

    /// The tool a full `context.*` name selects, if any.
    pub(super) fn from_full(name: &str) -> Option<Self> {
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
