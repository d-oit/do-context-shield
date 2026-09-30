//! Argument parsing for `tools/call`: the enforcement context and the shared
//! string/session readers.

use do_context_shield_plugin_api::{
    DataCategory, ProcessingContext, RecipientClass, is_valid_jurisdiction,
};
use serde_json::Value;

/// Parse the optional enforcement-context arguments of `context.sanitize`.
///
/// Omitted fields fall back to `base`, the server's configured context (by
/// default the most restrictive one: external recipient, personal data, no
/// purpose or jurisdiction). An unknown enum name, a wrong JSON type, or a
/// malformed jurisdiction is an error, never a silent downgrade to a weaker
/// context: an invalid explicit override does not fall back to a valid server
/// default either.
pub(super) fn processing_context(
    args: &Value,
    base: &ProcessingContext,
) -> Result<ProcessingContext, String> {
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
pub(super) fn optional_string(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

/// Read the required `text` argument of a tool that declares it.
pub(super) fn text_argument(args: &Value, tool: &str) -> Result<String, String> {
    match optional_string(args, "text") {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Err(format!("{tool} requires a string `text` argument")),
        Err(message) => Err(message),
    }
}

/// Read the explicit `session` that resolving and deleting tools require.
pub(super) fn required_session(args: &Value, tool: &str) -> Result<String, String> {
    match optional_string(args, "session") {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(format!("{tool} requires an explicit session")),
        Err(message) => Err(message),
    }
}
