//! `DO_CONTEXT_SHIELD_*` environment overrides, applied over the file values.
//!
//! Precedence is CLI flag > environment variable > file value > built-in
//! default: [`apply`] runs after the file is read, and every CLI flag still
//! wins in [`super::resolve`]. An unset or empty variable keeps the file value.

use super::{
    Config, DATA_CATEGORIES, DETECTORS, JUDGES, POLICIES, RECIPIENTS, TRANSFORMERS, VAULTS,
};
use do_context_shield_mcp_server::ToolSet;
use std::path::PathBuf;

/// Apply environment overrides onto `config`.
///
/// # Errors
///
/// Returns an error naming the variable when a value is not one of the
/// accepted names, is not a whole number of seconds, or is not a valid tool
/// list.
pub(super) fn apply(config: &mut Config) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(value) = var("DO_CONTEXT_SHIELD_DETECTOR") {
        checked(&value, "DO_CONTEXT_SHIELD_DETECTOR", "detector", &DETECTORS)?;
        config.plugins.detector = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_POLICY") {
        checked(&value, "DO_CONTEXT_SHIELD_POLICY", "policy", &POLICIES)?;
        config.plugins.policy = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_TRANSFORMER") {
        checked(
            &value,
            "DO_CONTEXT_SHIELD_TRANSFORMER",
            "transformer",
            &TRANSFORMERS,
        )?;
        config.plugins.transformer = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_JUDGE") {
        checked(&value, "DO_CONTEXT_SHIELD_JUDGE", "judge", &JUDGES)?;
        config.plugins.judge = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_TOOLS") {
        ToolSet::parse(&value).map_err(|error| {
            format!(
                "environment variable DO_CONTEXT_SHIELD_TOOLS: invalid tool list `{value}`: {error}"
            )
        })?;
        config.plugins.tools = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT") {
        checked(&value, "DO_CONTEXT_SHIELD_VAULT", "vault", &VAULTS)?;
        config.vault.vault = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT_FILE") {
        config.vault.vault_file = Some(PathBuf::from(value));
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS") {
        let seconds = value.parse::<u64>().map_err(|error| {
            format!(
                "environment variable DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS: `{value}` is not a whole number of seconds: {error}"
            )
        })?;
        config.vault.vault_ttl_seconds = Some(seconds);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_RECIPIENT") {
        checked(
            &value,
            "DO_CONTEXT_SHIELD_RECIPIENT",
            "recipient",
            &RECIPIENTS,
        )?;
        config.context.recipient = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_DATA_CATEGORY") {
        checked(
            &value,
            "DO_CONTEXT_SHIELD_DATA_CATEGORY",
            "data_category",
            &DATA_CATEGORIES,
        )?;
        config.context.data_category = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_PURPOSE") {
        config.context.purpose = Some(value);
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_JURISDICTION") {
        config.context.jurisdiction = Some(value);
    }
    Ok(())
}

/// One non-empty environment variable; empty values keep the file value.
fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Reject a value that is not one of the accepted names, naming the variable.
///
/// # Errors
///
/// Returns an error naming the variable, the field, the rejected value, and
/// the accepted values.
fn checked(
    value: &str,
    name: &str,
    field: &str,
    allowed: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    if !allowed.contains(&value) {
        return Err(format!(
            "environment variable {name}: unknown {field} `{value}` (allowed: {})",
            allowed.join(", ")
        )
        .into());
    }
    Ok(())
}
