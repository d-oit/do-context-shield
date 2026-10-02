//! `DO_CONTEXT_SHIELD_*` environment overrides, applied over the file values.
//!
//! Precedence is CLI flag > environment variable > file value > built-in
//! default: [`apply`] runs after the file is read, and every CLI flag still
//! wins in [`super::resolve`]. An unset or empty variable keeps the file value.
//! Every applied variable is recorded in [`EnvSet`], which the
//! effective-configuration diagnostics read to name the supplying layer.

use super::{
    Config, DATA_CATEGORIES, DETECTORS, JUDGES, POLICIES, RECIPIENTS, TRANSFORMERS, VAULTS,
};
use do_context_shield_mcp_server::ToolSet;
use std::path::PathBuf;

/// One flag per `DO_CONTEXT_SHIELD_*` variable [`apply`] recognises.
///
/// A flag is set when the variable held a non-empty value and its value was
/// applied, whatever the file said; the merged value alone cannot distinguish
/// the environment layer from the file, so the source is recorded here.
// Named booleans are the representation: a bitset would hide which variable
// each flag answers for.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct EnvSet {
    pub(crate) detector: bool,
    pub(crate) policy: bool,
    pub(crate) transformer: bool,
    pub(crate) judge: bool,
    pub(crate) tools: bool,
    pub(crate) vault: bool,
    pub(crate) vault_file: bool,
    pub(crate) vault_key_file: bool,
    pub(crate) audit_file: bool,
    pub(crate) vault_ttl_seconds: bool,
    pub(crate) recipient: bool,
    pub(crate) data_category: bool,
    pub(crate) purpose: bool,
    pub(crate) jurisdiction: bool,
}

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
        config.env.detector = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_POLICY") {
        checked(&value, "DO_CONTEXT_SHIELD_POLICY", "policy", &POLICIES)?;
        config.plugins.policy = Some(value);
        config.env.policy = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_TRANSFORMER") {
        checked(
            &value,
            "DO_CONTEXT_SHIELD_TRANSFORMER",
            "transformer",
            &TRANSFORMERS,
        )?;
        config.plugins.transformer = Some(value);
        config.env.transformer = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_JUDGE") {
        checked(&value, "DO_CONTEXT_SHIELD_JUDGE", "judge", &JUDGES)?;
        config.plugins.judge = Some(value);
        config.env.judge = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_TOOLS") {
        ToolSet::parse(&value).map_err(|error| {
            format!(
                "environment variable DO_CONTEXT_SHIELD_TOOLS: invalid tool list `{value}`: {error}"
            )
        })?;
        config.plugins.tools = Some(value);
        config.env.tools = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT") {
        checked(&value, "DO_CONTEXT_SHIELD_VAULT", "vault", &VAULTS)?;
        config.vault.vault = Some(value);
        config.env.vault = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT_FILE") {
        config.vault.vault_file = Some(PathBuf::from(value));
        config.env.vault_file = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT_KEY_FILE") {
        config.vault.vault_key_file = Some(PathBuf::from(value));
        config.env.vault_key_file = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_AUDIT_FILE") {
        config.audit.audit_file = Some(PathBuf::from(value));
        config.env.audit_file = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS") {
        let seconds = value.parse::<u64>().map_err(|error| {
            format!(
                "environment variable DO_CONTEXT_SHIELD_VAULT_TTL_SECONDS: `{value}` is not a whole number of seconds: {error}"
            )
        })?;
        config.vault.vault_ttl_seconds = Some(seconds);
        config.env.vault_ttl_seconds = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_RECIPIENT") {
        checked(
            &value,
            "DO_CONTEXT_SHIELD_RECIPIENT",
            "recipient",
            &RECIPIENTS,
        )?;
        config.context.recipient = Some(value);
        config.env.recipient = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_DATA_CATEGORY") {
        checked(
            &value,
            "DO_CONTEXT_SHIELD_DATA_CATEGORY",
            "data_category",
            &DATA_CATEGORIES,
        )?;
        config.context.data_category = Some(value);
        config.env.data_category = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_PURPOSE") {
        config.context.purpose = Some(value);
        config.env.purpose = true;
    }
    if let Some(value) = var("DO_CONTEXT_SHIELD_JURISDICTION") {
        config.context.jurisdiction = Some(value);
        config.env.jurisdiction = true;
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
