use super::{
    Config, DATA_CATEGORIES, DETECTORS, JUDGES, POLICIES, RECIPIENTS, TRANSFORMERS, ToolSet,
    VAULTS, vault,
};
use do_context_shield_plugin_api::is_valid_jurisdiction;
/// Reject unknown plugin and context names, and contradictory vault
/// combinations, in the file.
///
/// # Errors
///
/// Returns an error naming the offending field and the accepted values.
pub(crate) fn validate(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let plugins = &config.plugins;
    let vault = &config.vault;
    let context = &config.context;
    let fields = [
        (
            plugins.detector.as_deref(),
            "detector",
            DETECTORS.as_slice(),
        ),
        (plugins.policy.as_deref(), "policy", POLICIES.as_slice()),
        (
            plugins.transformer.as_deref(),
            "transformer",
            TRANSFORMERS.as_slice(),
        ),
        (plugins.judge.as_deref(), "judge", JUDGES.as_slice()),
        (vault.vault.as_deref(), "vault", VAULTS.as_slice()),
        (
            context.recipient.as_deref(),
            "recipient",
            RECIPIENTS.as_slice(),
        ),
        (
            context.data_category.as_deref(),
            "data_category",
            DATA_CATEGORIES.as_slice(),
        ),
    ];
    for (value, field, allowed) in fields {
        if let Some(value) = value {
            validate_choice(value, field, allowed)?;
        }
    }
    if let Some(tools) = plugins.tools.as_deref() {
        ToolSet::parse(tools)
            .map_err(|error| format!("config: invalid `tools` value `{tools}`: {error}"))?;
    }
    if let Some(jurisdiction) = context.jurisdiction.as_deref() {
        validate_jurisdiction(jurisdiction)?;
    }
    vault::validate_vault(&config.vault)
}

/// Reject a `jurisdiction` that is not an ISO 3166-1 alpha-2 code.
///
/// The value is forwarded to policies as written, so a typo (`DEU`, `Germany`,
/// `de-DE`) would silently reach policy decisions that compare it against
/// two-letter codes. The predicate is the shared
/// [`is_valid_jurisdiction`], so the file, the environment, the CLI flag, and
/// the MCP arguments enforce one contract.
///
/// # Errors
///
/// Returns an error naming the field and the rejected value.
fn validate_jurisdiction(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !is_valid_jurisdiction(value) {
        return Err(format!(
            "config: `jurisdiction` must be an ISO 3166-1 alpha-2 code, got `{value}`"
        )
        .into());
    }
    Ok(())
}

/// Reject a value that is not one of the accepted names.
///
/// # Errors
///
/// Returns an error naming the field, the rejected value, and the accepted
/// values.
fn validate_choice(
    value: &str,
    field: &str,
    allowed: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    if !allowed.contains(&value) {
        return Err(format!(
            "config: unknown {field} `{value}` (allowed: {})",
            allowed.join(", ")
        )
        .into());
    }
    Ok(())
}
