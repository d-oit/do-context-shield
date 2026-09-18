//! File-based configuration (`do-context-shield.toml`).
//!
//! Every field is optional: an omitted field keeps the built-in default, and a
//! CLI flag passed on the command line overrides the file value. Unknown
//! fields and unknown plugin names are rejected so that a typo cannot silently
//! change which plugin guards the privacy boundary.

use crate::{ContextArgs, DetectorSelection, PipelineSelection, ProcessArgs, VaultSelection};
use do_context_shield_plugin_api::{DataCategory, ProcessingContext, RecipientClass};
use do_context_shield_plugin_process::DEFAULT_TIMEOUT_MS;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// File name auto-discovered in the working directory.
const CONFIG_FILE_NAME: &str = "do-context-shield.toml";

/// Detector plugin names accepted in the configuration file.
const DETECTORS: [&str; 3] = ["regex", "gliner2", "process"];
/// Policy plugin names accepted in the configuration file.
const POLICIES: [&str; 2] = ["default", "process"];
/// Transformer plugin names accepted in the configuration file.
const TRANSFORMERS: [&str; 2] = ["pseudonymize", "process"];
/// Judge plugin names accepted in the configuration file.
const JUDGES: [&str; 2] = ["heuristics", "process"];
/// Vault plugin names accepted in the configuration file.
const VAULTS: [&str; 3] = ["memory", "json", "process"];
/// Recipient classes accepted in the configuration file.
const RECIPIENTS: [&str; 4] = ["local", "trusted", "external", "unknown"];
/// Data categories accepted in the configuration file.
const DATA_CATEGORIES: [&str; 3] = ["non_personal", "personal", "special_category"];

/// Configuration loaded from `do-context-shield.toml`.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) plugins: Plugins,
    #[serde(default)]
    pub(crate) vault: VaultConfig,
    #[serde(default)]
    pub(crate) context: ContextConfig,
    #[serde(default)]
    pub(crate) process: ProcessConfig,
}

/// Plugin selection; a value here overrides the built-in default and is
/// itself overridden by the matching CLI flag.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plugins {
    pub(crate) detector: Option<String>,
    pub(crate) policy: Option<String>,
    pub(crate) transformer: Option<String>,
    pub(crate) judge: Option<String>,
    pub(crate) model_dir: Option<PathBuf>,
    pub(crate) detector_command: Option<String>,
    pub(crate) policy_command: Option<String>,
    pub(crate) transformer_command: Option<String>,
    pub(crate) judge_command: Option<String>,
}

/// Vault selection and persistence.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultConfig {
    pub(crate) vault: Option<String>,
    pub(crate) vault_file: Option<PathBuf>,
    pub(crate) vault_command: Option<String>,
    pub(crate) vault_ttl_seconds: Option<u64>,
}

/// Default enforcement context for `sanitize`.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContextConfig {
    pub(crate) recipient: Option<String>,
    pub(crate) data_category: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) jurisdiction: Option<String>,
}

/// Process-plugin tuning.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessConfig {
    pub(crate) timeout_ms: Option<u64>,
}

/// Load the configuration file.
///
/// Search order: the explicit `--config <path>`, then `./do-context-shield.toml`,
/// then `$HOME/.config/do-context-shield/config.toml`. Without a file the
/// configuration is empty and every field keeps its built-in default.
///
/// # Errors
///
/// Returns an error when a configuration file exists but cannot be read or
/// parsed, or when an explicit path cannot be read.
pub(crate) fn load(explicit: Option<&Path>) -> Result<Config, Box<dyn std::error::Error>> {
    if let Some(path) = explicit {
        return read(path);
    }
    let candidates = [Some(PathBuf::from(CONFIG_FILE_NAME)), home_config_path()];
    for candidate in candidates.into_iter().flatten() {
        if candidate.is_file() {
            return read(&candidate);
        }
    }
    Ok(Config::default())
}

/// Parse one configuration file, naming it in every error.
///
/// # Errors
///
/// Returns an error when the file cannot be read or is not valid TOML for
/// [`Config`].
fn read(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    let config = toml::from_str(&text)
        .map_err(|e| format!("cannot parse config {}: {e}", path.display()))?;
    Ok(config)
}

/// `$HOME/.config/do-context-shield/config.toml`, if `HOME` is set.
fn home_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/do-context-shield/config.toml"))
}

/// Reject unknown plugin and context names in the file.
///
/// # Errors
///
/// Returns an error naming the field and the accepted values.
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

/// CLI-side selections for one command, before merging with the config file.
#[derive(Default)]
pub(crate) struct CliSelection {
    pub(crate) detector: DetectorSelection,
    pub(crate) pipeline: PipelineSelection,
    pub(crate) vault: VaultSelection,
    pub(crate) vault_file: Option<PathBuf>,
    pub(crate) vault_ttl_seconds: Option<u64>,
    pub(crate) context: ContextArgs,
    pub(crate) process: ProcessArgs,
}

/// Fully resolved plugin selection and context: CLI flag, else config value,
/// else built-in default.
#[derive(Debug)]
pub(crate) struct Resolved {
    pub(crate) detector: String,
    pub(crate) model_dir: Option<PathBuf>,
    pub(crate) detector_command: Option<String>,
    pub(crate) policy: String,
    pub(crate) policy_command: Option<String>,
    pub(crate) transformer: String,
    pub(crate) transformer_command: Option<String>,
    pub(crate) judge: Option<String>,
    pub(crate) judge_command: Option<String>,
    pub(crate) vault: Option<String>,
    pub(crate) vault_file: Option<PathBuf>,
    pub(crate) vault_command: Option<String>,
    pub(crate) vault_ttl_seconds: Option<u64>,
    pub(crate) recipient: String,
    pub(crate) data_category: String,
    pub(crate) purpose: Option<String>,
    pub(crate) jurisdiction: Option<String>,
    pub(crate) process_timeout_ms: u64,
}

impl Resolved {
    /// Build the pipeline enforcement context from the resolved values.
    ///
    /// [`validate`] already restricted the names a file can carry, so the
    /// parse fallback is only a fail-closed backstop (most-restrictive
    /// recipient and data category).
    pub(crate) fn to_context(&self) -> ProcessingContext {
        ProcessingContext {
            purpose: self.purpose.clone(),
            recipient: RecipientClass::parse(&self.recipient).unwrap_or_default(),
            jurisdiction: self.jurisdiction.clone(),
            data_category: DataCategory::parse(&self.data_category).unwrap_or_default(),
        }
    }
}

/// Merge one command's CLI options over the configuration file.
pub(crate) fn resolve(cli: CliSelection, config: &Config) -> Resolved {
    let plugins = &config.plugins;
    let vault = &config.vault;
    let context = &config.context;
    Resolved {
        detector: pick(cli.detector.detector, plugins.detector.as_deref(), "regex"),
        model_dir: cli.detector.model_dir.or_else(|| plugins.model_dir.clone()),
        detector_command: cli
            .detector
            .detector_command
            .or_else(|| plugins.detector_command.clone()),
        policy: pick(cli.pipeline.policy, plugins.policy.as_deref(), "default"),
        policy_command: cli
            .pipeline
            .policy_command
            .or_else(|| plugins.policy_command.clone()),
        transformer: pick(
            cli.pipeline.transformer,
            plugins.transformer.as_deref(),
            "pseudonymize",
        ),
        transformer_command: cli
            .pipeline
            .transformer_command
            .or_else(|| plugins.transformer_command.clone()),
        judge: cli.pipeline.judge.or_else(|| plugins.judge.clone()),
        judge_command: cli
            .pipeline
            .judge_command
            .or_else(|| plugins.judge_command.clone()),
        vault: cli.vault.vault.or_else(|| vault.vault.clone()),
        vault_file: cli.vault_file.or_else(|| vault.vault_file.clone()),
        vault_command: cli
            .vault
            .vault_command
            .or_else(|| vault.vault_command.clone()),
        vault_ttl_seconds: cli.vault_ttl_seconds.or(vault.vault_ttl_seconds),
        recipient: pick(
            cli.context.recipient,
            context.recipient.as_deref(),
            "external",
        ),
        data_category: pick(
            cli.context.data_category,
            context.data_category.as_deref(),
            "personal",
        ),
        purpose: cli.context.purpose.or_else(|| context.purpose.clone()),
        jurisdiction: cli
            .context
            .jurisdiction
            .or_else(|| context.jurisdiction.clone()),
        process_timeout_ms: cli
            .process
            .process_timeout_ms
            .or(config.process.timeout_ms)
            .unwrap_or(DEFAULT_TIMEOUT_MS),
    }
}

/// First non-`None` of the CLI value, the config value, and the built-in
/// default.
fn pick(cli: Option<String>, file: Option<&str>, default: &str) -> String {
    cli.or_else(|| file.map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        CliSelection, Config, ContextConfig, Plugins, ProcessConfig, VaultConfig, resolve, validate,
    };
    use crate::DetectorSelection;
    use do_context_shield_plugin_process::DEFAULT_TIMEOUT_MS;
    use std::path::PathBuf;

    #[test]
    fn empty_config_is_default() -> Result<(), Box<dyn std::error::Error>> {
        let config: Config = toml::from_str("")?;
        assert_eq!(config, Config::default());
        Ok(())
    }

    #[test]
    fn full_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let text = r#"
[plugins]
detector = "gliner2"
policy = "process"
transformer = "process"
judge = "heuristics"
model_dir = "/models/gliner2"
detector_command = "detect-detector"
policy_command = "detect-policy"
transformer_command = "detect-transformer"
judge_command = "detect-judge"

[vault]
vault = "json"
vault_file = "vault.json"
vault_command = "detect-vault"
vault_ttl_seconds = 3600

[context]
recipient = "trusted"
data_category = "special_category"
purpose = "code assistance"
jurisdiction = "DE"

[process]
timeout_ms = 1500
"#;
        let config: Config = toml::from_str(text)?;
        let expected = Config {
            plugins: Plugins {
                detector: Some("gliner2".to_owned()),
                policy: Some("process".to_owned()),
                transformer: Some("process".to_owned()),
                judge: Some("heuristics".to_owned()),
                model_dir: Some(PathBuf::from("/models/gliner2")),
                detector_command: Some("detect-detector".to_owned()),
                policy_command: Some("detect-policy".to_owned()),
                transformer_command: Some("detect-transformer".to_owned()),
                judge_command: Some("detect-judge".to_owned()),
            },
            vault: VaultConfig {
                vault: Some("json".to_owned()),
                vault_file: Some(PathBuf::from("vault.json")),
                vault_command: Some("detect-vault".to_owned()),
                vault_ttl_seconds: Some(3600),
            },
            context: ContextConfig {
                recipient: Some("trusted".to_owned()),
                data_category: Some("special_category".to_owned()),
                purpose: Some("code assistance".to_owned()),
                jurisdiction: Some("DE".to_owned()),
            },
            process: ProcessConfig {
                timeout_ms: Some(1500),
            },
        };
        assert_eq!(config, expected);
        Ok(())
    }

    #[test]
    fn unknown_field_rejected() {
        assert!(toml::from_str::<Config>("[plugins]\nbogus = 1").is_err());
    }

    #[test]
    fn invalid_value_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let detector: Config = toml::from_str("[plugins]\ndetector = \"bogus\"")?;
        assert!(validate(&detector).is_err());
        let recipient: Config = toml::from_str("[context]\nrecipient = \"nope\"")?;
        assert!(validate(&recipient).is_err());
        Ok(())
    }

    #[test]
    fn cli_overrides_config_and_defaults_fill_gaps() -> Result<(), Box<dyn std::error::Error>> {
        let config: Config = toml::from_str(
            "[plugins]\npolicy = \"process\"\n\n[context]\nrecipient = \"local\"\n",
        )?;
        let cli = CliSelection {
            detector: DetectorSelection {
                detector: Some("gliner2".to_owned()),
                ..DetectorSelection::default()
            },
            ..CliSelection::default()
        };
        let resolved = resolve(cli, &config);
        assert_eq!(resolved.detector, "gliner2");
        assert_eq!(resolved.policy, "process");
        assert_eq!(resolved.transformer, "pseudonymize");
        assert_eq!(resolved.recipient, "local");
        assert_eq!(resolved.data_category, "personal");
        assert_eq!(resolved.process_timeout_ms, DEFAULT_TIMEOUT_MS);
        Ok(())
    }
}
