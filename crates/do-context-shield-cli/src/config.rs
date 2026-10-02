//! File-based configuration (`do-context-shield.toml`).
//!
//! Every field is optional: an omitted field keeps the built-in default, a
//! `DO_CONTEXT_SHIELD_*` environment variable (see [`env`]) overrides the file
//! value, and a CLI flag passed on the command line overrides both. Unknown
//! fields and unknown plugin names are rejected so that a typo cannot silently
//! change which plugin guards the privacy boundary.

use crate::cli::{ContextArgs, DetectorSelection, PipelineSelection, ProcessArgs, VaultSelection};
use do_context_shield_mcp_server::ToolSet;
use do_context_shield_plugin_api::{DataCategory, ProcessingContext, RecipientClass};
use do_context_shield_plugin_process::DEFAULT_TIMEOUT_MS;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub(crate) mod diag;
mod env;
mod validation;
mod vault;

pub(crate) use validation::validate;

pub(crate) use vault::{VaultKind, json_vault_file, vault_kind};

/// File name auto-discovered in the working directory.
const CONFIG_FILE_NAME: &str = "do-context-shield.toml";

/// Detector plugin names accepted in the configuration file.
const DETECTORS: [&str; 4] = ["regex", "gliner2", "hybrid", "process"];
/// Policy plugin names accepted in the configuration file.
const POLICIES: [&str; 2] = ["default", "process"];
/// Transformer plugin names accepted in the configuration file.
const TRANSFORMERS: [&str; 4] = ["pseudonymize", "generalize", "mask", "process"];
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
    pub(crate) audit: AuditConfig,
    #[serde(default)]
    pub(crate) context: ContextConfig,
    #[serde(default)]
    pub(crate) process: ProcessConfig,
    /// Which settings the environment layer supplied, for [`diag`]; the file
    /// schema has no `env` key, so this is never read from or written to disk.
    #[serde(skip)]
    pub(crate) env: env::EnvSet,
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
    pub(crate) tools: Option<String>,
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
    pub(crate) vault_key_file: Option<PathBuf>,
}

/// Optional local audit-log destination.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditConfig {
    pub(crate) audit_file: Option<PathBuf>,
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

/// Load the configuration file, then apply environment overrides.
///
/// Search order: the explicit `--config <path>`, then `./do-context-shield.toml`,
/// then `$HOME/.config/do-context-shield/config.toml`. Without a file the
/// configuration is empty and every field keeps its built-in default. A
/// `DO_CONTEXT_SHIELD_*` environment variable (see [`env`]) overrides the file
/// value; a CLI flag still overrides both.
///
/// # Errors
///
/// Returns an error when a configuration file exists but cannot be read or
/// parsed, when an explicit path cannot be read, or when an environment
/// override is not a valid value. A missing explicit path is an error; a
/// candidate that does not exist is simply not selected.
pub(crate) fn load(explicit: Option<&Path>) -> Result<Config, Box<dyn std::error::Error>> {
    let config = match explicit {
        Some(path) => read(path)?,
        None => read_discovered()?,
    };
    apply_env(config)
}

/// Load the configuration for a command that must not read an ambient file:
/// only the explicit `--config <path>` is honoured; without it every field
/// keeps its built-in default.
///
/// `mcp-stdio` uses this loader. An MCP client spawns the server with the
/// project as its working directory, so auto-discovery would let a repository
/// file select process plugins, loosen `[context]`, or expose
/// `context.restore` merely by being the server's cwd. Trusted
/// `DO_CONTEXT_SHIELD_*` environment overrides still apply.
///
/// # Errors
///
/// Returns an error when the explicit path cannot be read or parsed, or when
/// an environment override is not a valid value. A missing explicit path is an
/// error, never a silent fallback to defaults.
pub(crate) fn load_explicit(explicit: Option<&Path>) -> Result<Config, Box<dyn std::error::Error>> {
    let config = match explicit {
        Some(path) => read(path)?,
        None => Config::default(),
    };
    apply_env(config)
}

/// Apply `DO_CONTEXT_SHIELD_*` overrides to a loaded configuration.
///
/// # Errors
///
/// Returns an error when an override is not a valid value.
fn apply_env(mut config: Config) -> Result<Config, Box<dyn std::error::Error>> {
    env::apply(&mut config)?;
    Ok(config)
}

/// The first existing auto-discovery candidate, else an empty configuration.
///
/// # Errors
///
/// Returns an error when a discovered file cannot be read or parsed.
fn read_discovered() -> Result<Config, Box<dyn std::error::Error>> {
    let candidates = [Some(PathBuf::from(CONFIG_FILE_NAME)), home_config_path()];
    for candidate in candidates.into_iter().flatten() {
        // Existence, not `is_file()`: a candidate that exists but is not a
        // regular file (a directory of that name, a dangling symlink) is a
        // broken setup, not an absent one, and must fail instead of falling
        // through to the next candidate.
        if candidate.symlink_metadata().is_ok() {
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

/// CLI-side selections for one command, before merging with the config file.
#[derive(Clone, Default)]
pub(crate) struct CliSelection {
    pub(crate) detector: DetectorSelection,
    pub(crate) pipeline: PipelineSelection,
    pub(crate) vault: VaultSelection,
    pub(crate) vault_file: Option<PathBuf>,
    pub(crate) vault_key_file: Option<PathBuf>,
    pub(crate) audit_file: Option<PathBuf>,
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
    pub(crate) vault_key_file: Option<PathBuf>,
    pub(crate) audit_file: Option<PathBuf>,
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
pub(crate) fn resolve(cli: &CliSelection, config: &Config) -> Resolved {
    let cli = cli.clone();
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
        vault_key_file: cli.vault_key_file.or_else(|| vault.vault_key_file.clone()),
        audit_file: cli.audit_file.or_else(|| config.audit.audit_file.clone()),
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

/// MCP tool surface: the `--tools` flag, else the configured list, else the
/// model-facing default.
///
/// # Errors
///
/// Returns an error when the configured value is not a valid tool list. The
/// file and environment are validated at load time, so this fires only for a
/// configuration built in-process without validation.
pub(crate) fn resolve_tools(
    cli: Option<ToolSet>,
    config: &Config,
) -> Result<ToolSet, Box<dyn std::error::Error>> {
    match cli {
        Some(tools) => Ok(tools),
        None => match config.plugins.tools.as_deref() {
            Some(list) => Ok(ToolSet::parse(list)?),
            None => Ok(ToolSet::default()),
        },
    }
}

#[cfg(test)]
mod tests;
