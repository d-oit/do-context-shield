//! Effective-configuration diagnostics for the `config` command.
//!
//! The report is a whitelist: validated plugin and vault names, enforcement
//! context values (recipient, data category, jurisdiction), numeric limits,
//! and presence booleans for path- and command-shaped settings, each with the
//! layer that supplied it (CLI flag > environment > file > built-in default).
//! Raw process commands, filesystem paths, key material, and free-form
//! `purpose` values never appear, so the report is safe to hand to an agent.

use super::{CliSelection, Config, VaultKind, resolve, vault_kind};
use serde::Serialize;

/// The configuration layer that supplied a setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Source {
    /// A CLI flag on this invocation.
    Cli,
    /// A `DO_CONTEXT_SHIELD_*` environment variable.
    Environment,
    /// The configuration file.
    File,
    /// The built-in default.
    Default,
    /// Not configured (optional settings only).
    None,
}

/// A setting with a built-in default.
#[derive(Debug, Serialize)]
pub(crate) struct Named {
    pub(crate) value: String,
    pub(crate) source: Source,
}

/// An optional setting whose value is a name.
#[derive(Debug, Serialize)]
pub(crate) struct MaybeNamed {
    pub(crate) value: Option<String>,
    pub(crate) source: Source,
}

/// An optional setting whose value is a number.
#[derive(Debug, Serialize)]
pub(crate) struct MaybeNumber {
    pub(crate) value: Option<u64>,
    pub(crate) source: Source,
}

/// A setting with a built-in numeric default.
#[derive(Debug, Serialize)]
pub(crate) struct Number {
    pub(crate) value: u64,
    pub(crate) source: Source,
}

/// A presence-only setting: a path, a command line, a key file, or a
/// free-form value whose text is never reported.
#[derive(Debug, Serialize)]
pub(crate) struct Presence {
    pub(crate) configured: bool,
    pub(crate) source: Source,
}

/// The reported enforcement context.
#[derive(Debug, Serialize)]
pub(crate) struct Context {
    pub(crate) recipient: Named,
    pub(crate) data_category: Named,
    pub(crate) jurisdiction: MaybeNamed,
    pub(crate) purpose: Presence,
}

/// The whitelisted effective configuration for one CLI selection.
#[derive(Debug, Serialize)]
pub(crate) struct Explained {
    pub(crate) detector: Named,
    pub(crate) policy: Named,
    pub(crate) transformer: Named,
    pub(crate) judge: MaybeNamed,
    pub(crate) vault: MaybeNamed,
    pub(crate) effective_vault: String,
    pub(crate) vault_file: Presence,
    pub(crate) audit_file: Presence,
    pub(crate) vault_key_file: Presence,
    pub(crate) vault_ttl_seconds: MaybeNumber,
    pub(crate) model_dir: Presence,
    pub(crate) detector_command: Presence,
    pub(crate) policy_command: Presence,
    pub(crate) transformer_command: Presence,
    pub(crate) judge_command: Presence,
    pub(crate) vault_command: Presence,
    pub(crate) context: Context,
    pub(crate) process_timeout_ms: Number,
}

/// Report the effective configuration for one command's CLI selection.
///
/// # Errors
///
/// Returns the same vault-selection conflict the executing command would
/// report when the resolved selection cannot name one consistent vault.
pub(crate) fn explain(
    cli: &CliSelection,
    config: &Config,
) -> Result<Explained, Box<dyn std::error::Error>> {
    let resolved = resolve(cli, config);
    let env = &config.env;
    let effective_vault = match vault_kind(&resolved)? {
        VaultKind::Process => "process",
        VaultKind::Json => "json",
        VaultKind::Memory => "memory",
    };
    Ok(Explained {
        detector: named(
            &resolved.detector,
            cli.detector.detector.is_some(),
            env.detector,
            config.plugins.detector.is_some(),
        ),
        policy: named(
            &resolved.policy,
            cli.pipeline.policy.is_some(),
            env.policy,
            config.plugins.policy.is_some(),
        ),
        transformer: named(
            &resolved.transformer,
            cli.pipeline.transformer.is_some(),
            env.transformer,
            config.plugins.transformer.is_some(),
        ),
        judge: maybe_named(
            resolved.judge.as_deref(),
            cli.pipeline.judge.is_some(),
            env.judge,
            config.plugins.judge.is_some(),
        ),
        vault: maybe_named(
            resolved.vault.as_deref(),
            cli.vault.vault.is_some(),
            env.vault,
            config.vault.vault.is_some(),
        ),
        effective_vault: effective_vault.to_owned(),
        vault_file: presence(
            cli.vault_file.is_some(),
            env.vault_file,
            config.vault.vault_file.is_some(),
        ),
        audit_file: presence(
            cli.audit_file.is_some(),
            env.audit_file,
            config.audit.audit_file.is_some(),
        ),
        vault_key_file: presence(
            cli.vault_key_file.is_some(),
            env.vault_key_file,
            config.vault.vault_key_file.is_some(),
        ),
        vault_ttl_seconds: maybe_number(
            resolved.vault_ttl_seconds,
            cli.vault_ttl_seconds.is_some(),
            env.vault_ttl_seconds,
            config.vault.vault_ttl_seconds.is_some(),
        ),
        model_dir: presence(
            cli.detector.model_dir.is_some(),
            false,
            config.plugins.model_dir.is_some(),
        ),
        detector_command: presence(
            cli.detector.detector_command.is_some(),
            false,
            config.plugins.detector_command.is_some(),
        ),
        policy_command: presence(
            cli.pipeline.policy_command.is_some(),
            false,
            config.plugins.policy_command.is_some(),
        ),
        transformer_command: presence(
            cli.pipeline.transformer_command.is_some(),
            false,
            config.plugins.transformer_command.is_some(),
        ),
        judge_command: presence(
            cli.pipeline.judge_command.is_some(),
            false,
            config.plugins.judge_command.is_some(),
        ),
        vault_command: presence(
            cli.vault.vault_command.is_some(),
            false,
            config.vault.vault_command.is_some(),
        ),
        context: context(cli, config, &resolved),
        process_timeout_ms: number(
            resolved.process_timeout_ms,
            cli.process.process_timeout_ms.is_some(),
            false,
            config.process.timeout_ms.is_some(),
        ),
    })
}

/// The reported enforcement context.
fn context(cli: &CliSelection, config: &Config, resolved: &super::Resolved) -> Context {
    let env = &config.env;
    Context {
        recipient: named(
            &resolved.recipient,
            cli.context.recipient.is_some(),
            env.recipient,
            config.context.recipient.is_some(),
        ),
        data_category: named(
            &resolved.data_category,
            cli.context.data_category.is_some(),
            env.data_category,
            config.context.data_category.is_some(),
        ),
        jurisdiction: maybe_named(
            resolved.jurisdiction.as_deref(),
            cli.context.jurisdiction.is_some(),
            env.jurisdiction,
            config.context.jurisdiction.is_some(),
        ),
        purpose: presence(
            cli.context.purpose.is_some(),
            env.purpose,
            config.context.purpose.is_some(),
        ),
    }
}

/// A named setting with a built-in default.
fn named(value: &str, cli: bool, environment: bool, merged: bool) -> Named {
    Named {
        value: value.to_owned(),
        source: with_default(cli, environment, merged),
    }
}

/// An optional named setting.
fn maybe_named(value: Option<&str>, cli: bool, environment: bool, merged: bool) -> MaybeNamed {
    MaybeNamed {
        value: value.map(str::to_owned),
        source: optional(cli, environment, merged),
    }
}

/// An optional numeric setting.
fn maybe_number(value: Option<u64>, cli: bool, environment: bool, merged: bool) -> MaybeNumber {
    MaybeNumber {
        value,
        source: optional(cli, environment, merged),
    }
}

/// A numeric setting with a built-in default.
fn number(value: u64, cli: bool, environment: bool, merged: bool) -> Number {
    Number {
        value,
        source: with_default(cli, environment, merged),
    }
}

/// Layer for a setting that has a built-in default.
fn with_default(cli: bool, environment: bool, merged: bool) -> Source {
    if cli {
        Source::Cli
    } else if environment {
        Source::Environment
    } else if merged {
        Source::File
    } else {
        Source::Default
    }
}

/// Layer for a setting that is unset unless a layer supplies it.
fn optional(cli: bool, environment: bool, merged: bool) -> Source {
    if cli {
        Source::Cli
    } else if environment {
        Source::Environment
    } else if merged {
        Source::File
    } else {
        Source::None
    }
}

/// Presence-only report for a path-, command-, key-, or free-form setting.
fn presence(cli: bool, environment: bool, merged: bool) -> Presence {
    Presence {
        configured: cli || environment || merged,
        source: optional(cli, environment, merged),
    }
}
