//! CLI argument definitions.

use clap::{Args, Parser, Subcommand};
use do_context_shield_core::EntitySummary;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "do-context-shield",
    version,
    about = "Local privacy boundary for coding agents"
)]
pub(crate) struct Cli {
    /// Path to a configuration file; without it `./do-context-shield.toml` and
    /// `$HOME/.config/do-context-shield/config.toml` are tried in that order.
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Sanitize(SanitizeArgs),
    Restore(RestoreArgs),
    Inspect(InspectArgs),
    Forget(ForgetArgs),
    McpStdio(McpArgs),
}

#[derive(Args)]
pub(crate) struct SanitizeArgs {
    #[command(flatten)]
    pub(crate) vault: VaultArgs,
    #[command(flatten)]
    pub(crate) detector: DetectorSelection,
    #[command(flatten)]
    pub(crate) pipeline: PipelineSelection,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
    #[command(flatten)]
    pub(crate) context: ContextArgs,
}

#[derive(Args)]
pub(crate) struct RestoreArgs {
    #[command(flatten)]
    pub(crate) vault: VaultArgs,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
}

#[derive(Args)]
pub(crate) struct InspectArgs {
    #[command(flatten)]
    pub(crate) detector: DetectorSelection,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
}

/// Delete every mapping stored for a session scope.
#[derive(Args)]
pub(crate) struct ForgetArgs {
    #[command(flatten)]
    pub(crate) vault: VaultArgs,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
}

/// Session scope and vault selection shared by sanitize and restore.
#[derive(Args)]
pub(crate) struct VaultArgs {
    #[arg(long, default_value = "default")]
    pub(crate) session: String,
    /// Optional local file for persistence across separate CLI processes (JSON vault).
    #[arg(long)]
    pub(crate) vault_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) store: VaultSelection,
}

#[derive(Args)]
pub(crate) struct McpArgs {
    /// Optional local file for persistence across MCP process restarts (JSON vault).
    #[arg(long)]
    pub(crate) vault_file: Option<PathBuf>,
    /// Lifetime in seconds after which in-process memory-vault mappings stop
    /// resolving (memory vault only).
    #[arg(long)]
    pub(crate) vault_ttl_seconds: Option<u64>,
    #[command(flatten)]
    pub(crate) store: VaultSelection,
    #[command(flatten)]
    pub(crate) detector: DetectorSelection,
    #[command(flatten)]
    pub(crate) pipeline: PipelineSelection,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
}

/// Detector plugin selection shared by sanitize, inspect, and mcp-stdio.
#[derive(Args, Default)]
pub(crate) struct DetectorSelection {
    /// Detector plugin (default `regex`): `regex` (built-in), `gliner2` (local ONNX NER),
    /// `hybrid` (regex plus the local ONNX NER model), or `process` (local executable over
    /// newline-delimited JSON).
    #[arg(long, value_parser = ["regex", "gliner2", "hybrid", "process"])]
    pub(crate) detector: Option<String>,
    /// Local directory holding the `GLiNER2` ONNX export; used with `--detector gliner2` and
    /// `--detector hybrid`.
    #[arg(long)]
    pub(crate) model_dir: Option<PathBuf>,
    /// Command line of a local detector executable; required with `--detector process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) detector_command: Option<String>,
}

/// Vault plugin selection shared by sanitize, restore, and mcp-stdio.
#[derive(Args, Default)]
pub(crate) struct VaultSelection {
    /// Vault plugin: `memory`, `json` (with `--vault-file`), or `process` (local executable).
    #[arg(long, value_parser = ["memory", "json", "process"])]
    pub(crate) vault: Option<String>,
    /// Command line of a local vault executable; required with `--vault process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) vault_command: Option<String>,
}

/// Policy and transformer selection shared by sanitize and mcp-stdio.
#[derive(Args, Default)]
pub(crate) struct PipelineSelection {
    /// Optional semantic judge: `heuristics` (built-in rules) or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["heuristics", "process"])]
    pub(crate) judge: Option<String>,
    /// Command line of a local judge executable; required with `--judge process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) judge_command: Option<String>,
    /// Policy plugin (default `default`): `default` or `process` (local executable over
    /// newline-delimited JSON).
    #[arg(long, value_parser = ["default", "process"])]
    pub(crate) policy: Option<String>,
    /// Command line of a local policy executable; required with `--policy process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) policy_command: Option<String>,
    /// Transformer plugin (default `pseudonymize`): `pseudonymize` or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["pseudonymize", "process"])]
    pub(crate) transformer: Option<String>,
    /// Command line of a local transformer executable; required with `--transformer process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) transformer_command: Option<String>,
}

/// Enforcement context for `sanitize`.
#[derive(Args, Default)]
pub(crate) struct ContextArgs {
    /// Recipient trust classification used by the policy (default `external`).
    #[arg(long, value_parser = ["local", "trusted", "external", "unknown"])]
    pub(crate) recipient: Option<String>,
    /// Data category of the input used by the policy (default `personal`).
    #[arg(long, value_parser = ["non_personal", "personal", "special_category"])]
    pub(crate) data_category: Option<String>,
    /// Purpose of the processing operation (free-form, policy-matched).
    #[arg(long)]
    pub(crate) purpose: Option<String>,
    /// Jurisdiction code (ISO 3166-1 alpha-2), if known.
    #[arg(long)]
    pub(crate) jurisdiction: Option<String>,
}

/// Timeout shared by every process plugin.
#[derive(Args, Default)]
pub(crate) struct ProcessArgs {
    /// Milliseconds to wait for one process-plugin response (detector, policy, transformer, vault);
    /// defaults to the config file value or the built-in timeout.
    #[arg(long)]
    pub(crate) process_timeout_ms: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct InspectOutput {
    pub(crate) entities: Vec<EntitySummary>,
}
