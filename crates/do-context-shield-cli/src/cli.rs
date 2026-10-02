//! CLI argument definitions.

use clap::{Args, Parser, Subcommand};
use do_context_shield_core::EntitySummary;
use do_context_shield_mcp_server::ToolSet;
use do_context_shield_plugin_api::is_valid_jurisdiction;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "do-context-shield",
    version,
    about = "Local privacy boundary for coding agents"
)]
pub(crate) struct Cli {
    /// Path to a configuration file. The one-shot commands fall back to
    /// `./do-context-shield.toml`, then
    /// `$HOME/.config/do-context-shield/config.toml`; `mcp-stdio` reads a file
    /// only when this flag names one, because a project directory must not
    /// configure the server that runs in it.
    #[arg(long, global = true)]
    pub(crate) config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    #[command(about = "Sanitize sensitive text from stdin")]
    Sanitize(SanitizeArgs),
    #[command(about = "Restore placeholders from stdin within an explicit session")]
    Restore(RestoreArgs),
    #[command(about = "Inspect sensitive entities from stdin without exposing their values")]
    Inspect(InspectArgs),
    #[command(about = "Delete every mapping stored for a session scope")]
    Forget(ForgetArgs),
    #[command(about = "Serve the privacy tools over MCP JSON-RPC stdio")]
    McpStdio(McpArgs),
    #[command(
        about = "Show the effective plugin selection and enforcement context with their source layer"
    )]
    Config(ConfigArgs),
    #[command(about = "Rewrite an existing plaintext JSON vault in the encrypted format")]
    EncryptVault(EncryptVaultArgs),
}

/// Explicit local append-only JSONL audit destination.
#[derive(Args, Default, Clone)]
pub(crate) struct AuditArgs {
    /// Record structure-only operation summaries in a private local file.
    #[arg(long)]
    pub(crate) audit_file: Option<PathBuf>,
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
    #[command(flatten)]
    pub(crate) audit: AuditArgs,
}

#[derive(Args)]
pub(crate) struct RestoreArgs {
    #[command(flatten)]
    pub(crate) vault: VaultArgs,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
    #[command(flatten)]
    pub(crate) audit: AuditArgs,
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
    #[command(flatten)]
    pub(crate) audit: AuditArgs,
}

/// Session scope and vault selection shared by sanitize, restore, and forget.
#[derive(Args)]
pub(crate) struct VaultArgs {
    /// Session scope for the vault mappings.
    ///
    /// Required on every command: an implicit default scope would let
    /// concurrent tasks resolve each other's placeholders, which explicit
    /// session scoping exists to prevent.
    #[arg(long)]
    pub(crate) session: String,
    /// Optional local file for persistence across separate CLI processes (JSON vault).
    #[arg(long)]
    pub(crate) vault_file: Option<PathBuf>,
    /// Optional 64-hex-character key file that encrypts the JSON vault at rest
    /// (requires `--vault-file`; on Unix the key file must be owner-only).
    #[arg(long)]
    pub(crate) vault_key_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) store: VaultSelection,
}

#[derive(Args)]
pub(crate) struct McpArgs {
    /// Optional local file for persistence across MCP process restarts (JSON vault).
    #[arg(long)]
    pub(crate) vault_file: Option<PathBuf>,
    /// Optional 64-hex-character key file that encrypts the JSON vault at rest
    /// (requires `--vault-file`; on Unix the key file must be owner-only).
    #[arg(long)]
    pub(crate) vault_key_file: Option<PathBuf>,
    /// Lifetime in seconds after which vault mappings stop resolving (memory
    /// or JSON vault; a persisted JSON mapping stays expired across restarts).
    #[arg(long)]
    pub(crate) vault_ttl_seconds: Option<u64>,
    /// Comma-separated MCP tools to expose: `sanitize`, `restore`, `inspect`,
    /// `forget`, or `all`. Defaults to `sanitize,inspect`, or the configured
    /// `[plugins] tools` value: MCP tool results return to the calling model, so
    /// `restore` (which resolves raw values) stays off the model-facing surface
    /// unless a client opts in.
    #[arg(long, value_parser = parse_tools)]
    pub(crate) tools: Option<ToolSet>,
    #[command(flatten)]
    pub(crate) store: VaultSelection,
    #[command(flatten)]
    pub(crate) detector: DetectorSelection,
    #[command(flatten)]
    pub(crate) pipeline: PipelineSelection,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
    #[command(flatten)]
    pub(crate) audit: AuditArgs,
}

/// Selection flags shared by `config` with the executing commands.
///
/// `config` accepts the same flags so the four-layer precedence
/// (CLI > environment > file > default) can be inspected with the exact
/// invocation it would diagnose; it never reads stdin and never builds a
/// plugin.
#[derive(Args, Default, Clone)]
pub(crate) struct ConfigArgs {
    #[command(flatten)]
    pub(crate) detector: DetectorSelection,
    #[command(flatten)]
    pub(crate) pipeline: PipelineSelection,
    #[command(flatten)]
    pub(crate) store: VaultSelection,
    /// Optional local file for persistence across separate CLI processes (JSON vault).
    #[arg(long)]
    pub(crate) vault_file: Option<PathBuf>,
    /// Optional 64-hex-character key file that encrypts the JSON vault at rest
    /// (requires `--vault-file`).
    #[arg(long)]
    pub(crate) vault_key_file: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) context: ContextArgs,
    #[command(flatten)]
    pub(crate) process: ProcessArgs,
    #[command(flatten)]
    pub(crate) audit: AuditArgs,
}

/// Rewrite an existing plaintext JSON vault in the encrypted format.
///
/// Both paths are explicit on purpose: a migration rewrites the vault in
/// place, so it must not be triggered by an ambient configuration file.
#[derive(Args)]
pub(crate) struct EncryptVaultArgs {
    /// Existing plaintext vault file to migrate.
    #[arg(long)]
    pub(crate) vault_file: PathBuf,
    /// 64-hex-character key file the vault is encrypted with
    /// (owner-only on Unix).
    #[arg(long)]
    pub(crate) vault_key_file: PathBuf,
}

/// Parse the `--tools` value into a [`ToolSet`].
fn parse_tools(value: &str) -> Result<ToolSet, String> {
    ToolSet::parse(value)
}

/// Parse the `--jurisdiction` value with the shared shape predicate.
///
/// A rejected value fails argument parsing (exit 2) before stdin is read, so a
/// malformed code can never satisfy the declared-jurisdiction policy
/// condition. The rejection message is fixed: it does not echo the rejected
/// text.
fn parse_jurisdiction(value: &str) -> Result<String, String> {
    if is_valid_jurisdiction(value) {
        Ok(value.to_owned())
    } else {
        Err("jurisdiction must be an ISO 3166-1 alpha-2 code".to_owned())
    }
}

/// Detector plugin selection shared by sanitize, inspect, and mcp-stdio.
#[derive(Args, Default, Clone)]
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
#[derive(Args, Default, Clone)]
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
#[derive(Args, Default, Clone)]
pub(crate) struct PipelineSelection {
    /// Optional semantic judge: `heuristics` (built-in rules) or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["heuristics", "process"])]
    pub(crate) judge: Option<String>,
    /// Command line of a local judge executable; required with `--judge process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) judge_command: Option<String>,
    /// Policy plugin (default `default`): `default`, `matrix` (opt-in jurisdiction
    /// adequacy and purpose mapping from `[policy_matrix]`), or `process` (local
    /// executable over newline-delimited JSON).
    #[arg(long, value_parser = ["default", "matrix", "process"])]
    pub(crate) policy: Option<String>,
    /// Command line of a local policy executable; required with `--policy process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) policy_command: Option<String>,
    /// Transformer plugin (default `pseudonymize`): `pseudonymize` (reversible
    /// vault-backed tokens), `generalize` (kind-only non-reversible tokens),
    /// `mask` (partial reveal, non-reversible), or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["pseudonymize", "generalize", "mask", "process"])]
    pub(crate) transformer: Option<String>,
    /// Command line of a local transformer executable; required with `--transformer process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    pub(crate) transformer_command: Option<String>,
}

/// Enforcement context for `sanitize`.
#[derive(Args, Default, Clone)]
pub(crate) struct ContextArgs {
    /// Recipient trust classification used by the policy (default `external`).
    #[arg(long, value_parser = ["local", "trusted", "external", "unknown"])]
    pub(crate) recipient: Option<String>,
    /// Data category of the input used by the policy (default `personal`).
    #[arg(long, value_parser = ["non_personal", "personal", "special_category"])]
    pub(crate) data_category: Option<String>,
    /// Purpose of the processing operation (free-form). Forwarded to policy
    /// plugins; the built-in default policy does not read it, and it never
    /// loosens a decision.
    #[arg(long)]
    pub(crate) purpose: Option<String>,
    /// Jurisdiction code (ISO 3166-1 alpha-2), if known. Unset counts as
    /// unknown, which blocks special-category data to any non-local recipient;
    /// a malformed value is an argument error instead of an implicit
    /// declaration.
    #[arg(long, value_parser = parse_jurisdiction)]
    pub(crate) jurisdiction: Option<String>,
}

/// Timeout shared by every process plugin.
#[derive(Args, Default, Clone)]
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
