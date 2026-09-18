//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::{Args, Parser, Subcommand};
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use do_context_shield_plugin_process::{
    ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

mod config;

#[derive(Parser)]
#[command(
    name = "do-context-shield",
    version,
    about = "Local privacy boundary for coding agents"
)]
struct Cli {
    /// Path to a configuration file; without it `./do-context-shield.toml` and
    /// `$HOME/.config/do-context-shield/config.toml` are tried in that order.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Sanitize(SanitizeArgs),
    Restore(RestoreArgs),
    Inspect(InspectArgs),
    Forget(ForgetArgs),
    McpStdio(McpArgs),
}

#[derive(Args)]
struct SanitizeArgs {
    #[command(flatten)]
    vault: VaultArgs,
    #[command(flatten)]
    detector: DetectorSelection,
    #[command(flatten)]
    pipeline: PipelineSelection,
    #[command(flatten)]
    process: ProcessArgs,
    #[command(flatten)]
    context: ContextArgs,
}

#[derive(Args)]
struct RestoreArgs {
    #[command(flatten)]
    vault: VaultArgs,
    #[command(flatten)]
    process: ProcessArgs,
}

#[derive(Args)]
struct InspectArgs {
    #[command(flatten)]
    detector: DetectorSelection,
    #[command(flatten)]
    process: ProcessArgs,
}

/// Delete every mapping stored for a session scope.
#[derive(Args)]
struct ForgetArgs {
    #[command(flatten)]
    vault: VaultArgs,
    #[command(flatten)]
    process: ProcessArgs,
}

/// Session scope and vault selection shared by sanitize and restore.
#[derive(Args)]
struct VaultArgs {
    #[arg(long, default_value = "default")]
    session: String,
    /// Optional local file for persistence across separate CLI processes (JSON vault).
    #[arg(long)]
    vault_file: Option<PathBuf>,
    #[command(flatten)]
    store: VaultSelection,
}

#[derive(Args)]
struct McpArgs {
    /// Optional local file for persistence across MCP process restarts (JSON vault).
    #[arg(long)]
    vault_file: Option<PathBuf>,
    /// Lifetime in seconds after which in-process memory-vault mappings stop
    /// resolving (memory vault only).
    #[arg(long)]
    vault_ttl_seconds: Option<u64>,
    #[command(flatten)]
    store: VaultSelection,
    #[command(flatten)]
    detector: DetectorSelection,
    #[command(flatten)]
    pipeline: PipelineSelection,
    #[command(flatten)]
    process: ProcessArgs,
}

/// Detector plugin selection shared by sanitize, inspect, and mcp-stdio.
#[derive(Args, Default)]
struct DetectorSelection {
    /// Detector plugin (default `regex`): `regex` (built-in), `gliner2` (local ONNX NER), or
    /// `process` (local executable over newline-delimited JSON).
    #[arg(long, value_parser = ["regex", "gliner2", "process"])]
    detector: Option<String>,
    /// Local directory holding the `GLiNER2` ONNX export; only used with `--detector gliner2`.
    #[arg(long)]
    model_dir: Option<PathBuf>,
    /// Command line of a local detector executable; required with `--detector process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    detector_command: Option<String>,
}

/// Vault plugin selection shared by sanitize, restore, and mcp-stdio.
#[derive(Args, Default)]
struct VaultSelection {
    /// Vault plugin: `memory`, `json` (with `--vault-file`), or `process` (local executable).
    #[arg(long, value_parser = ["memory", "json", "process"])]
    vault: Option<String>,
    /// Command line of a local vault executable; required with `--vault process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    vault_command: Option<String>,
}

/// Policy and transformer selection shared by sanitize and mcp-stdio.
#[derive(Args, Default)]
struct PipelineSelection {
    /// Optional semantic judge: `heuristics` (built-in rules) or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["heuristics", "process"])]
    judge: Option<String>,
    /// Command line of a local judge executable; required with `--judge process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    judge_command: Option<String>,
    /// Policy plugin (default `default`): `default` or `process` (local executable over
    /// newline-delimited JSON).
    #[arg(long, value_parser = ["default", "process"])]
    policy: Option<String>,
    /// Command line of a local policy executable; required with `--policy process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    policy_command: Option<String>,
    /// Transformer plugin (default `pseudonymize`): `pseudonymize` or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["pseudonymize", "process"])]
    transformer: Option<String>,
    /// Command line of a local transformer executable; required with `--transformer process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    transformer_command: Option<String>,
}

/// Enforcement context for `sanitize`.
#[derive(Args, Default)]
struct ContextArgs {
    /// Recipient trust classification used by the policy (default `external`).
    #[arg(long, value_parser = ["local", "trusted", "external", "unknown"])]
    recipient: Option<String>,
    /// Data category of the input used by the policy (default `personal`).
    #[arg(long, value_parser = ["non_personal", "personal", "special_category"])]
    data_category: Option<String>,
    /// Purpose of the processing operation (free-form, policy-matched).
    #[arg(long)]
    purpose: Option<String>,
    /// Jurisdiction code (ISO 3166-1 alpha-2), if known.
    #[arg(long)]
    jurisdiction: Option<String>,
}

/// Timeout shared by every process plugin.
#[derive(Args, Default)]
struct ProcessArgs {
    /// Milliseconds to wait for one process-plugin response (detector, policy, transformer, vault);
    /// defaults to the config file value or the built-in timeout.
    #[arg(long)]
    process_timeout_ms: Option<u64>,
}

#[derive(Serialize)]
struct InspectOutput {
    entities: Vec<do_context_shield_core::EntitySummary>,
}

fn build_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    let vault_file = resolved.vault_file.as_deref();
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match resolved.vault.as_deref() {
        Some("process") => {
            if vault_file.is_some() {
                return Err("`--vault-file` cannot be combined with `--vault process`".into());
            }
            Box::new(ProcessVault::from_selection(
                resolved.vault_command.as_deref(),
                timeout,
            )?)
        }
        Some("json") => Box::new(do_context_shield_vault_json::JsonVault::open(
            json_vault_file(vault_file)?,
        )?),
        Some("memory") => {
            if vault_file.is_some() {
                return Err("`--vault-file` cannot be combined with `--vault memory`".into());
            }
            do_context_shield_plugin_registry::vault("memory")?
        }
        Some(other) => return Err(format!("unknown vault plugin `{other}`").into()),
        None => match vault_file {
            Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
            None => do_context_shield_plugin_registry::vault("memory")?,
        },
    };
    let detector: Box<dyn do_context_shield_plugin_api::Detector> = match resolved.detector.as_str()
    {
        "gliner2" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
            let config = match resolved.model_dir.as_deref() {
                Some(dir) => Gliner2Config::with_model_dir(dir.to_path_buf()),
                None => Gliner2Config::default(),
            };
            Box::new(Gliner2Detector::new(config))
        }
        "process" => Box::new(ProcessDetector::from_selection(
            resolved.detector_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::detector(name)?,
    };
    let policy: Box<dyn do_context_shield_plugin_api::Policy> = match resolved.policy.as_str() {
        "process" => Box::new(ProcessPolicy::from_selection(
            resolved.policy_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::policy(name)?,
    };
    let transformer: Box<dyn do_context_shield_plugin_api::Transformer> =
        match resolved.transformer.as_str() {
            "process" => Box::new(ProcessTransformer::from_selection(
                resolved.transformer_command.as_deref(),
                timeout,
            )?),
            name => do_context_shield_plugin_registry::transformer(name)?,
        };
    let judge: Option<Box<dyn do_context_shield_plugin_api::SemanticJudge>> =
        match resolved.judge.as_deref() {
            Some("process") => Some(Box::new(ProcessJudge::from_selection(
                resolved.judge_command.as_deref(),
                timeout,
            )?)),
            Some(name) => Some(do_context_shield_plugin_registry::judge(name)?),
            None => None,
        };
    let pipeline = PrivacyPipeline::new(detector, policy, transformer, vault);
    Ok(match judge {
        Some(judge) => pipeline.with_judge(judge),
        None => pipeline,
    })
}

/// Resolve the JSON vault path or explain what is missing.
fn json_vault_file(vault_file: Option<&Path>) -> Result<&Path, Box<dyn std::error::Error>> {
    vault_file.ok_or_else(|| "`--vault json` requires `--vault-file <path>`".into())
}

fn read_stdin() -> Result<String, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}

/// Run one subcommand against the merged configuration.
fn run_simple(command: Command, config: &config::Config) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Sanitize(args) => run_sanitize(args, config)?,
        Command::Restore(args) => run_restore(args, config)?,
        Command::Inspect(args) => run_inspect(args, config)?,
        Command::Forget(args) => run_forget(args, config)?,
        Command::McpStdio(args) => run_mcp(args, config)?,
    }
    io::stdout().flush()?;
    Ok(())
}

fn run_sanitize(
    args: SanitizeArgs,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let VaultArgs {
        session,
        vault_file,
        store,
    } = args.vault;
    let resolved = config::resolve(
        config::CliSelection {
            detector: args.detector,
            pipeline: args.pipeline,
            vault: store,
            vault_file,
            vault_ttl_seconds: None,
            context: args.context,
            process: args.process,
        },
        config,
    );
    let mut pipeline = build_pipeline(&resolved)?;
    let input = read_stdin()?;
    let result = pipeline.sanitize(&ScopeId(session), &input, &resolved.to_context())?;
    print!("{}", result.text);
    Ok(())
}

fn run_restore(
    args: RestoreArgs,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let VaultArgs {
        session,
        vault_file,
        store,
    } = args.vault;
    let resolved = config::resolve(
        config::CliSelection {
            detector: DetectorSelection::default(),
            pipeline: PipelineSelection::default(),
            vault: store,
            vault_file,
            vault_ttl_seconds: None,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    let pipeline = build_pipeline(&resolved)?;
    let input = read_stdin()?;
    let result = pipeline.restore(&ScopeId(session), &input)?;
    print!("{result}");
    Ok(())
}

fn run_inspect(
    args: InspectArgs,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = config::resolve(
        config::CliSelection {
            detector: args.detector,
            pipeline: PipelineSelection::default(),
            vault: VaultSelection::default(),
            vault_file: None,
            vault_ttl_seconds: None,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    let pipeline = build_pipeline(&resolved)?;
    let input = read_stdin()?;
    let entities = pipeline.inspect(&input)?;
    serde_json::to_writer_pretty(io::stdout(), &InspectOutput { entities })?;
    println!();
    Ok(())
}

fn run_forget(args: ForgetArgs, config: &config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let VaultArgs {
        session,
        vault_file,
        store,
    } = args.vault;
    let resolved = config::resolve(
        config::CliSelection {
            detector: DetectorSelection::default(),
            pipeline: PipelineSelection::default(),
            vault: store,
            vault_file,
            vault_ttl_seconds: None,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    let mut pipeline = build_pipeline(&resolved)?;
    pipeline.forget(&ScopeId(session))?;
    Ok(())
}

fn run_mcp(args: McpArgs, config: &config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = config::resolve(
        config::CliSelection {
            detector: args.detector,
            pipeline: args.pipeline,
            vault: args.store,
            vault_file: args.vault_file,
            vault_ttl_seconds: args.vault_ttl_seconds,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    do_context_shield_mcp_server::run_stdio(do_context_shield_mcp_server::ServerConfig {
        vault_file: resolved.vault_file,
        vault: resolved.vault,
        vault_command: resolved.vault_command,
        vault_ttl_seconds: resolved.vault_ttl_seconds,
        detector: resolved.detector,
        model_dir: resolved.model_dir,
        detector_command: resolved.detector_command,
        policy: resolved.policy,
        policy_command: resolved.policy_command,
        judge: resolved.judge,
        judge_command: resolved.judge_command,
        transformer: resolved.transformer,
        transformer_command: resolved.transformer_command,
        process_timeout_ms: resolved.process_timeout_ms,
    })?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let config = config::load(cli.config.as_deref())?;
    config::validate(&config)?;
    run_simple(cli.command, &config)
}
