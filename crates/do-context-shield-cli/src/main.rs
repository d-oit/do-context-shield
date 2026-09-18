//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::{Args, Parser, Subcommand};
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use do_context_shield_plugin_process::{
    DEFAULT_TIMEOUT_MS, ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer,
    ProcessVault,
};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "do-context-shield",
    version,
    about = "Local privacy boundary for coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Sanitize(SanitizeArgs),
    Restore(RestoreArgs),
    Inspect(InspectArgs),
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

impl Default for VaultArgs {
    fn default() -> Self {
        Self {
            session: "default".to_owned(),
            vault_file: None,
            store: VaultSelection::default(),
        }
    }
}

#[derive(Args)]
struct McpArgs {
    /// Optional local file for persistence across MCP process restarts (JSON vault).
    #[arg(long)]
    vault_file: Option<PathBuf>,
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
#[derive(Args)]
struct DetectorSelection {
    /// Detector plugin: `regex` (built-in), `gliner2` (local ONNX NER), or `process` (local
    /// executable over newline-delimited JSON).
    #[arg(long, default_value = "regex", value_parser = ["regex", "gliner2", "process"])]
    detector: String,
    /// Local directory holding the `GLiNER2` ONNX export; only used with `--detector gliner2`.
    #[arg(long)]
    model_dir: Option<PathBuf>,
    /// Command line of a local detector executable; required with `--detector process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    detector_command: Option<String>,
}

impl Default for DetectorSelection {
    fn default() -> Self {
        Self {
            detector: "regex".to_owned(),
            model_dir: None,
            detector_command: None,
        }
    }
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
#[derive(Args)]
struct PipelineSelection {
    /// Optional semantic judge: `heuristics` (built-in rules) or `process` (local executable
    /// over newline-delimited JSON).
    #[arg(long, value_parser = ["heuristics", "process"])]
    judge: Option<String>,
    /// Command line of a local judge executable; required with `--judge process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    judge_command: Option<String>,
    /// Policy plugin: `default` or `process` (local executable over newline-delimited JSON).
    #[arg(long, default_value = "default", value_parser = ["default", "process"])]
    policy: String,
    /// Command line of a local policy executable; required with `--policy process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    policy_command: Option<String>,
    /// Transformer plugin: `pseudonymize` or `process` (local executable over newline-delimited JSON).
    #[arg(long, default_value = "pseudonymize", value_parser = ["pseudonymize", "process"])]
    transformer: String,
    /// Command line of a local transformer executable; required with `--transformer process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    #[arg(long)]
    transformer_command: Option<String>,
}

impl Default for PipelineSelection {
    fn default() -> Self {
        Self {
            judge: None,
            judge_command: None,
            policy: "default".to_owned(),
            policy_command: None,
            transformer: "pseudonymize".to_owned(),
            transformer_command: None,
        }
    }
}

/// Timeout shared by every process plugin.
#[derive(Args)]
struct ProcessArgs {
    /// Milliseconds to wait for one process-plugin response (detector, policy, transformer, vault).
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    process_timeout_ms: u64,
}

impl Default for ProcessArgs {
    fn default() -> Self {
        Self {
            process_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

#[derive(Serialize)]
struct InspectOutput {
    entities: Vec<do_context_shield_core::EntitySummary>,
}

fn build_pipeline(
    vault_args: &VaultArgs,
    detector_selection: &DetectorSelection,
    pipeline_selection: &PipelineSelection,
    process: &ProcessArgs,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(process.process_timeout_ms);
    let vault_file = vault_args.vault_file.as_deref();
    let vault: Box<dyn do_context_shield_plugin_api::Vault> =
        match vault_args.store.vault.as_deref() {
            Some("process") => {
                if vault_file.is_some() {
                    return Err("`--vault-file` cannot be combined with `--vault process`".into());
                }
                Box::new(ProcessVault::from_selection(
                    vault_args.store.vault_command.as_deref(),
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
    let detector: Box<dyn do_context_shield_plugin_api::Detector> =
        match detector_selection.detector.as_str() {
            "gliner2" => {
                use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
                let config = match detector_selection.model_dir.as_deref() {
                    Some(dir) => Gliner2Config::with_model_dir(dir.to_path_buf()),
                    None => Gliner2Config::default(),
                };
                Box::new(Gliner2Detector::new(config))
            }
            "process" => Box::new(ProcessDetector::from_selection(
                detector_selection.detector_command.as_deref(),
                timeout,
            )?),
            name => do_context_shield_plugin_registry::detector(name)?,
        };
    let policy: Box<dyn do_context_shield_plugin_api::Policy> =
        match pipeline_selection.policy.as_str() {
            "process" => Box::new(ProcessPolicy::from_selection(
                pipeline_selection.policy_command.as_deref(),
                timeout,
            )?),
            name => do_context_shield_plugin_registry::policy(name)?,
        };
    let transformer: Box<dyn do_context_shield_plugin_api::Transformer> =
        match pipeline_selection.transformer.as_str() {
            "process" => Box::new(ProcessTransformer::from_selection(
                pipeline_selection.transformer_command.as_deref(),
                timeout,
            )?),
            name => do_context_shield_plugin_registry::transformer(name)?,
        };
    let judge: Option<Box<dyn do_context_shield_plugin_api::SemanticJudge>> =
        match pipeline_selection.judge.as_deref() {
            Some("process") => Some(Box::new(ProcessJudge::from_selection(
                pipeline_selection.judge_command.as_deref(),
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

fn run_simple(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Sanitize(args) => {
            let mut pipeline =
                build_pipeline(&args.vault, &args.detector, &args.pipeline, &args.process)?;
            let input = read_stdin()?;
            let result = pipeline.sanitize(&ScopeId(args.vault.session), &input)?;
            print!("{}", result.text);
        }
        Command::Restore(args) => {
            let pipeline = build_pipeline(
                &args.vault,
                &DetectorSelection::default(),
                &PipelineSelection::default(),
                &args.process,
            )?;
            let input = read_stdin()?;
            let result = pipeline.restore(&ScopeId(args.vault.session), &input)?;
            print!("{result}");
        }
        Command::Inspect(args) => {
            let pipeline = build_pipeline(
                &VaultArgs::default(),
                &args.detector,
                &PipelineSelection::default(),
                &args.process,
            )?;
            let input = read_stdin()?;
            let entities = pipeline.inspect(&input)?;
            serde_json::to_writer_pretty(io::stdout(), &InspectOutput { entities })?;
            println!();
        }
        Command::McpStdio(args) => {
            do_context_shield_mcp_server::run_stdio(do_context_shield_mcp_server::ServerConfig {
                vault_file: args.vault_file,
                vault: args.store.vault,
                vault_command: args.store.vault_command,
                detector: args.detector.detector,
                model_dir: args.detector.model_dir,
                detector_command: args.detector.detector_command,
                policy: args.pipeline.policy,
                policy_command: args.pipeline.policy_command,
                judge: args.pipeline.judge,
                judge_command: args.pipeline.judge_command,
                transformer: args.pipeline.transformer,
                transformer_command: args.pipeline.transformer_command,
                process_timeout_ms: args.process.process_timeout_ms,
            })?;
        }
    }
    io::stdout().flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_simple(Cli::parse().command)
}
