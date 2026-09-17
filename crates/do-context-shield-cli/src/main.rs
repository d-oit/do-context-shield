//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::{Args, Parser, Subcommand};
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_detector_process::{
    DEFAULT_TIMEOUT_MS, ProcessDetector, ProcessDetectorConfig,
};
use do_context_shield_plugin_api::ScopeId;
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::PathBuf;
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
    Restore(VaultArgs),
    Inspect(InspectArgs),
    McpStdio(McpArgs),
}

#[derive(Args)]
struct SanitizeArgs {
    #[command(flatten)]
    vault: VaultArgs,
    #[command(flatten)]
    detector: DetectorSelection,
}

#[derive(Args)]
struct InspectArgs {
    #[command(flatten)]
    detector: DetectorSelection,
}

#[derive(Args)]
struct VaultArgs {
    #[arg(long, default_value = "default")]
    session: String,
    /// Optional local file for persistence across separate CLI processes.
    #[arg(long)]
    vault_file: Option<PathBuf>,
}

#[derive(Args)]
struct McpArgs {
    /// Optional local file for persistence across MCP process restarts.
    #[arg(long)]
    vault_file: Option<PathBuf>,
    #[command(flatten)]
    detector: DetectorSelection,
}

/// Detector plugin selection shared by sanitize and inspect.
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
    /// Milliseconds to wait for one process-detector response; only used with `--detector process`.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
    detector_timeout_ms: u64,
}

impl Default for DetectorSelection {
    fn default() -> Self {
        Self {
            detector: "regex".to_owned(),
            model_dir: None,
            detector_command: None,
            detector_timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

#[derive(Serialize)]
struct InspectOutput {
    entities: Vec<do_context_shield_plugin_api::Entity>,
}

fn build_pipeline(
    vault_file: Option<PathBuf>,
    selection: &DetectorSelection,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match vault_file {
        Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
        None => do_context_shield_plugin_registry::vault("memory")?,
    };
    let detector: Box<dyn do_context_shield_plugin_api::Detector> = match selection
        .detector
        .as_str()
    {
        "gliner2" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
            let config = match selection.model_dir.as_deref() {
                Some(dir) => Gliner2Config::with_model_dir(dir.to_path_buf()),
                None => Gliner2Config::default(),
            };
            Box::new(Gliner2Detector::new(config))
        }
        "process" => {
            let command = selection
                .detector_command
                .as_deref()
                .filter(|command| !command.trim().is_empty())
                .ok_or("`--detector process` requires `--detector-command <program> [args...]`")?;
            Box::new(ProcessDetector::new(ProcessDetectorConfig {
                command: Some(command.to_owned()),
                timeout: Duration::from_millis(selection.detector_timeout_ms),
            }))
        }
        name => do_context_shield_plugin_registry::detector(name)?,
    };
    Ok(PrivacyPipeline::new(
        detector,
        do_context_shield_plugin_registry::policy("default")?,
        do_context_shield_plugin_registry::transformer("pseudonymize")?,
        vault,
    ))
}

fn read_stdin() -> Result<String, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}

fn run_simple(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Sanitize(args) => {
            let mut pipeline = build_pipeline(args.vault.vault_file, &args.detector)?;
            let input = read_stdin()?;
            let result = pipeline.sanitize(&ScopeId(args.vault.session), &input)?;
            print!("{}", result.text);
        }
        Command::Restore(args) => {
            let pipeline = build_pipeline(args.vault_file, &DetectorSelection::default())?;
            let input = read_stdin()?;
            let result = pipeline.restore(&ScopeId(args.session), &input)?;
            print!("{result}");
        }
        Command::Inspect(args) => {
            let pipeline = build_pipeline(None, &args.detector)?;
            let input = read_stdin()?;
            let entities = pipeline.inspect(&input)?;
            serde_json::to_writer_pretty(io::stdout(), &InspectOutput { entities })?;
            println!();
        }
        Command::McpStdio(args) => {
            do_context_shield_mcp_server::run_stdio(do_context_shield_mcp_server::ServerConfig {
                vault_file: args.vault_file,
                detector: args.detector.detector,
                model_dir: args.detector.model_dir,
                detector_command: args.detector.detector_command,
                detector_timeout_ms: args.detector.detector_timeout_ms,
            })?;
        }
    }
    io::stdout().flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_simple(Cli::parse().command)
}
