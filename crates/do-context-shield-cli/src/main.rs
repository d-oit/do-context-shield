//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::{Args, Parser, Subcommand};
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use serde::Serialize;
use std::io::{self, Read, Write};
use std::path::PathBuf;

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
    /// Detector plugin: `regex` (built-in) or `gliner2` (local ONNX NER).
    #[arg(long, default_value = "regex", value_parser = ["regex", "gliner2"])]
    detector: String,
    /// Local directory holding the `GLiNER2` ONNX export; only used with `--detector gliner2`.
    #[arg(long)]
    model_dir: Option<PathBuf>,
}

#[derive(Serialize)]
struct InspectOutput {
    entities: Vec<do_context_shield_plugin_api::Entity>,
}

fn build_pipeline(
    vault_file: Option<PathBuf>,
    detector_name: &str,
    model_dir: Option<PathBuf>,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match vault_file {
        Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
        None => do_context_shield_plugin_registry::vault("memory")?,
    };
    let detector: Box<dyn do_context_shield_plugin_api::Detector> = match detector_name {
        "gliner2" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
            let config = match model_dir {
                Some(dir) => Gliner2Config::with_model_dir(dir),
                None => Gliner2Config::default(),
            };
            Box::new(Gliner2Detector::new(config))
        }
        _ => do_context_shield_plugin_registry::detector(detector_name)?,
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
            let mut pipeline = build_pipeline(
                args.vault.vault_file,
                &args.detector.detector,
                args.detector.model_dir,
            )?;
            let input = read_stdin()?;
            let result = pipeline.sanitize(&ScopeId(args.vault.session), &input)?;
            print!("{}", result.text);
        }
        Command::Restore(args) => {
            let pipeline = build_pipeline(args.vault_file, "regex", None)?;
            let input = read_stdin()?;
            let result = pipeline.restore(&ScopeId(args.session), &input)?;
            print!("{result}");
        }
        Command::Inspect(args) => {
            let pipeline = build_pipeline(None, &args.detector.detector, args.detector.model_dir)?;
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
            })?;
        }
    }
    io::stdout().flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_simple(Cli::parse().command)
}
