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
    Sanitize(VaultArgs),
    Restore(VaultArgs),
    Inspect,
    McpStdio(McpArgs),
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
}

#[derive(Serialize)]
struct InspectOutput {
    entities: Vec<do_context_shield_plugin_api::Entity>,
}

fn build_pipeline(
    vault_file: Option<PathBuf>,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match vault_file {
        Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
        None => do_context_shield_plugin_registry::vault("memory")?,
    };
    Ok(PrivacyPipeline::new(
        do_context_shield_plugin_registry::detector("regex")?,
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
            let mut pipeline = build_pipeline(args.vault_file)?;
            let input = read_stdin()?;
            let result = pipeline.sanitize(&ScopeId(args.session), &input)?;
            print!("{}", result.text);
        }
        Command::Restore(args) => {
            let pipeline = build_pipeline(args.vault_file)?;
            let input = read_stdin()?;
            let result = pipeline.restore(&ScopeId(args.session), &input)?;
            print!("{}", result);
        }
        Command::Inspect => {
            let pipeline = build_pipeline(None)?;
            let input = read_stdin()?;
            let entities = pipeline.inspect(&input)?;
            serde_json::to_writer_pretty(io::stdout(), &InspectOutput { entities })?;
            println!();
        }
        Command::McpStdio(args) => {
            do_context_shield_mcp_server::run_stdio(args.vault_file)?;
        }
    }
    io::stdout().flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_simple(Cli::parse().command)
}
