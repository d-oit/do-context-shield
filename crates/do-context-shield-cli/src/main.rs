//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::Parser;
use cli::{
    Cli, Command, ConfigArgs, ContextArgs, DetectorSelection, EncryptVaultArgs, ForgetArgs,
    InspectArgs, InspectOutput, McpArgs, PipelineSelection, RestoreArgs, SanitizeArgs, VaultArgs,
    VaultSelection,
};
use do_context_shield_plugin_api::ScopeId;
use std::io::{self, Read, Write};

mod cli;
mod config;
mod pipeline;

use pipeline::{build_pipeline, inspect_pipeline, vault_pipeline};

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
        Command::Config(args) => run_config(args, config)?,
        Command::EncryptVault(args) => run_encrypt_vault(&args)?,
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
        vault_key_file,
        store,
    } = args.vault;
    let resolved = config::resolve(
        &config::CliSelection {
            detector: args.detector,
            pipeline: args.pipeline,
            vault: store,
            vault_file,
            vault_key_file,
            audit_file: args.audit.audit_file,
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
        vault_key_file,
        store,
    } = args.vault;
    let resolved = config::resolve(
        &config::CliSelection {
            detector: DetectorSelection::default(),
            pipeline: PipelineSelection::default(),
            vault: store,
            vault_file,
            vault_key_file,
            audit_file: args.audit.audit_file,
            vault_ttl_seconds: None,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    // `restore` only resolves placeholders, so only the vault is taken from
    // the configuration: a broken detector/policy/transformer selection must
    // not fail it.
    let pipeline = vault_pipeline(&resolved)?;
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
        &config::CliSelection {
            detector: args.detector,
            pipeline: PipelineSelection::default(),
            vault: VaultSelection::default(),
            vault_file: None,
            vault_key_file: None,
            audit_file: None,
            vault_ttl_seconds: None,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    // `inspect` only runs the detector; the other stages are defaults so a
    // broken selection for them cannot fail the command.
    let pipeline = inspect_pipeline(&resolved)?;
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
        vault_key_file,
        store,
    } = args.vault;
    let resolved = config::resolve(
        &config::CliSelection {
            detector: DetectorSelection::default(),
            pipeline: PipelineSelection::default(),
            vault: store,
            vault_file,
            vault_key_file,
            audit_file: args.audit.audit_file,
            vault_ttl_seconds: None,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    // `forget` only deletes vault mappings; the other stages stay defaults.
    let mut pipeline = vault_pipeline(&resolved)?;
    pipeline.forget(&ScopeId(session))?;
    Ok(())
}

fn run_mcp(args: McpArgs, config: &config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let tools = config::resolve_tools(args.tools, config)?;
    let resolved = config::resolve(
        &config::CliSelection {
            detector: args.detector,
            pipeline: args.pipeline,
            vault: args.store,
            vault_file: args.vault_file,
            vault_key_file: args.vault_key_file,
            audit_file: args.audit.audit_file,
            vault_ttl_seconds: args.vault_ttl_seconds,
            context: ContextArgs::default(),
            process: args.process,
        },
        config,
    );
    let context = resolved.to_context();
    do_context_shield_mcp_server::run_stdio(do_context_shield_mcp_server::ServerConfig {
        tools,
        vault_file: resolved.vault_file,
        vault_key_file: resolved.vault_key_file,
        audit_file: resolved.audit_file,
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
        context,
    })?;
    Ok(())
}

/// Print the effective configuration for the given selection flags.
///
/// The report never builds a plugin and never reads stdin; it lists the
/// whitelisted settings with the layer that supplied each one
/// ([`config::diag`]).
///
/// # Errors
///
/// Returns the vault-selection conflict when the flags name no consistent
/// vault, exactly as the executing commands would.
fn run_config(args: ConfigArgs, config: &config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let cli = config::CliSelection {
        detector: args.detector,
        pipeline: args.pipeline,
        vault: args.store,
        vault_file: args.vault_file,
        vault_key_file: args.vault_key_file,
        audit_file: args.audit.audit_file,
        vault_ttl_seconds: None,
        context: args.context,
        process: args.process,
    };
    let explained = config::diag::explain(&cli, config)?;
    serde_json::to_writer_pretty(io::stdout(), &explained)?;
    println!();
    Ok(())
}

/// Rewrite an existing plaintext JSON vault in the encrypted format.
///
/// Both paths come from the command line, not the configuration: a migration
/// rewrites the vault in place, so an ambient file must not trigger it.
fn run_encrypt_vault(args: &EncryptVaultArgs) -> Result<(), Box<dyn std::error::Error>> {
    let key = do_context_shield_vault_json::VaultKey::from_file(&args.vault_key_file)?;
    do_context_shield_vault_json::JsonVault::encrypt_in_place(&args.vault_file, key)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // `mcp-stdio` runs with the client's project as its working directory, so
    // an ambient file there must not configure it: the MCP entry point reads
    // only an explicit `--config` path. One-shot commands keep auto-discovery.
    let config = if matches!(&cli.command, Command::McpStdio(_)) {
        config::load_explicit(cli.config.as_deref())?
    } else {
        config::load(cli.config.as_deref())?
    };
    config::validate(&config)?;
    run_simple(cli.command, &config)
}
