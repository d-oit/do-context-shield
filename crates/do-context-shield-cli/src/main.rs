//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::Parser;
use cli::{
    Cli, Command, ConfigArgs, ContextArgs, DetectorSelection, EncryptVaultArgs, ForgetArgs,
    InspectArgs, InspectOutput, McpArgs, PipelineSelection, RestoreArgs, SanitizeArgs, VaultArgs,
    VaultSelection,
};
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use do_context_shield_plugin_process::{
    ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

mod cli;
mod config;

/// `GLiNER2` detector for the resolved model directory; an unconfigured or
/// missing export fails closed on the first detect.
fn gliner2_detector(
    model_dir: Option<&Path>,
) -> do_context_shield_detector_gliner2::Gliner2Detector {
    use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
    let config = match model_dir {
        Some(dir) => Gliner2Config::with_model_dir(dir.to_path_buf()),
        None => Gliner2Config::default(),
    };
    Gliner2Detector::new(config)
}

/// Detector named by the resolved configuration.
///
/// # Errors
///
/// Returns an error for a process detector without a command or an unknown
/// detector name.
fn build_detector(
    resolved: &config::Resolved,
) -> Result<Box<dyn do_context_shield_plugin_api::Detector>, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    Ok(match resolved.detector.as_str() {
        "gliner2" => Box::new(gliner2_detector(resolved.model_dir.as_deref())),
        "hybrid" => Box::new(do_context_shield_detector_hybrid::HybridDetector::new(
            do_context_shield_plugin_registry::detector("regex")?,
            Box::new(gliner2_detector(resolved.model_dir.as_deref())),
        )),
        "process" => Box::new(ProcessDetector::from_selection(
            resolved.detector_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::detector(name)?,
    })
}

/// Vault named by the resolved configuration.
///
/// # Errors
///
/// Returns an error for contradictory vault selections, a process vault
/// without a command, a JSON vault without a file, or an unknown vault name.
fn build_vault(
    resolved: &config::Resolved,
) -> Result<Box<dyn do_context_shield_plugin_api::Vault>, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    let vault_file = resolved.vault_file.as_deref();
    let vault_key_file = resolved.vault_key_file.as_deref();
    Ok(match config::vault_kind(resolved)? {
        config::VaultKind::Process => Box::new(ProcessVault::from_selection(
            resolved.vault_command.as_deref(),
            timeout,
        )?),
        config::VaultKind::Json => do_context_shield_plugin_registry::json_vault(
            config::json_vault_file(vault_file)?,
            vault_key_file,
            resolved.vault_ttl_seconds.map(Duration::from_secs),
        )?,
        config::VaultKind::Memory => do_context_shield_plugin_registry::vault("memory")?,
    })
}

/// Policy named by the resolved configuration.
///
/// # Errors
///
/// Returns an error for a process policy without a command or an unknown name.
fn build_policy(
    resolved: &config::Resolved,
) -> Result<Box<dyn do_context_shield_plugin_api::Policy>, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    Ok(match resolved.policy.as_str() {
        "process" => Box::new(ProcessPolicy::from_selection(
            resolved.policy_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::policy(name)?,
    })
}

/// Transformer named by the resolved configuration.
///
/// # Errors
///
/// Returns an error for a process transformer without a command or an unknown
/// name.
fn build_transformer(
    resolved: &config::Resolved,
) -> Result<Box<dyn do_context_shield_plugin_api::Transformer>, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    Ok(match resolved.transformer.as_str() {
        "process" => Box::new(ProcessTransformer::from_selection(
            resolved.transformer_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::transformer(name)?,
    })
}

/// Judge named by the resolved configuration, if any.
///
/// # Errors
///
/// Returns an error for a process judge without a command or an unknown name.
fn build_judge(
    resolved: &config::Resolved,
) -> Result<Option<Box<dyn do_context_shield_plugin_api::SemanticJudge>>, Box<dyn std::error::Error>>
{
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    Ok(match resolved.judge.as_deref() {
        Some("process") => Some(Box::new(ProcessJudge::from_selection(
            resolved.judge_command.as_deref(),
            timeout,
        )?)),
        Some(name) => Some(do_context_shield_plugin_registry::judge(name)?),
        None => None,
    })
}

/// The full pipeline: every stage named by the configuration.
///
/// # Errors
///
/// Returns an error when any selected plugin cannot be built.
fn build_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let pipeline = PrivacyPipeline::new(
        build_detector(resolved)?,
        build_policy(resolved)?,
        build_transformer(resolved)?,
        build_vault(resolved)?,
    );
    Ok(match build_judge(resolved)? {
        Some(judge) => pipeline.with_judge(judge),
        None => pipeline,
    })
}

/// A pipeline whose vault comes from the configuration and whose other stages
/// are the built-in defaults.
///
/// `restore` and `forget` only touch the vault, so a plugin for detector,
/// policy, or transformer that cannot be built (a `process` selection without
/// a command) must not fail them. The defaults are never invoked here.
///
/// # Errors
///
/// Returns an error when the selected vault cannot be built.
fn vault_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    Ok(PrivacyPipeline::new(
        do_context_shield_plugin_registry::detector("regex")?,
        do_context_shield_plugin_registry::policy("default")?,
        do_context_shield_plugin_registry::transformer("pseudonymize")?,
        build_vault(resolved)?,
    ))
}

/// A pipeline whose detector comes from the configuration and whose other
/// stages are the built-in defaults.
///
/// `inspect` never runs policy, transformer, or vault, so a plugin for those
/// stages that cannot be built (a `process` policy without a command, a JSON
/// vault without a file) must not fail the command. `docs/configuration.md`
/// records the same rule in its applicability table.
///
/// # Errors
///
/// Returns an error when the selected detector cannot be built.
fn inspect_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    Ok(PrivacyPipeline::new(
        build_detector(resolved)?,
        do_context_shield_plugin_registry::policy("default")?,
        do_context_shield_plugin_registry::transformer("pseudonymize")?,
        do_context_shield_plugin_registry::vault("memory")?,
    ))
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
