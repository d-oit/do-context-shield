//! Local privacy boundary CLI: sanitize, restore, and inspect over stdin/stdout.

use clap::Parser;
use cli::{
    Cli, Command, ContextArgs, DetectorSelection, ForgetArgs, InspectArgs, InspectOutput, McpArgs,
    PipelineSelection, RestoreArgs, SanitizeArgs, VaultArgs, VaultSelection,
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

fn build_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(resolved.process_timeout_ms);
    let vault_file = resolved.vault_file.as_deref();
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match resolved.vault.as_deref() {
        Some("process") => {
            if vault_file.is_some() {
                return Err(
                    "vault `process` cannot be combined with a vault file (`vault_file` or `--vault-file`)"
                        .into(),
                );
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
                return Err(
                    "vault `memory` cannot be combined with a vault file (`vault_file` or `--vault-file`)"
                        .into(),
                );
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
    vault_file.ok_or_else(|| {
        "vault `json` requires a vault file (`vault_file` or `--vault-file <path>`)".into()
    })
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
    let tools = args.tools.unwrap_or_default();
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
        tools,
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
