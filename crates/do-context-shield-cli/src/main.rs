//! Local privacy boundary CLI: sanitize, restore, inspect, and canary checks over stdin/stdout.

use clap::Parser;
use cli::{
    Cli, Command, ConfigArgs, ContextArgs, DetectorSelection, DoctorArgs, ForgetArgs, InspectArgs,
    InspectOutput, McpArgs, PipelineSelection, RestoreArgs, SanitizeArgs, VaultArgs,
    VaultSelection,
};
use do_context_shield_core::canary::{canary_marker, verify_canary};
use do_context_shield_plugin_api::ScopeId;
use std::io::{self, Read, Write};

mod canary_key;
mod cli;
mod config;
mod file_commands;
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
        Command::Doctor(args) => run_doctor(args, config)?,
        Command::Config(args) => run_config(args, config)?,
        Command::CreateKey(args) => file_commands::create_key(&args)?,
        Command::EncryptVault(args) => file_commands::encrypt_vault(&args)?,
        Command::VerifyCanary(args) => run_verify_canary(&args)?,
        Command::VerifyAudit(args) => file_commands::verify_audit(&args)?,
    }
    io::stdout().flush()?;
    Ok(())
}

fn run_sanitize(
    args: SanitizeArgs,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let canary_key_file = args.canary_key_file.clone();
    let VaultArgs {
        session,
        vault_file,
        vault_key_file,
        store,
    } = args.vault;
    let scope = ScopeId(session);
    let resolved = config::resolve(
        &config::CliSelection {
            detector: args.detector,
            pipeline: args.pipeline,
            vault: store,
            vault_file,
            vault_key_file,
            audit_file: args.audit.audit_file,
            audit_max_records: args.audit.audit_max_records,
            audit_max_bytes: args.audit.audit_max_bytes,
            vault_ttl_seconds: None,
            context: args.context,
            process: args.process,
        },
        config,
    );
    let mut pipeline = build_pipeline(&resolved)?;
    let input = read_stdin()?;
    let result = pipeline.sanitize(&scope, &input, &resolved.to_context())?;
    print!("{}", result.text);
    if let Some(path) = &canary_key_file {
        let key = canary_key::read_canary_key(path)?;
        print!("\n{}\n", canary_marker(&key, &scope)?);
    }
    Ok(())
}

/// Check stdin for a valid canary marker; fails closed when it is absent or forged.
fn run_verify_canary(args: &cli::VerifyCanaryArgs) -> Result<(), Box<dyn std::error::Error>> {
    let key = canary_key::read_canary_key(&args.canary_key_file)?;
    let input = read_stdin()?;
    if verify_canary(&key, &ScopeId(args.session.clone()), &input)? {
        println!("ok");
        Ok(())
    } else {
        Err("canary marker missing or invalid for this session".into())
    }
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
            audit_max_records: args.audit.audit_max_records,
            audit_max_bytes: args.audit.audit_max_bytes,
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
            audit_max_records: None,
            audit_max_bytes: None,
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
            audit_max_records: args.audit.audit_max_records,
            audit_max_bytes: args.audit.audit_max_bytes,
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
            audit_max_records: args.audit.audit_max_records,
            audit_max_bytes: args.audit.audit_max_bytes,
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
        audit_max_records: resolved.audit_max_records,
        audit_max_bytes: resolved.audit_max_bytes,
        vault: resolved.vault,
        vault_command: resolved.vault_command,
        vault_ttl_seconds: resolved.vault_ttl_seconds,
        detector: resolved.detector,
        model_dir: resolved.model_dir,
        model_max_tokens: resolved.model_max_tokens,
        model_threads: resolved.model_threads,
        detector_command: resolved.detector_command,
        policy: resolved.policy,
        policy_command: resolved.policy_command,
        judge: resolved.judge,
        policy_matrix: resolved.policy_matrix,
        judge_command: resolved.judge_command,
        transformer: resolved.transformer,
        transformer_command: resolved.transformer_command,
        process_timeout_ms: resolved.process_timeout_ms,
        context,
    })?;
    Ok(())
}

/// One `doctor` report: stable fields for scripts, fixed guidance only.
#[derive(serde::Serialize)]
struct DoctorReport {
    detector: String,
    available: bool,
    reason_code: &'static str,
    guidance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    layout: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    intra_threads: Option<usize>,
}

/// Build the readiness report for one resolved detector selection.
///
/// `hybrid` is reported through its `GLiNER2` half: it is ready only when a
/// model is loadable, so a missing model never looks like a working
/// regex-only scan. `process` is configuration-only (the probe does not run
/// the executable). No input text is read and no path is printed.
fn doctor_report(resolved: &config::Resolved) -> DoctorReport {
    let detector = resolved.detector.clone();
    match detector.as_str() {
        "regex" => DoctorReport {
            detector,
            available: true,
            reason_code: "ready",
            guidance: "built-in regex detector; selected structured PII/credential formats only"
                .to_owned(),
            layout: None,
            max_tokens: None,
            intra_threads: None,
        },
        "process" => {
            let configured = resolved
                .detector_command
                .as_deref()
                .is_some_and(|command| !command.trim().is_empty());
            DoctorReport {
                detector,
                available: configured,
                reason_code: if configured {
                    "ready"
                } else {
                    "not_configured"
                },
                guidance: if configured {
                    "local detector executable configured; doctor checks configuration only and does not run it"
                        .to_owned()
                } else {
                    "set `--detector-command` (or the pinned config file's `[plugins] detector_command`) to a local executable"
                        .to_owned()
                },
                layout: None,
                max_tokens: None,
                intra_threads: None,
            }
        }
        "gliner2" | "hybrid" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, probe};
            let base = match resolved.model_dir.clone() {
                Some(dir) => Gliner2Config::with_model_dir(dir),
                None => Gliner2Config::default(),
            };
            let config = match (resolved.model_max_tokens, resolved.model_threads) {
                (None, None) => base,
                (max_tokens, threads) => {
                    let max_tokens = max_tokens.unwrap_or(base.max_tokens);
                    let threads = threads.unwrap_or(base.intra_threads);
                    base.with_limits(max_tokens, threads)
                }
            };
            let report = probe(&config);
            let guidance = if detector == "hybrid" && !report.available {
                format!(
                    "hybrid needs a loadable GLiNER2 model; regex alone is not a hybrid result. {}",
                    report.guidance
                )
            } else {
                report.guidance.to_owned()
            };
            DoctorReport {
                detector,
                available: report.available,
                reason_code: report.code.as_str(),
                guidance,
                layout: report
                    .layout
                    .map(do_context_shield_detector_gliner2::ModelLayout::as_str),
                max_tokens: Some(report.max_tokens),
                intra_threads: Some(report.intra_threads),
            }
        }
        other => DoctorReport {
            detector: other.to_owned(),
            available: false,
            reason_code: "unknown_detector",
            guidance: "expected `regex`, `gliner2`, `hybrid`, or `process`".to_owned(),
            layout: None,
            max_tokens: None,
            intra_threads: None,
        },
    }
}

/// Report detector readiness without reading stdin or running a scan.
///
/// Exits 0 when the selected detector is ready and 1 when it is not, so a
/// preflight can gate routing private content through the pipeline. The
/// structured report carries a stable `reason_code`; failures are categories,
/// never paths, model contents, or raw metadata.
///
/// # Errors
///
/// Returns an error only when the report cannot be serialized or stdout cannot
/// be flushed.
fn run_doctor(args: DoctorArgs, config: &config::Config) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = config::resolve(
        &config::CliSelection {
            detector: args.detector,
            ..config::CliSelection::default()
        },
        config,
    );
    let report = doctor_report(&resolved);
    if args.format == "json" {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("detector: {}", report.detector);
        println!("available: {}", report.available);
        println!("reason_code: {}", report.reason_code);
        println!("guidance: {}", report.guidance);
        if let Some(layout) = report.layout {
            println!("layout: {layout}");
        }
        if let Some(max_tokens) = report.max_tokens {
            println!("max_tokens: {max_tokens}");
        }
        if let Some(intra_threads) = report.intra_threads {
            println!("intra_threads: {intra_threads}");
        }
    }
    io::stdout().flush()?;
    if !report.available {
        std::process::exit(1);
    }
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
        audit_max_records: args.audit.audit_max_records,
        audit_max_bytes: args.audit.audit_max_bytes,
        vault_ttl_seconds: None,
        context: args.context,
        process: args.process,
    };
    let explained = config::diag::explain(&cli, config)?;
    serde_json::to_writer_pretty(io::stdout(), &explained)?;
    println!();
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let explicit_config = cli.config;
    match cli.command {
        Command::CreateKey(args) => file_commands::create_key(&args),
        command => {
            // `mcp-stdio` runs with the client's project as its working
            // directory, so an ambient file there must not configure it.
            // Key creation is configuration-independent and never discovers
            // or reads a project config file.
            let config = if matches!(&command, Command::McpStdio(_)) {
                config::load_explicit(explicit_config.as_deref())?
            } else {
                config::load(explicit_config.as_deref())?
            };
            config::validate(&config)?;
            run_simple(command, &config)
        }
    }
}
