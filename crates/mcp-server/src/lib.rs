//! MCP stdio adapter. The privacy engine itself remains transport-agnostic.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_process::{
    DEFAULT_TIMEOUT_MS, ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer,
    ProcessVault,
};
use do_context_shield_vault_memory::MemoryVault;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

mod handle;

use crate::handle::handle_request;

/// Server configuration: persistence and plugin selection.
pub struct ServerConfig {
    /// Optional local file for persistence across MCP process restarts (JSON vault).
    pub vault_file: Option<PathBuf>,
    /// Vault plugin: `memory` (default without `vault_file`), `json`, or `process`.
    pub vault: Option<String>,
    /// Command line of a local vault executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub vault_command: Option<String>,
    /// Detector plugin name: `regex` (built-in), `gliner2` (local ONNX NER), or `process`
    /// (local executable over newline-delimited JSON).
    pub detector: String,
    /// Local directory holding the `GLiNER2` ONNX export; only used with `gliner2`.
    pub model_dir: Option<PathBuf>,
    /// Command line of a local detector executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub detector_command: Option<String>,
    /// Policy plugin name: `default` or `process`.
    pub policy: String,
    /// Command line of a local policy executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub policy_command: Option<String>,
    /// Optional semantic judge: `heuristics` (built-in rules) or `process` (local executable
    /// over newline-delimited JSON).
    pub judge: Option<String>,
    /// Command line of a local judge executable; required with `judge` set to `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub judge_command: Option<String>,
    /// Transformer plugin name: `pseudonymize` or `process`.
    pub transformer: String,
    /// Command line of a local transformer executable; required with `process`.
    /// Split on whitespace; quoting and shell expansion are not supported.
    pub transformer_command: Option<String>,
    /// Milliseconds to wait for one process-plugin response (detector, policy, transformer, vault).
    pub process_timeout_ms: u64,
    /// Lifetime in seconds after which in-process memory-vault mappings stop
    /// resolving. Only valid with the memory vault; `None` keeps mappings for
    /// the server's lifetime.
    pub vault_ttl_seconds: Option<u64>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            vault_file: None,
            vault: None,
            vault_command: None,
            detector: "regex".to_owned(),
            model_dir: None,
            detector_command: None,
            policy: "default".to_owned(),
            policy_command: None,
            judge: None,
            judge_command: None,
            transformer: "pseudonymize".to_owned(),
            transformer_command: None,
            process_timeout_ms: DEFAULT_TIMEOUT_MS,
            vault_ttl_seconds: None,
        }
    }
}

/// Build the mapping vault from the server configuration.
///
/// # Errors
///
/// Returns an error for an unknown vault name, a missing vault file, an
/// incompatible `vault_file`/`vault` combination, or a `vault_ttl_seconds`
/// that does not apply to the selected vault.
fn build_vault(
    config: &mut ServerConfig,
    timeout: Duration,
) -> Result<Box<dyn do_context_shield_plugin_api::Vault>, Box<dyn std::error::Error>> {
    let ttl = config.vault_ttl_seconds;
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match config.vault.as_deref() {
        Some("process") => {
            if config.vault_file.is_some() {
                return Err(
                    "vault `process` cannot be combined with a vault file (`vault_file` or `--vault-file`)"
                        .into(),
                );
            }
            reject_ttl(ttl, "process")?;
            Box::new(ProcessVault::from_selection(
                config.vault_command.as_deref(),
                timeout,
            )?)
        }
        Some("json") => {
            reject_ttl(ttl, "json")?;
            let path = config.vault_file.take().ok_or(
                "vault `json` requires a vault file (`vault_file` or `--vault-file <path>`)",
            )?;
            Box::new(do_context_shield_vault_json::JsonVault::open(path)?)
        }
        Some("memory") => {
            if config.vault_file.is_some() {
                return Err(
                    "vault `memory` cannot be combined with a vault file (`vault_file` or `--vault-file`)"
                        .into(),
                );
            }
            memory_vault(ttl)
        }
        Some(other) => return Err(format!("unknown vault plugin `{other}`").into()),
        None => match config.vault_file.take() {
            Some(path) => {
                reject_ttl(ttl, "json")?;
                Box::new(do_context_shield_vault_json::JsonVault::open(path)?)
            }
            None => memory_vault(ttl),
        },
    };
    Ok(vault)
}

/// Reject a TTL that the selected vault has no lifetime policy for.
fn reject_ttl(ttl: Option<u64>, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if ttl.is_some() {
        return Err(format!(
            "`vault_ttl_seconds` (`--vault-ttl-seconds`) requires the memory vault (selected: `{name}`)"
        )
        .into());
    }
    Ok(())
}

/// In-process memory vault; with a TTL, mappings stop resolving after it.
fn memory_vault(ttl_seconds: Option<u64>) -> Box<dyn do_context_shield_plugin_api::Vault> {
    match ttl_seconds {
        Some(seconds) => Box::new(MemoryVault::with_ttl(Duration::from_secs(seconds))),
        None => Box::new(MemoryVault::default()),
    }
}

/// Run the MCP server over newline-delimited JSON-RPC on stdio.
///
/// # Errors
///
/// Returns an error when stdio I/O fails, a request cannot be answered, or a plugin cannot be constructed.
pub fn run_stdio(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(config.process_timeout_ms);
    let vault = build_vault(&mut config, timeout)?;
    let detector: Box<dyn do_context_shield_plugin_api::Detector> = match config.detector.as_str() {
        "gliner2" | "hybrid" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
            let detector_config = match config.model_dir.take() {
                Some(dir) => Gliner2Config::with_model_dir(dir),
                None => Gliner2Config::default(),
            };
            let gliner2 = Box::new(Gliner2Detector::new(detector_config));
            if config.detector == "hybrid" {
                Box::new(do_context_shield_detector_hybrid::HybridDetector::new(
                    do_context_shield_plugin_registry::detector("regex")?,
                    gliner2,
                ))
            } else {
                gliner2
            }
        }
        "process" => Box::new(ProcessDetector::from_selection(
            config.detector_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::detector(name)?,
    };
    let policy: Box<dyn do_context_shield_plugin_api::Policy> = match config.policy.as_str() {
        "process" => Box::new(ProcessPolicy::from_selection(
            config.policy_command.as_deref(),
            timeout,
        )?),
        name => do_context_shield_plugin_registry::policy(name)?,
    };
    let transformer: Box<dyn do_context_shield_plugin_api::Transformer> =
        match config.transformer.as_str() {
            "process" => Box::new(ProcessTransformer::from_selection(
                config.transformer_command.as_deref(),
                timeout,
            )?),
            name => do_context_shield_plugin_registry::transformer(name)?,
        };
    let judge: Option<Box<dyn do_context_shield_plugin_api::SemanticJudge>> =
        match config.judge.as_deref() {
            Some("process") => Some(Box::new(ProcessJudge::from_selection(
                config.judge_command.as_deref(),
                timeout,
            )?)),
            Some(name) => Some(do_context_shield_plugin_registry::judge(name)?),
            None => None,
        };
    let pipeline = PrivacyPipeline::new(detector, policy, transformer, vault);
    let mut pipeline = match judge {
        Some(judge) => pipeline.with_judge(judge),
        None => pipeline,
    };
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut line = String::new();

    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_request(&mut pipeline, &line)?;
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}
