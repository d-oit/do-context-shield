//! MCP stdio adapter. The privacy engine itself remains transport-agnostic.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_process::{
    DEFAULT_TIMEOUT_MS, ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer,
    ProcessVault,
};
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
        }
    }
}

/// Run the MCP server over newline-delimited JSON-RPC on stdio.
///
/// # Errors
///
/// Returns an error when stdio I/O fails, a request cannot be answered, or a plugin cannot be constructed.
pub fn run_stdio(mut config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let timeout = Duration::from_millis(config.process_timeout_ms);
    let vault: Box<dyn do_context_shield_plugin_api::Vault> = match config.vault.as_deref() {
        Some("process") => {
            if config.vault_file.is_some() {
                return Err("`--vault-file` cannot be combined with `--vault process`".into());
            }
            Box::new(ProcessVault::from_selection(
                config.vault_command.as_deref(),
                timeout,
            )?)
        }
        Some("json") => {
            let path = config
                .vault_file
                .take()
                .ok_or("`--vault json` requires `--vault-file <path>`")?;
            Box::new(do_context_shield_vault_json::JsonVault::open(path)?)
        }
        Some("memory") => {
            if config.vault_file.is_some() {
                return Err("`--vault-file` cannot be combined with `--vault memory`".into());
            }
            do_context_shield_plugin_registry::vault("memory")?
        }
        Some(other) => return Err(format!("unknown vault plugin `{other}`").into()),
        None => match config.vault_file.take() {
            Some(path) => Box::new(do_context_shield_vault_json::JsonVault::open(path)?),
            None => do_context_shield_plugin_registry::vault("memory")?,
        },
    };
    let detector: Box<dyn do_context_shield_plugin_api::Detector> = match config.detector.as_str() {
        "gliner2" => {
            use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector};
            let detector_config = match config.model_dir.take() {
                Some(dir) => Gliner2Config::with_model_dir(dir),
                None => Gliner2Config::default(),
            };
            Box::new(Gliner2Detector::new(detector_config))
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
