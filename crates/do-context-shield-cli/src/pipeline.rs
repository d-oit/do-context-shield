use crate::config;
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::AuditSink;
use do_context_shield_plugin_process::{
    ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use std::path::Path;
use std::time::Duration;
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

/// Open and validate the selected audit sink before building any pipeline stage.
///
/// # Errors
///
/// Returns an error when the destination aliases vault state or cannot be
/// created and validated as a private local audit file.
fn build_audit(
    resolved: &config::Resolved,
) -> Result<Option<Box<dyn AuditSink>>, Box<dyn std::error::Error>> {
    let Some(path) = resolved.audit_file.as_deref() else {
        return Ok(None);
    };
    Ok(Some(do_context_shield_plugin_registry::file_audit_sink(
        path,
        resolved.vault_file.as_deref(),
        resolved.vault_key_file.as_deref(),
    )?))
}

fn attach_audit(pipeline: PrivacyPipeline, audit: Option<Box<dyn AuditSink>>) -> PrivacyPipeline {
    match audit {
        Some(sink) => pipeline.with_audit_sink(sink),
        None => pipeline,
    }
}

/// The full pipeline: every stage named by the configuration.
///
/// # Errors
///
/// Returns an error when any selected plugin cannot be built.
pub(crate) fn build_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let audit = build_audit(resolved)?;
    let pipeline = PrivacyPipeline::new(
        build_detector(resolved)?,
        build_policy(resolved)?,
        build_transformer(resolved)?,
        build_vault(resolved)?,
    );
    let pipeline = match build_judge(resolved)? {
        Some(judge) => pipeline.with_judge(judge),
        None => pipeline,
    };
    Ok(attach_audit(pipeline, audit))
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
pub(crate) fn vault_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    let audit = build_audit(resolved)?;
    let pipeline = PrivacyPipeline::new(
        do_context_shield_plugin_registry::detector("regex")?,
        do_context_shield_plugin_registry::policy("default")?,
        do_context_shield_plugin_registry::transformer("pseudonymize")?,
        build_vault(resolved)?,
    );
    Ok(attach_audit(pipeline, audit))
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
pub(crate) fn inspect_pipeline(
    resolved: &config::Resolved,
) -> Result<PrivacyPipeline, Box<dyn std::error::Error>> {
    Ok(PrivacyPipeline::new(
        build_detector(resolved)?,
        do_context_shield_plugin_registry::policy("default")?,
        do_context_shield_plugin_registry::transformer("pseudonymize")?,
        do_context_shield_plugin_registry::vault("memory")?,
    ))
}
