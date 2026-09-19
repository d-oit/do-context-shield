//! Built-in plugin registry.

use do_context_shield_detector_gliner2::Gliner2Detector;
use do_context_shield_detector_hybrid::HybridDetector;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_judge_heuristics::HeuristicJudge;
use do_context_shield_plugin_api::{Detector, Policy, SemanticJudge, Transformer, Vault};
use do_context_shield_plugin_process::{
    ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;
use thiserror::Error;

/// Registry errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Unknown plugin name.
    #[error("unknown {kind} plugin `{name}`")]
    Unknown {
        /// Plugin capability, e.g. `detector`.
        kind: &'static str,
        /// Requested logical plugin name.
        name: String,
    },
}

/// Construct a detector by logical name.
///
/// # Errors
///
/// Returns [`RegistryError::Unknown`] for an unregistered name.
pub fn detector(name: &str) -> Result<Box<dyn Detector>, RegistryError> {
    match name {
        "regex" => Ok(Box::new(RegexDetector)),
        "gliner2" => Ok(Box::new(Gliner2Detector::default())),
        "hybrid" => Ok(Box::new(HybridDetector::new(
            Box::new(RegexDetector),
            Box::new(Gliner2Detector::default()),
        ))),
        "process" => Ok(Box::new(ProcessDetector::default())),
        _ => Err(RegistryError::Unknown {
            kind: "detector",
            name: name.to_owned(),
        }),
    }
}

/// Construct a semantic judge by logical name.
///
/// # Errors
///
/// Returns [`RegistryError::Unknown`] for an unregistered name.
pub fn judge(name: &str) -> Result<Box<dyn SemanticJudge>, RegistryError> {
    match name {
        "heuristics" => Ok(Box::new(HeuristicJudge)),
        "process" => Ok(Box::new(ProcessJudge::default())),
        _ => Err(RegistryError::Unknown {
            kind: "judge",
            name: name.to_owned(),
        }),
    }
}

/// Construct a policy by logical name.
///
/// # Errors
///
/// Returns [`RegistryError::Unknown`] for an unregistered name.
pub fn policy(name: &str) -> Result<Box<dyn Policy>, RegistryError> {
    match name {
        "default" => Ok(Box::new(DefaultPolicy)),
        "process" => Ok(Box::new(ProcessPolicy::default())),
        _ => Err(RegistryError::Unknown {
            kind: "policy",
            name: name.to_owned(),
        }),
    }
}

/// Construct a transformer by logical name.
///
/// # Errors
///
/// Returns [`RegistryError::Unknown`] for an unregistered name.
pub fn transformer(name: &str) -> Result<Box<dyn Transformer>, RegistryError> {
    match name {
        "pseudonymize" => Ok(Box::new(PseudonymizingTransformer)),
        "process" => Ok(Box::new(ProcessTransformer::default())),
        _ => Err(RegistryError::Unknown {
            kind: "transformer",
            name: name.to_owned(),
        }),
    }
}

/// Construct a vault by logical name.
///
/// # Errors
///
/// Returns [`RegistryError::Unknown`] for an unregistered name.
pub fn vault(name: &str) -> Result<Box<dyn Vault>, RegistryError> {
    match name {
        "memory" => Ok(Box::new(MemoryVault::default())),
        "process" => Ok(Box::new(ProcessVault::default())),
        _ => Err(RegistryError::Unknown {
            kind: "vault",
            name: name.to_owned(),
        }),
    }
}
