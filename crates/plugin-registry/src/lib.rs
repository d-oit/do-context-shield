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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_names_construct() {
        for name in ["regex", "gliner2", "hybrid", "process"] {
            assert!(detector(name).is_ok(), "detector `{name}`");
        }
        for name in ["heuristics", "process"] {
            assert!(judge(name).is_ok(), "judge `{name}`");
        }
        for name in ["default", "process"] {
            assert!(policy(name).is_ok(), "policy `{name}`");
        }
        for name in ["pseudonymize", "process"] {
            assert!(transformer(name).is_ok(), "transformer `{name}`");
        }
        for name in ["memory", "process"] {
            assert!(vault(name).is_ok(), "vault `{name}`");
        }
    }

    #[test]
    fn unknown_names_report_the_capability() {
        let errors = [
            ("detector", detector("nope").err()),
            ("judge", judge("nope").err()),
            ("policy", policy("nope").err()),
            ("transformer", transformer("nope").err()),
            ("vault", vault("nope").err()),
        ];
        for (kind, error) in errors {
            match error {
                Some(RegistryError::Unknown {
                    kind: reported,
                    name,
                }) => {
                    assert_eq!(reported, kind);
                    assert_eq!(name, "nope");
                }
                other => panic!("expected an unknown-{kind} error, got {other:?}"),
            }
        }
    }

    #[test]
    fn regex_name_detects_and_hybrid_name_pairs_it_with_the_model() {
        let Ok(regex) = detector("regex") else {
            panic!("the regex detector must construct");
        };
        let entities = match regex.detect("SSN 123-45-6789") {
            Ok(entities) => entities,
            Err(error) => panic!("regex detect failed: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "ssn");

        // The hybrid name must wire regex together with the model half: with
        // no model directory the pair fails closed even though regex alone
        // finds the SSN.
        let Ok(hybrid) = detector("hybrid") else {
            panic!("the hybrid detector must construct");
        };
        let error = match hybrid.detect("SSN 123-45-6789") {
            Ok(entities) => panic!("expected a fail-closed error, got {entities:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("model_dir"), "{error}");
    }
}
