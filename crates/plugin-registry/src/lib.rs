//! Built-in plugin registry.

use do_context_shield_detector_gliner2::Gliner2Detector;
use do_context_shield_detector_hybrid::HybridDetector;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_judge_heuristics::HeuristicJudge;
use do_context_shield_plugin_api::{
    Detector, Policy, SemanticJudge, Transformer, Vault, VaultError,
};
use do_context_shield_plugin_process::{
    ProcessDetector, ProcessJudge, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_generalize::GeneralizingTransformer;
use do_context_shield_transformer_mask::MaskingTransformer;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_json::JsonVault;
use do_context_shield_vault_memory::MemoryVault;
use std::path::Path;
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
    /// A registered plugin needs an argument a name cannot carry.
    #[error("{kind} plugin `{name}` needs a storage path; build it with `json_vault(path)`")]
    NeedsArgument {
        /// Plugin capability, e.g. `vault`.
        kind: &'static str,
        /// Logical plugin name.
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
        "generalize" => Ok(Box::new(GeneralizingTransformer)),
        "mask" => Ok(Box::new(MaskingTransformer)),
        "process" => Ok(Box::new(ProcessTransformer::default())),
        _ => Err(RegistryError::Unknown {
            kind: "transformer",
            name: name.to_owned(),
        }),
    }
}

/// Construct a vault by logical name.
///
/// `json` is registered but cannot be built from a name alone: it needs its
/// storage path, so it is reported as [`RegistryError::NeedsArgument`] and
/// built with [`json_vault`].
///
/// # Errors
///
/// Returns [`RegistryError::Unknown`] for an unregistered name and
/// [`RegistryError::NeedsArgument`] for `json`.
pub fn vault(name: &str) -> Result<Box<dyn Vault>, RegistryError> {
    match name {
        "memory" => Ok(Box::new(MemoryVault::default())),
        "process" => Ok(Box::new(ProcessVault::default())),
        "json" => Err(RegistryError::NeedsArgument {
            kind: "vault",
            name: name.to_owned(),
        }),
        _ => Err(RegistryError::Unknown {
            kind: "vault",
            name: name.to_owned(),
        }),
    }
}

/// Construct the file-backed JSON vault at `path`.
///
/// The adapter owns the path (`vault_file` / `--vault-file`), the optional
/// key file (`vault_key_file` / `--vault-key-file`), and the TTL validation;
/// this is the registry entry point for the documented `json` vault so every
/// consumer builds the same implementation. With a key file the vault state is
/// encrypted at rest.
///
/// # Errors
///
/// Returns the vault's own error when the key file cannot be read or the file
/// cannot be opened in the selected format.
pub fn json_vault(path: &Path, key_file: Option<&Path>) -> Result<Box<dyn Vault>, VaultError> {
    Ok(Box::new(JsonVault::open_with_key_file(path, key_file)?))
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
        for name in ["pseudonymize", "generalize", "mask", "process"] {
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
    fn json_vault_is_registered_and_needs_its_path() {
        // The documented storage row lists the JSON vault, so the name must be
        // known; it cannot be built without a path, and that is reported as an
        // argument error rather than "unknown plugin".
        match vault("json").err() {
            Some(RegistryError::NeedsArgument { kind, name }) => {
                assert_eq!(kind, "vault");
                assert_eq!(name, "json");
            }
            other => panic!("expected a needs-argument error, got {other:?}"),
        }

        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("cannot create a temp directory: {error}"),
        };
        let path = dir.path().join("vault.json");
        let mut vault = match json_vault(&path, None) {
            Ok(vault) => vault,
            Err(error) => panic!("json vault must construct: {error}"),
        };
        let scope = do_context_shield_plugin_api::ScopeId("json-scope".to_owned());
        let mapping = match vault.get_or_insert(&scope, "email", "alice@example.com") {
            Ok(mapping) => mapping,
            Err(error) => panic!("insert failed: {error}"),
        };
        let resolved = match vault.resolve(&scope, &mapping.token) {
            Ok(resolved) => resolved,
            Err(error) => panic!("resolve failed: {error}"),
        };
        assert_eq!(
            resolved.map(|mapping| mapping.original),
            Some("alice@example.com".to_owned())
        );
        assert!(path.exists(), "the JSON vault must create its file");
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
