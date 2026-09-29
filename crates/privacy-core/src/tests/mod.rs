//! Unit tests for the pipeline, grouped by the contract they pin.
//!
//! The groups share the fixtures in this module ([`pipeline`], [`with_detector`],
//! [`sanitize_ok`],
//! [`sanitize_err`], [`first_placeholder`], [`with_detector`]) and live in
//! separate files so no single test file crowds the 500-line limit.

use super::*;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{Judgment, Mapping, PlannedEntity, SemanticLabel};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;

mod errors;
mod flow;
mod judge;
mod policy;
mod validation;

fn context() -> ProcessingContext {
    ProcessingContext::default()
}

fn pipeline() -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    )
}

struct FixedDetector(Vec<Entity>);

impl Detector for FixedDetector {
    fn detect(&self, _input: &str) -> Result<Vec<Entity>, DetectorError> {
        Ok(self.0.clone())
    }
}

fn entity(kind: &str, start: usize, end: usize, value: &str) -> Entity {
    Entity {
        kind: kind.to_owned(),
        start,
        end,
        value: value.to_owned(),
        confidence: 1.0,
    }
}

fn with_detector(entities: Vec<Entity>) -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(FixedDetector(entities)),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    )
}

fn sanitize_ok(pipeline: &mut PrivacyPipeline, input: &str) -> SanitizeResult {
    match pipeline.sanitize(&ScopeId("test".to_owned()), input, &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn sanitize_err(pipeline: &mut PrivacyPipeline, input: &str) -> PipelineError {
    match pipeline.sanitize(&ScopeId("test".to_owned()), input, &context()) {
        Ok(result) => panic!("expected an error, got {result:?}"),
        Err(error) => error,
    }
}

/// The first minted placeholder in `text`.
fn first_placeholder(text: &str) -> String {
    const PREFIX: &str = "__DO_PRIVATE_";
    let Some(start) = text.find(PREFIX) else {
        panic!("no placeholder in {text}");
    };
    let rest = &text[start + PREFIX.len()..];
    let Some(end) = rest.find("__") else {
        panic!("unterminated placeholder in {text}");
    };
    text[start..start + PREFIX.len() + end + 2].to_owned()
}
