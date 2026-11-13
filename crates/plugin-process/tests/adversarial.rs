//! Adversarial plugin responses at the pipeline composition level.
//!
//! These fixtures are syntactically valid protocol responses from a hostile
//! but well-behaved-on-the-wire plugin. Each case asserts both the observable
//! output and the side-effect state (mappings, redaction), so a regression
//! cannot silently weaken the boundary.

mod common;

use common::command;
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::ScopeId;
use do_context_shield_plugin_api::{Detector, ProcessingContext};
use do_context_shield_plugin_process::{
    ProcessConfig, ProcessDetector, ProcessPolicy, ProcessTransformer, ProcessVault,
};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;
use std::time::Duration;

const SCOPE: &str = "adversarial";
const SECRET: &str = "sk-abc123456";
const EMAIL: &str = "alice@example.com";

fn detector(mode: &str) -> ProcessDetector {
    ProcessDetector::new(ProcessConfig::with_command(command(mode)))
}

fn policy(mode: &str) -> ProcessPolicy {
    ProcessPolicy::new(ProcessConfig::with_command(command(mode)))
}

fn context() -> ProcessingContext {
    ProcessingContext::default()
}

#[test]
fn a_policy_cannot_keep_a_secret_entity() {
    // A syntactically valid plan that says `keep` for a secret-kind entity must
    // fail the call, never return reversible pseudonyms for a credential.
    let mut pipeline = PrivacyPipeline::new(
        Box::new(detector("detect-secret")),
        Box::new(policy("plan-keep")),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let error = match pipeline.sanitize(&ScopeId(SCOPE.to_owned()), SECRET, &context()) {
        Ok(result) => panic!("a secret survived the plan: {}", result.text),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("must be redacted"), "{error}");
    assert!(!error.contains(SECRET), "error leaked the value: {error}");
}

#[test]
fn overlapping_secret_and_non_secret_aliases_keep_the_wider_secret_span() {
    // The detector reports a person alias inside a wider api_key span; the
    // shared longest-span-wins rule must keep the secret, which the policy then
    // redacts.
    let mut pipeline = PrivacyPipeline::new(
        Box::new(detector("detect-overlap-secret")),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let result = match pipeline.sanitize(&ScopeId(SCOPE.to_owned()), SECRET, &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected pipeline error: {error}"),
    };
    assert!(!result.text.contains(SECRET), "{}", result.text);
    assert_eq!(result.entities.len(), 1);
    assert_eq!(result.entities[0].kind, "api_key");
    assert_eq!(result.text, "__DO_PRIVATE_REDACTED__");
}

#[test]
fn a_transformer_may_edit_text_outside_the_planned_spans_and_stays_reversible() {
    // Documented trust contract: the transformer is trusted for text outside
    // the planned entities (here it wraps the token), while the planned value
    // and the emitted placeholder are still validated and the mapping stays
    // resolvable through the configured vault.
    let mut pipeline = PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(ProcessTransformer::new(ProcessConfig::with_command(
            command("transform-wrapped"),
        ))),
        Box::new(ProcessVault::new(ProcessConfig::with_command(command(
            "vault-ok",
        )))),
    );
    // The process vault fixture resolves the token for scope `s1`.
    let result = match pipeline.sanitize(&ScopeId("s1".to_owned()), EMAIL, &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected pipeline error: {error}"),
    };
    assert!(!result.text.contains(EMAIL), "{}", result.text);
    assert_eq!(result.text, "<<__DO_PRIVATE_EMAIL_1__>>");
    let restored = match pipeline.restore(&ScopeId("s1".to_owned()), &result.text) {
        Ok(restored) => restored,
        Err(error) => panic!("unexpected restore error: {error}"),
    };
    assert_eq!(restored, format!("<<{EMAIL}>>"));
}

#[test]
fn a_second_response_line_is_never_read_or_returned() {
    // Two valid JSON lines: the driver reads exactly one response line, so the
    // smuggled second entity never reaches the pipeline.
    let mut pipeline = PrivacyPipeline::new(
        Box::new(detector("multiline")),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let result = match pipeline.sanitize(&ScopeId(SCOPE.to_owned()), "alice", &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected pipeline error: {error}"),
    };
    assert!(result.entities.is_empty(), "{:?}", result.entities);
    assert_eq!(result.text, "alice");
}

#[test]
fn a_failed_hostile_call_does_not_poison_the_next_one() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let marker = directory.path().join("counter.marker");
    let mut plugin_command = command("counter");
    plugin_command.args.push(marker.as_os_str().to_owned());
    let detector = ProcessDetector::new(
        ProcessConfig::with_command(plugin_command).with_timeout(Duration::from_secs(5)),
    );
    let first = detector.detect(EMAIL);
    assert!(first.is_err(), "the first (hostile) call must fail");
    let second = match detector.detect(EMAIL) {
        Ok(entities) => entities,
        Err(error) => panic!("the follow-up call was poisoned: {error}"),
    };
    assert!(second.is_empty(), "{second:?}");
}
