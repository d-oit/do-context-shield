//! End-to-end pipeline test: detect, plan, transform, and restore all run
//! through configured child processes.

mod common;

use common::command;
use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ScopeId;
use do_context_shield_plugin_process::{
    ProcessConfig, ProcessDetector, ProcessPolicy, ProcessTransformer, ProcessVault,
};

fn pipeline() -> PrivacyPipeline {
    PrivacyPipeline::new(
        Box::new(ProcessDetector::new(ProcessConfig::with_command(command(
            "detect-ok",
        )))),
        Box::new(ProcessPolicy::new(ProcessConfig::with_command(command(
            "plan-ok",
        )))),
        Box::new(ProcessTransformer::new(ProcessConfig::with_command(
            command("transform-ok"),
        ))),
        Box::new(ProcessVault::new(ProcessConfig::with_command(command(
            "vault-ok",
        )))),
    )
}

fn scope(name: &str) -> ScopeId {
    ScopeId(name.to_owned())
}

#[test]
fn sanitizes_and_restores_across_process_plugins() {
    let mut pipeline = pipeline();
    let result = match pipeline.sanitize(&scope("s1"), "alice@example.com") {
        Ok(result) => result,
        Err(error) => panic!("sanitize failed: {error}"),
    };
    assert_eq!(result.text, "__DO_PRIVATE_EMAIL_1__");
    let restored = match pipeline.restore(&scope("s1"), &result.text) {
        Ok(restored) => restored,
        Err(error) => panic!("restore failed: {error}"),
    };
    assert_eq!(restored, "alice@example.com");
}

#[test]
fn restore_is_limited_to_the_vault_scope() {
    let mut pipeline = pipeline();
    let result = match pipeline.sanitize(&scope("s1"), "alice@example.com") {
        Ok(result) => result,
        Err(error) => panic!("sanitize failed: {error}"),
    };
    let untouched = match pipeline.restore(&scope("other"), &result.text) {
        Ok(restored) => restored,
        Err(error) => panic!("restore failed: {error}"),
    };
    assert_eq!(untouched, result.text);
}
