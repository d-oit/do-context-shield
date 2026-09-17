//! Transformer protocol tests: text, mappings, and vault resolvability.

mod common;

use common::command;
use do_context_shield_plugin_api::{
    Action, Entity, Mapping, PlannedEntity, ScopeId, TransformResult, Transformer, Vault,
};
use do_context_shield_plugin_process::{ProcessConfig, ProcessTransformer, ProcessVault};

const INPUT: &str = "alice@example.com";
const TOKEN: &str = "__DO_PRIVATE_EMAIL_1__";

fn transformer(mode: &str) -> ProcessTransformer {
    ProcessTransformer::new(ProcessConfig::with_command(command(mode)))
}

fn vault(mode: &str) -> ProcessVault {
    ProcessVault::new(ProcessConfig::with_command(command(mode)))
}

fn scope() -> ScopeId {
    ScopeId("s1".to_owned())
}

fn planned(kind: &str, start: usize, end: usize, value: &str, action: Action) -> PlannedEntity {
    PlannedEntity {
        entity: Entity {
            kind: kind.to_owned(),
            start,
            end,
            value: value.to_owned(),
            confidence: 1.0,
        },
        action,
    }
}

fn sensitive() -> PlannedEntity {
    planned("email", 0, INPUT.len(), INPUT, Action::Pseudonymize)
}

fn transform(input: &str, mode: &str, plan: &[PlannedEntity]) -> Result<TransformResult, String> {
    let mut vault = vault("vault-ok");
    transformer(mode)
        .transform(input, plan, &scope(), &mut vault)
        .map_err(|error| error.to_string())
}

#[test]
fn transforms_with_vault_resolvable_mappings() {
    let mut vault = vault("vault-ok");
    let result =
        match transformer("transform-ok").transform(INPUT, &[sensitive()], &scope(), &mut vault) {
            Ok(result) => result,
            Err(error) => panic!("expected a transform, got error: {error}"),
        };
    assert_eq!(result.text, TOKEN);
    assert_eq!(
        result.mappings,
        [Mapping {
            kind: "email".to_owned(),
            original: INPUT.to_owned(),
            token: TOKEN.to_owned(),
        }]
    );
    let resolved = match vault.resolve(&scope(), TOKEN) {
        Ok(resolved) => resolved,
        Err(error) => panic!("expected a mapping, got error: {error}"),
    };
    assert_eq!(
        resolved.map(|mapping| mapping.original),
        Some(INPUT.to_owned())
    );
}

#[test]
fn redacts_without_registering_mappings() {
    let plan = [planned("email", 0, INPUT.len(), INPUT, Action::Redact)];
    let result = match transform(INPUT, "transform-redact", &plan) {
        Ok(result) => result,
        Err(error) => panic!("expected a transform, got error: {error}"),
    };
    assert_eq!(result.text, "__DO_PRIVATE_REDACTED__");
    assert!(result.mappings.is_empty());
}

#[test]
fn rejects_leftover_value() {
    let message = match transform(INPUT, "transform-leak", &[sensitive()]) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(
        message.contains("still contains the value of kind `email`"),
        "got: {message}"
    );
}

#[test]
fn rejects_mapping_without_text_token() {
    let message = match transform(INPUT, "transform-notoken", &[sensitive()]) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(message.contains("without its token"), "got: {message}");
}

#[test]
fn rejects_unplanned_mapping() {
    let message = match transform(INPUT, "transform-unplanned", &[sensitive()]) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(
        message.contains("was not planned for pseudonymization"),
        "got: {message}"
    );
}

#[test]
fn rejects_unresolvable_token() {
    let message = match transform(INPUT, "transform-foreign", &[sensitive()]) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(message.contains("cannot resolve"), "got: {message}");
}

#[test]
fn rejects_dropped_keep_value() {
    let plan = [planned("email", 0, 5, "alice", Action::Keep)];
    let message = match transform("alice", "transform-dropkeep", &plan) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(message.contains("planned to be kept"), "got: {message}");
}

#[test]
fn rejects_duplicate_token() {
    let message = match transform(INPUT, "transform-duplicate-token", &[sensitive()]) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(message.contains("duplicate token"), "got: {message}");
}

#[test]
fn rejects_duplicate_mappings_for_one_value() {
    let message = match transform(INPUT, "transform-duplicate-mapping", &[sensitive()]) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error,
    };
    assert!(message.contains("duplicate mappings"), "got: {message}");
}

#[test]
fn errors_without_command() {
    let mut vault = vault("vault-ok");
    let message = match ProcessTransformer::default().transform(
        INPUT,
        &[sensitive()],
        &scope(),
        &mut vault,
    ) {
        Ok(result) => panic!("expected an error, got text: {}", result.text),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("no command configured"), "got: {message}");
}
