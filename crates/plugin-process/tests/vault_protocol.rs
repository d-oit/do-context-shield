//! Vault protocol tests: tokens, resolution, and fail-closed validation.

mod common;

use common::command;
use do_context_shield_plugin_api::{ScopeId, Vault};
use do_context_shield_plugin_process::{ProcessConfig, ProcessVault};

const TOKEN: &str = "__DO_PRIVATE_EMAIL_1__";

fn vault(mode: &str) -> ProcessVault {
    ProcessVault::new(ProcessConfig::with_command(command(mode)))
}

fn scope(name: &str) -> ScopeId {
    ScopeId(name.to_owned())
}

#[test]
fn get_or_insert_returns_a_placeholder_token() {
    let mut vault = vault("vault-ok");
    let mapping = match vault.get_or_insert(&scope("s1"), "email", "alice@example.com") {
        Ok(mapping) => mapping,
        Err(error) => panic!("expected a mapping, got error: {error}"),
    };
    assert_eq!(mapping.token, TOKEN);
    assert_eq!(mapping.kind, "email");
    assert_eq!(mapping.original, "alice@example.com");
}

#[test]
fn resolve_returns_the_stored_mapping() {
    let vault = vault("vault-ok");
    let resolved = match vault.resolve(&scope("s1"), TOKEN) {
        Ok(resolved) => resolved,
        Err(error) => panic!("expected a mapping, got error: {error}"),
    };
    assert_eq!(
        resolved.map(|mapping| (mapping.kind, mapping.original)),
        Some(("email".to_owned(), "alice@example.com".to_owned()))
    );
}

#[test]
fn resolve_returns_none_for_an_unknown_token() {
    let vault = vault("vault-ok");
    let resolved = match vault.resolve(&scope("s2"), TOKEN) {
        Ok(resolved) => resolved,
        Err(error) => panic!("expected a miss, got error: {error}"),
    };
    assert_eq!(resolved, None);
}

#[test]
fn resolve_returns_none_on_an_explicit_miss() {
    let vault = vault("vault-miss");
    let resolved = match vault.resolve(&scope("s1"), TOKEN) {
        Ok(resolved) => resolved,
        Err(error) => panic!("expected a miss, got error: {error}"),
    };
    assert_eq!(resolved, None);
}

#[test]
fn rejects_a_token_restore_cannot_resolve() {
    let mut vault = vault("vault-bad-token");
    let message = match vault.get_or_insert(&scope("s1"), "email", "alice@example.com") {
        Ok(mapping) => panic!("expected an error, got mapping: {mapping:?}"),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("that `restore` cannot resolve"),
        "got: {message}"
    );
}

#[test]
fn rejects_a_token_echo_mismatch() {
    let vault = vault("vault-wrong-token");
    let message = match vault.resolve(&scope("s1"), TOKEN) {
        Ok(resolved) => panic!("expected an error, got mapping: {resolved:?}"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("different token"), "got: {message}");
}

#[test]
fn errors_without_command() {
    let mut vault = ProcessVault::default();
    let message = match vault.get_or_insert(&scope("s1"), "email", "alice@example.com") {
        Ok(mapping) => panic!("expected an error, got mapping: {mapping:?}"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("no command configured"), "got: {message}");
}
