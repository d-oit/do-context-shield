//! Policy protocol tests: action mapping and fail-closed plan validation.

mod common;

use common::command;
use do_context_shield_plugin_api::{Action, Entity, Policy};
use do_context_shield_plugin_process::{ProcessConfig, ProcessPolicy};

fn policy(mode: &str) -> ProcessPolicy {
    ProcessPolicy::new(ProcessConfig::with_command(command(mode)))
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

fn entities() -> Vec<Entity> {
    vec![
        entity("email", 0, 5, "alice"),
        entity("phone", 6, 17, "example.com"),
    ]
}

fn plan(policy: &ProcessPolicy, entities: &[Entity]) -> Vec<Action> {
    match policy.plan(entities) {
        Ok(planned) => planned.iter().map(|entry| entry.action.clone()).collect(),
        Err(error) => panic!("expected a plan, got error: {error}"),
    }
}

fn error_message(policy: &ProcessPolicy, entities: &[Entity]) -> String {
    match policy.plan(entities) {
        Ok(planned) => panic!("expected an error, got plan: {planned:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn plans_one_action_per_entity() {
    let entities = entities();
    let actions = plan(&policy("plan-two"), &entities);
    assert_eq!(actions, [Action::Pseudonymize, Action::Redact]);
}

#[test]
fn plans_a_single_entity() {
    let entities = [entity("email", 0, 17, "alice@example.com")];
    let planned = match policy("plan-ok").plan(&entities) {
        Ok(planned) => planned,
        Err(error) => panic!("expected a plan, got error: {error}"),
    };
    let [entry] = planned.as_slice() else {
        panic!("expected exactly one entry, got {planned:?}");
    };
    assert_eq!(entry.action, Action::Pseudonymize);
    assert_eq!(entry.entity, entities[0]);
}

#[test]
fn rejects_missing_decision() {
    let entities = entities();
    let message = error_message(&policy("plan-missing"), &entities);
    assert!(
        message.contains("no decision for index 1"),
        "got: {message}"
    );
}

#[test]
fn rejects_duplicate_index() {
    let entities = entities();
    let message = error_message(&policy("plan-dupe"), &entities);
    assert!(message.contains("duplicate index 0"), "got: {message}");
}

#[test]
fn rejects_out_of_range_index() {
    let entities = entities();
    let message = error_message(&policy("plan-range"), &entities);
    assert!(message.contains("out-of-range index 7"), "got: {message}");
}

#[test]
fn rejects_unknown_action() {
    let entities = entities();
    let message = error_message(&policy("plan-unknown"), &entities);
    assert!(
        message.contains("unknown action `nope` for index 0"),
        "got: {message}"
    );
}

#[test]
fn errors_without_command() {
    let message = error_message(&ProcessPolicy::default(), &entities());
    assert!(message.contains("no command configured"), "got: {message}");
}

#[test]
fn errors_on_non_zero_exit() {
    let message = error_message(&policy("exit"), &entities());
    assert!(
        message.contains("process policy exited with status"),
        "got: {message}"
    );
}
