//! Policy protocol tests: action mapping and fail-closed plan validation.

mod common;

use common::command;
use do_context_shield_plugin_api::{
    Action, Entity, Judgment, Policy, ProcessingContext, RecipientClass, SemanticLabel,
};
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
    match policy.plan(entities, &[], &ProcessingContext::default()) {
        Ok(planned) => planned.iter().map(|entry| entry.action.clone()).collect(),
        Err(error) => panic!("expected a plan, got error: {error}"),
    }
}

fn error_message(policy: &ProcessPolicy, entities: &[Entity]) -> String {
    match policy.plan(entities, &[], &ProcessingContext::default()) {
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
    let planned = match policy("plan-ok").plan(&entities, &[], &ProcessingContext::default()) {
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

#[test]
fn forwards_judgments_to_the_child() {
    let entities = [entity("email", 0, 17, "alice@example.com")];
    let judgments = [Judgment::Labeled {
        index: 0,
        label: SemanticLabel::Business,
        confidence: 0.95,
    }];
    let planned =
        match policy("plan-judged").plan(&entities, &judgments, &ProcessingContext::default()) {
            Ok(planned) => planned,
            Err(error) => panic!("expected a plan, got error: {error}"),
        };
    assert_eq!(planned[0].action, Action::Keep, "{planned:?}");
}

#[test]
fn parses_block_and_review_actions() {
    let entities = [entity("email", 0, 17, "alice@example.com")];
    assert_eq!(plan(&policy("plan-block"), &entities), [Action::Block]);
    assert_eq!(plan(&policy("plan-review"), &entities), [Action::Review]);
}

#[test]
fn forwards_the_processing_context_to_the_child() {
    let entities = [entity("email", 0, 17, "alice@example.com")];
    let unknown = ProcessingContext {
        recipient: RecipientClass::Unknown,
        ..ProcessingContext::default()
    };
    let local = ProcessingContext {
        recipient: RecipientClass::Local,
        ..ProcessingContext::default()
    };
    let policy = policy("plan-context");
    let blocked = match policy.plan(&entities, &[], &unknown) {
        Ok(planned) => planned,
        Err(error) => panic!("expected a plan, got error: {error}"),
    };
    assert_eq!(blocked[0].action, Action::Block, "{blocked:?}");
    let kept = match policy.plan(&entities, &[], &local) {
        Ok(planned) => planned,
        Err(error) => panic!("expected a plan, got error: {error}"),
    };
    assert_eq!(kept[0].action, Action::Keep, "{kept:?}");
    let defaulted = match policy.plan(&entities, &[], &ProcessingContext::default()) {
        Ok(planned) => planned,
        Err(error) => panic!("expected a plan, got error: {error}"),
    };
    assert_eq!(defaulted[0].action, Action::Redact, "{defaulted:?}");
}
