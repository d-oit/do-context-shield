//! Judge protocol tests: label mapping and fail-closed judgment validation.

mod common;

use common::command;
use do_context_shield_plugin_api::{Entity, Judgment, SemanticJudge, SemanticLabel};
use do_context_shield_plugin_process::{ProcessConfig, ProcessJudge};

fn judge(mode: &str) -> ProcessJudge {
    ProcessJudge::new(ProcessConfig::with_command(command(mode)))
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

fn judge_ok(judge: &ProcessJudge, entities: &[Entity]) -> Vec<Judgment> {
    match judge.judge("alice@example.com", entities) {
        Ok(judgments) => judgments,
        Err(error) => panic!("expected judgments, got error: {error}"),
    }
}

fn error_message(judge: &ProcessJudge, entities: &[Entity]) -> String {
    match judge.judge("alice@example.com", entities) {
        Ok(judgments) => panic!("expected an error, got judgments: {judgments:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn labels_a_candidate() {
    let entities = entities();
    let judgments = judge_ok(&judge("judge-ok"), &entities);
    assert_eq!(
        judgments,
        [Judgment::Labeled {
            index: 0,
            label: SemanticLabel::Business,
            confidence: 0.95,
        }]
    );
}

#[test]
fn allows_abstention() {
    let entities = entities();
    let judgments = judge_ok(&judge("judge-abstain"), &entities);
    assert!(judgments.is_empty(), "{judgments:?}");
}

#[test]
fn rejects_out_of_range_index() {
    let entities = entities();
    let message = error_message(&judge("judge-range"), &entities);
    assert!(
        message.contains("index 7 is out of range"),
        "got: {message}"
    );
}

#[test]
fn rejects_duplicate_index() {
    let entities = entities();
    let message = error_message(&judge("judge-dupe"), &entities);
    assert!(
        message.contains("repeated candidate index 0"),
        "got: {message}"
    );
}

#[test]
fn rejects_out_of_range_confidence() {
    let entities = entities();
    let message = error_message(&judge("judge-confidence"), &entities);
    assert!(message.contains("outside 0..=1"), "got: {message}");
}

#[test]
fn rejects_unknown_label() {
    let entities = entities();
    let message = error_message(&judge("judge-unknown-label"), &entities);
    assert!(message.contains("unknown label `banana`"), "got: {message}");
}

#[test]
fn errors_without_command() {
    let entities = entities();
    let message = error_message(&ProcessJudge::default(), &entities);
    assert!(message.contains("no command configured"), "got: {message}");
}

#[test]
fn errors_on_non_zero_exit() {
    let entities = entities();
    let message = error_message(&judge("exit"), &entities);
    assert!(
        message.contains("process judge exited with status"),
        "got: {message}"
    );
}
