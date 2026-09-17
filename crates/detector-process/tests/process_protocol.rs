//! End-to-end tests for the process detector protocol driver.

use do_context_shield_detector_process::{ProcessDetector, ProcessDetectorConfig};
use do_context_shield_plugin_api::Detector;
use std::time::{Duration, Instant};

/// Command line invoking the fixture in `mode` (`sh` keeps the fixture
/// executable-bit independent).
fn command(mode: &str) -> String {
    format!(
        "sh {} {mode}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/detector.sh")
    )
}

fn detector(mode: &str) -> ProcessDetector {
    ProcessDetector::new(ProcessDetectorConfig::with_command(command(mode)))
}

fn detect(detector: &ProcessDetector, input: &str) -> Vec<do_context_shield_plugin_api::Entity> {
    match detector.detect(input) {
        Ok(entities) => entities,
        Err(error) => panic!("expected entities, got error: {error}"),
    }
}

fn error_message(detector: &ProcessDetector, input: &str) -> String {
    match detector.detect(input) {
        Ok(entities) => panic!("expected an error, got entities: {entities:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn detects_entities_from_process() {
    let entities = detect(&detector("ok"), "alice@example.com");
    let [entity] = entities.as_slice() else {
        panic!("expected exactly one entity, got {entities:?}");
    };
    assert_eq!(entity.kind, "email");
    assert_eq!((entity.start, entity.end), (0, 17));
    assert_eq!(entity.value, "alice@example.com");
    assert!((entity.confidence - 0.99).abs() < 1e-6);
}

#[test]
fn applies_defaults_and_sorts_entities() {
    let entities = detect(&detector("two"), "alice@example.com");
    let reported: Vec<(&str, usize, usize, &str, f32)> = entities
        .iter()
        .map(|entity| {
            (
                entity.kind.as_str(),
                entity.start,
                entity.end,
                entity.value.as_str(),
                entity.confidence,
            )
        })
        .collect();
    assert_eq!(
        reported,
        [
            ("email", 0, 5, "alice", 1.0),
            ("phone", 6, 17, "example.com", 1.0),
        ]
    );
}

#[test]
fn longest_span_wins_for_overlapping_spans() {
    let entities = detect(&detector("overlap"), "alice@example.com");
    let [entity] = entities.as_slice() else {
        panic!("expected exactly one entity, got {entities:?}");
    };
    assert_eq!(entity.kind, "email");
    assert_eq!((entity.start, entity.end), (0, 17));
}

#[test]
fn rejects_value_mismatch() {
    let message = error_message(&detector("mismatch"), "alice@example.com");
    assert!(message.contains("does not match input"), "got: {message}");
}

#[test]
fn rejects_non_char_boundary_span() {
    let message = error_message(&detector("badspan"), "grüße");
    assert!(message.contains("invalid span"), "got: {message}");
}

#[test]
fn errors_without_command() {
    let message = error_message(&ProcessDetector::default(), "x");
    assert!(message.contains("no command configured"), "got: {message}");
}

#[test]
fn errors_on_spawn_failure() {
    let detector = ProcessDetector::new(ProcessDetectorConfig::with_command(
        "definitely-not-a-real-binary-xyz".to_owned(),
    ));
    let message = error_message(&detector, "x");
    assert!(message.contains("failed to start"), "got: {message}");
}

#[test]
fn errors_on_non_zero_exit() {
    let message = error_message(&detector("exit"), "alice@example.com");
    assert!(message.contains("exited with status"), "got: {message}");
}

#[test]
fn errors_on_invalid_json() {
    let message = error_message(&detector("junk"), "alice@example.com");
    assert!(message.contains("invalid JSON"), "got: {message}");
}

#[test]
fn errors_on_empty_response() {
    let message = error_message(&detector("empty"), "alice@example.com");
    assert!(message.contains("empty response"), "got: {message}");
}

#[test]
fn times_out_and_kills_child() {
    let detector = ProcessDetector::new(ProcessDetectorConfig {
        command: Some(command("hang")),
        timeout: Duration::from_millis(300),
    });
    let started = Instant::now();
    let message = error_message(&detector, "alice@example.com");
    let elapsed = started.elapsed();
    assert!(message.contains("timed out"), "got: {message}");
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout did not fire, elapsed {elapsed:?}"
    );
}
