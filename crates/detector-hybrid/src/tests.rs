//! Unit tests with stub detectors: ordering, concatenation, fail-closed.

use super::*;
use std::sync::{Arc, Mutex};

fn entity(kind: &str, start: usize, end: usize, value: &str) -> Entity {
    Entity {
        kind: kind.to_owned(),
        start,
        end,
        value: value.to_owned(),
        confidence: 0.9,
    }
}

/// Detector stub that records its call and returns a fixed result.
struct Stub {
    name: &'static str,
    entities: Vec<Entity>,
    log: Arc<Mutex<Vec<&'static str>>>,
    fails: bool,
}

impl Detector for Stub {
    fn detect(&self, _input: &str) -> Result<Vec<Entity>, DetectorError> {
        match self.log.lock() {
            Ok(mut log) => log.push(self.name),
            Err(error) => {
                return Err(DetectorError::Message(format!(
                    "stub log poisoned: {error}"
                )));
            }
        }
        if self.fails {
            return Err(DetectorError::Message(format!(
                "{} detector failed",
                self.name
            )));
        }
        Ok(self.entities.clone())
    }
}

fn stub(
    name: &'static str,
    entities: Vec<Entity>,
    log: &Arc<Mutex<Vec<&'static str>>>,
    fails: bool,
) -> Box<dyn Detector> {
    Box::new(Stub {
        name,
        entities,
        log: Arc::clone(log),
        fails,
    })
}

#[test]
fn runs_both_detectors_in_order_and_concatenates() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", vec![entity("ssn", 0, 3, "123")], &log, false),
        stub(
            "secondary",
            vec![entity("full_name", 4, 8, "John")],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("123 John") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    let kinds: Vec<&str> = entities.iter().map(|entity| entity.kind.as_str()).collect();
    assert_eq!(kinds, ["ssn", "full_name"]);
    match log.lock() {
        Ok(log) => assert_eq!(*log, ["primary", "secondary"]),
        Err(error) => panic!("stub log poisoned: {error}"),
    }
}

#[test]
fn primary_spans_displace_overlapping_secondary_spans() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        // The authoritative primary span: the full SSN.
        stub(
            "primary",
            vec![entity("ssn", 0, 11, "123-45-6789")],
            &log,
            false,
        ),
        // Noisy secondary fragments overlapping the SSN, plus a disjoint city.
        stub(
            "secondary",
            vec![
                entity("tax_id", 0, 4, "123-"),
                entity("ssn", 8, 11, "789"),
                entity("city", 20, 26, "Boston"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("123-45-6789 -- Boston") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    let kinds: Vec<(&str, usize, usize)> = entities
        .iter()
        .map(|entity| (entity.kind.as_str(), entity.start, entity.end))
        .collect();
    assert_eq!(kinds, [("ssn", 0, 11), ("city", 20, 26)]);
}

#[test]
fn both_empty_is_empty() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub("secondary", Vec::new(), &log, false),
    );
    match hybrid.detect("plain text") {
        Ok(entities) => assert!(entities.is_empty()),
        Err(error) => panic!("hybrid detect failed: {error}"),
    }
}

#[test]
fn secondary_failure_fails_the_call() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", vec![entity("ssn", 0, 3, "123")], &log, false),
        stub("secondary", Vec::new(), &log, true),
    );
    match hybrid.detect("123 John") {
        Ok(entities) => panic!("expected fail-closed error, got {entities:?}"),
        Err(error) => assert!(error.to_string().contains("secondary detector failed")),
    }
}

#[test]
fn primary_failure_short_circuits() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, true),
        stub("secondary", Vec::new(), &log, false),
    );
    match hybrid.detect("123 John") {
        Ok(entities) => panic!("expected fail-closed error, got {entities:?}"),
        Err(error) => assert!(error.to_string().contains("primary detector failed")),
    }
    match log.lock() {
        Ok(log) => assert_eq!(*log, ["primary"]),
        Err(error) => panic!("stub log poisoned: {error}"),
    }
}
