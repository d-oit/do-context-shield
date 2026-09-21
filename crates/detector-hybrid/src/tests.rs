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

/// `(kind, start, end)` tuples in result order.
fn spans(entities: &[Entity]) -> Vec<(&str, usize, usize)> {
    entities
        .iter()
        .map(|entity| (entity.kind.as_str(), entity.start, entity.end))
        .collect()
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

#[test]
fn touching_secondary_spans_are_kept() {
    // Half-open spans: secondary entities that touch a primary boundary (on
    // either side) do not overlap it and survive the merge.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", vec![entity("ssn", 5, 10, "56789")], &log, false),
        stub(
            "secondary",
            vec![
                entity("city", 0, 5, "01234"),
                entity("state", 10, 15, "abcde"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("0123456789abcde") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(
        spans(&entities),
        [("ssn", 5, 10), ("city", 0, 5), ("state", 10, 15)]
    );
}

#[test]
fn primary_displaces_engulfing_secondary() {
    // A secondary entity wider than the primary span it overlaps still loses:
    // primary precedence is not a length comparison.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", vec![entity("ssn", 2, 5, "234")], &log, false),
        stub(
            "secondary",
            vec![entity("tax_id", 0, 10, "0123456789")],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("0123456789") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("ssn", 2, 5)]);
}

#[test]
fn equal_length_overlapping_secondaries_keep_first() {
    // Equal-length secondary overlap: the earlier-returned span is kept.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub(
            "secondary",
            vec![
                entity("city", 0, 5, "01234"),
                entity("state", 2, 7, "23456"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("0123456") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("city", 0, 5)]);
}

#[test]
fn longer_secondary_displaces_shorter_secondary() {
    // A strictly longer secondary displaces the shorter span it overlaps.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub(
            "secondary",
            vec![
                entity("city", 0, 5, "01234"),
                entity("address", 3, 9, "345678"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("0123456789") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("address", 3, 9)]);
}

#[test]
fn engulfing_secondary_displaces_shorter_secondary() {
    // A contained secondary never displaces the wider kept one: the engulfer
    // arrived first and stays whole.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub(
            "secondary",
            vec![
                entity("address", 0, 10, "0123456789"),
                entity("city", 3, 5, "34"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("0123456789") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("address", 0, 10)]);
}

#[test]
fn longer_secondary_kept_when_returned_first() {
    // Longest-span-wins does not depend on arrival order: a later, shorter
    // overlapping secondary never displaces the longer kept one.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub(
            "secondary",
            vec![
                entity("address", 3, 9, "345678"),
                entity("city", 0, 5, "01234"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("0123456789") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("address", 3, 9)]);
}

#[test]
fn exact_duplicate_secondary_spans_keep_one() {
    // An exact duplicate span is dropped, not appended.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub(
            "secondary",
            vec![entity("city", 0, 5, "01234"), entity("city", 0, 5, "01234")],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("01234") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("city", 0, 5)]);
}

#[test]
fn empty_input_returns_merged_empty() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub("primary", Vec::new(), &log, false),
        stub("secondary", Vec::new(), &log, false),
    );
    match hybrid.detect("") {
        Ok(entities) => assert!(entities.is_empty()),
        Err(error) => panic!("hybrid detect failed: {error}"),
    }
}

#[test]
fn unicode_offsets_merge_by_byte_spans() {
    // Offsets are UTF-8 byte offsets: the secondary span overlapping the
    // multi-byte prefix by bytes is dropped, and the span that merely touches
    // the primary at byte 10 survives.
    let log = Arc::new(Mutex::new(Vec::new()));
    let hybrid = HybridDetector::new(
        stub(
            "primary",
            vec![entity("secret", 4, 10, "secret")],
            &log,
            false,
        ),
        stub(
            "secondary",
            vec![
                entity("person", 0, 8, "🎉secr"),
                entity("emoji", 10, 14, "🎉"),
            ],
            &log,
            false,
        ),
    );
    let entities = match hybrid.detect("🎉secret🎉") {
        Ok(entities) => entities,
        Err(error) => panic!("hybrid detect failed: {error}"),
    };
    assert_eq!(spans(&entities), [("secret", 4, 10), ("emoji", 10, 14)]);
}
