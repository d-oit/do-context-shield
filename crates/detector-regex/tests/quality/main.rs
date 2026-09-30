//! Repeatable quality benchmark for the default regex detector.
//!
//! Three corpora, all built in-process from a fixed seed (no fixture
//! literals, no network):
//!
//! - generated: every kind declared by the pattern table gets checksum-valid
//!   values, and each must be detected at its exact span with that kind;
//! - adversarial: values shaped like a kind but invalid by that kind's own
//!   rule (checksum, range, length) must not produce the kind;
//! - benign: prose, code, and numbers must produce no entities at all.
//!
//! Run `cargo test -p do-context-shield-detector-regex --test quality -- --nocapture`
//! to print the per-kind recall table.

use corpus::{Rng, adversarial_cases, benign_corpus, declared_kinds, generated_cases};
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{Detector, Entity};

mod corpus;

/// Detect entities, failing the test on a detector error.
fn detect(input: &str) -> Vec<Entity> {
    match RegexDetector.detect(input) {
        Ok(entities) => entities,
        Err(error) => panic!("detector failed: {error}"),
    }
}

#[test]
fn generated_corpus_is_detected_at_the_exact_span() {
    let mut rng = Rng::seeded();
    let cases = generated_cases(&mut rng);
    let kinds = declared_kinds();
    let mut detected = 0usize;
    for kind in &kinds {
        let matching = cases.iter().filter(|(case_kind, _)| case_kind == kind);
        let total = matching.clone().count();
        let hits = matching
            .filter(|(_, value)| {
                detect(value)
                    .iter()
                    .any(|entity| entity.kind == *kind && entity.value == *value)
            })
            .count();
        println!("{kind}: {hits}/{total} detected");
        assert!(total > 0, "kind `{kind}` has no generated samples");
        assert_eq!(hits, total, "kind `{kind}` missed generated samples");
        detected += hits;
    }
    println!("generated corpus: {detected}/{} detected", cases.len());
}

#[test]
fn adversarial_lookalikes_do_not_match_their_kind() {
    let mut rng = Rng::seeded();
    for (index, (kind, value)) in adversarial_cases(&mut rng).iter().enumerate() {
        let matched = detect(value).iter().any(|entity| entity.kind == *kind);
        assert!(
            !matched,
            "adversarial case {index} was reported as `{kind}`"
        );
    }
    println!("adversarial corpus: all lookalikes rejected");
}

#[test]
fn benign_text_produces_no_entities() {
    for (index, text) in benign_corpus().iter().enumerate() {
        let entities = detect(text);
        assert!(
            entities.is_empty(),
            "benign case {index} produced {} entities",
            entities.len()
        );
    }
    println!("benign corpus: no entities");
}
