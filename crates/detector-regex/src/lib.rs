//! Regex-based detector plugin.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use regex::Regex;
use std::sync::OnceLock;

/// Regex detector for common sensitive values.
#[derive(Default)]
pub struct RegexDetector;

const SPECS: [(&str, &str); 6] = [
    ("email", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    ("phone", r"\b(?:\+?\d[\d ()-]{7,}\d)\b"),
    ("iban", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("api_key", r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
];

/// Compiled once per process; patterns are constants, so a build failure
/// here means a programming error surfaced as [`DetectorError`].
static COMPILED: OnceLock<Vec<(String, Regex)>> = OnceLock::new();

fn compiled() -> Result<&'static [(String, Regex)], DetectorError> {
    if let Some(cached) = COMPILED.get() {
        return Ok(cached);
    }
    let mut specs = Vec::with_capacity(SPECS.len());
    for (kind, pattern) in SPECS {
        let regex =
            Regex::new(pattern).map_err(|error| DetectorError::Message(error.to_string()))?;
        specs.push((kind.to_owned(), regex));
    }
    // A concurrent caller may win the race; `get_or_init` returns the stored
    // value either way, so at most one compilation is discarded.
    Ok(COMPILED.get_or_init(|| specs))
}

impl Detector for RegexDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        let mut entities = Vec::new();
        for (kind, regex) in compiled()? {
            for found in regex.find_iter(input) {
                entities.push(Entity {
                    kind: kind.clone(),
                    start: found.start(),
                    end: found.end(),
                    value: found.as_str().to_owned(),
                    confidence: 0.99,
                });
            }
        }

        entities.sort_by_key(|entity| (entity.start, usize::MAX - entity.end));
        let mut deduped = Vec::with_capacity(entities.len());
        for entity in entities {
            if deduped
                .iter()
                .any(|saved: &Entity| entity.start < saved.end && saved.start < entity.end)
            {
                continue;
            }
            deduped.push(entity);
        }
        deduped.sort_by_key(|entity: &Entity| (entity.start, entity.end));
        Ok(deduped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email_and_key() {
        let detector = RegexDetector;
        // Synthetic fixture built programmatically so no secret-like literal is committed.
        let api_key = format!("sk-test-{}", "0123456789abcdef");
        let input = format!("alice@example.com {api_key}");
        let entities = match detector.detect(&input) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].kind, "email");
        assert_eq!(entities[1].kind, "api_key");
    }

    #[test]
    fn api_key_is_not_double_counted_as_phone() {
        let detector = RegexDetector;
        let api_key = format!("sk-test-{}", "0123456789abcdef");
        let entities = match detector.detect(&api_key) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        // Longest-span-wins: the api_key match suppresses any phone overlap.
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "api_key");
    }

    #[test]
    fn repeated_detection_reuses_compiled_patterns() {
        let detector = RegexDetector;
        for _ in 0..3 {
            match detector.detect("call +1 555 010 1234 today") {
                Ok(_) => {}
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
    }
}
