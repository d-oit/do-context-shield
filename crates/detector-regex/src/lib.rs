//! Regex-based detector plugin.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use regex::Regex;

/// Regex detector for common sensitive values.
#[derive(Default)]
pub struct RegexDetector;

impl Detector for RegexDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        let specs = [
            ("email", r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
            ("phone", r"\b(?:\+?\d[\d ()-]{7,}\d)\b"),
            ("iban", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"),
            ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            ("api_key", r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b"),
            ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        ];

        let mut entities = Vec::new();
        for (kind, pattern) in specs {
            let regex =
                Regex::new(pattern).map_err(|error| DetectorError::Message(error.to_string()))?;
            for found in regex.find_iter(input) {
                entities.push(Entity {
                    kind: kind.to_owned(),
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
        let entities = match detector.detect("alice@example.com sk-12345678901234567890") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].kind, "email");
        assert_eq!(entities[1].kind, "api_key");
    }
}
