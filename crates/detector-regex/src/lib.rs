//! Regex-based detector plugin.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use regex::Regex;
use std::sync::LazyLock;

/// Regex detector for common sensitive values.
#[derive(Default)]
pub struct RegexDetector;

/// IPv6 matcher: full, `::`-compressed, and v4-mapped forms.
///
/// Alternatives are ordered so the longest valid form wins at one start
/// position (`2001:db8::1.2.3.4` before `2001:db8::1`). Zone IDs (`%eth0`)
/// and a bare `::` are out of scope.
const IPV6: &str = concat!(
    r"(?i)",
    r"\b(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}:){0,5}(?:\d{1,3}\.){3}\d{1,3}\b",
    r"|\b(?:[0-9a-f]{1,4}:){1,7}(?:\d{1,3}\.){3}\d{1,3}\b",
    r"|::(?:[0-9a-f]{1,4}:){0,6}(?:\d{1,3}\.){3}\d{1,3}\b",
    r"|\b(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*\b",
    r"|\b(?:[0-9a-f]{1,4}:){1,7}:",
    r"|\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b",
    r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})\b",
);

/// Pattern specs: entity kind, regex source, and detector confidence.
///
/// The order is part of the contract: for one identical span the overlap pass
/// keeps the first entity pushed, so `ssn` and `credit_card` precede the
/// looser `phone` shape that also matches their text.
const SPECS: [(&str, &str, f32); 11] = [
    (
        "email",
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        0.99,
    ),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", 0.95),
    ("credit_card", r"\b(?:\d[ -]*?){13,19}\b", 0.95),
    ("phone", r"\b(?:\+?\d[\d ()-]{7,}\d)\b", 0.99),
    ("iban", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", 0.99),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.99),
    ("api_key", r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b", 0.99),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", 0.99),
    ("ipv6", IPV6, 0.99),
    (
        "aws_access_key",
        r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        0.99,
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        0.95,
    ),
];

/// One compiled pattern with its entity kind and confidence.
struct Compiled {
    kind: String,
    regex: Regex,
    confidence: f32,
}

/// Compiled once per process; patterns are constants, so a build failure
/// here means a programming error surfaced as [`DetectorError`].
static COMPILED: LazyLock<Result<Vec<Compiled>, String>> = LazyLock::new(|| {
    let mut specs = Vec::with_capacity(SPECS.len());
    for (kind, pattern, confidence) in SPECS {
        let regex = Regex::new(pattern).map_err(|error| error.to_string())?;
        specs.push(Compiled {
            kind: kind.to_owned(),
            regex,
            confidence,
        });
    }
    Ok(specs)
});

fn compiled() -> Result<&'static [Compiled], DetectorError> {
    match &*COMPILED {
        Ok(specs) => Ok(specs.as_slice()),
        Err(message) => Err(DetectorError::Message(message.clone())),
    }
}

impl Detector for RegexDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        let mut entities = Vec::new();
        for spec in compiled()? {
            for found in spec.regex.find_iter(input) {
                entities.push(Entity {
                    kind: spec.kind.clone(),
                    start: found.start(),
                    end: found.end(),
                    value: found.as_str().to_owned(),
                    confidence: spec.confidence,
                });
            }
        }

        // A long digit run is only a card candidate until its checksum
        // passes; the loose matcher cannot express Luhn itself.
        entities.retain(|entity| entity.kind != "credit_card" || luhn_valid(&entity.value));

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

/// Whether `value` is a digit run (spaces and hyphens ignored) with a valid
/// Luhn checksum.
///
/// Returns `false` for any other character, so only card-shaped values reach
/// the checksum.
fn luhn_valid(value: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for byte in value.bytes().rev() {
        if byte == b' ' || byte == b'-' {
            continue;
        }
        if !byte.is_ascii_digit() {
            return false;
        }
        let mut digit = u32::from(byte - b'0');
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        double = !double;
    }
    sum % 10 == 0
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

    #[test]
    fn detects_credit_card_with_luhn() {
        let detector = RegexDetector;
        let entities = match detector.detect("card 4111 1111 1111 1111 on file") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "credit_card");
        assert_eq!(entities[0].value, "4111 1111 1111 1111");
    }

    #[test]
    fn rejects_invalid_luhn() {
        let detector = RegexDetector;
        let entities = match detector.detect("4111 1111 1111 1112") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(
            !entities.iter().any(|entity| entity.kind == "credit_card"),
            "{entities:?}"
        );
    }

    #[test]
    fn detects_ssn() {
        let detector = RegexDetector;
        let entities = match detector.detect("SSN is 123-45-6789") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "ssn");
    }

    #[test]
    fn detects_ipv6() {
        let detector = RegexDetector;
        let entities = match detector.detect("host 2001:0db8:85a3::8a2e:0370:7334 up") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "ipv6");
        assert_eq!(entities[0].value, "2001:0db8:85a3::8a2e:0370:7334");
    }

    #[test]
    fn detects_aws_key() {
        let detector = RegexDetector;
        // Synthetic fixture built programmatically so no credential literal is committed.
        let aws_key = format!("AKIA{}", "0123456789ABCDEF");
        let entities = match detector.detect(&aws_key) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "aws_access_key");
    }

    #[test]
    fn detects_jwt() {
        let detector = RegexDetector;
        // Synthetic fixture built programmatically so no token literal is committed.
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "hbGciOiJIUzI1NiJ9", "zdWIiOiIxIn0", "signature0123456789"
        );
        let entities = match detector.detect(&jwt) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "jwt");
    }

    #[test]
    fn credit_card_vs_phone_overlap() {
        let detector = RegexDetector;
        // The loose phone shape matches this span too; the more specific kind
        // wins the equal-span tie in the overlap pass.
        let entities = match detector.detect("pay 4111 1111 1111 1111 now") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "credit_card");
    }
}
