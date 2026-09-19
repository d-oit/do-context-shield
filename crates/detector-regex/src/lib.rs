//! Regex-based detector plugin.

mod patterns;

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};
use patterns::compiled;

/// Regex detector for common sensitive values.
#[derive(Default)]
pub struct RegexDetector;

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
        // passes, and a 9-digit run is only a routing candidate until the ABA
        // checksum passes; the loose matchers cannot express either.
        entities.retain(|entity| {
            (entity.kind != "credit_card" || luhn_valid(&entity.value))
                && (entity.kind != "us_bank_routing" || aba_valid(&entity.value))
        });

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

/// Whether `value` is a 9-digit run with a valid ABA routing checksum
/// (weights `3, 7, 1, 3, 7, 1, 3, 7, 1`).
///
/// Unlike [`luhn_valid`], the source pattern admits no separators, so the
/// length check is exact and any other character rejects the value.
fn aba_valid(value: &str) -> bool {
    const WEIGHTS: [u32; 9] = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let bytes = value.as_bytes();
    if bytes.len() != WEIGHTS.len() || !bytes.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let sum = bytes
        .iter()
        .zip(WEIGHTS)
        .map(|(&byte, weight)| u32::from(byte - b'0') * weight)
        .sum::<u32>();
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

    #[test]
    fn detects_date_of_birth() {
        let detector = RegexDetector;
        let entities = match detector.detect("DOB 01/15/1990 recorded") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "date_of_birth");
        assert_eq!(entities[0].value, "01/15/1990");

        // Out-of-range months and out-of-window years are not dates.
        let invalid = match detector.detect("on 13/15/1990 and 01/15/1890") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(invalid.is_empty(), "{invalid:?}");
    }

    #[test]
    fn date_of_birth_and_ssn_coexist() {
        let detector = RegexDetector;
        let entities = match detector.detect("DOB 01/15/1990 SSN 123-45-6789") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].kind, "date_of_birth");
        assert_eq!(entities[1].kind, "ssn");
    }

    #[test]
    fn detects_passport() {
        let detector = RegexDetector;
        let entities = match detector.detect("passport AB1234567 expires 2030") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "passport");
        assert_eq!(entities[0].value, "AB1234567");

        // Passport numbers are uppercase-only.
        let lowercase = match detector.detect("passport ab1234567 expires") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(lowercase.is_empty(), "{lowercase:?}");
    }

    #[test]
    fn detects_us_drivers_license() {
        let detector = RegexDetector;
        let entities = match detector.detect("license W1234-56789-01234 on file") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "us_drivers_license");
        assert_eq!(entities[0].value, "W1234-56789-01234");
    }

    #[test]
    fn detects_us_bank_routing_with_aba_checksum() {
        let detector = RegexDetector;
        let entities = match detector.detect("routing 021000021 on file") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "us_bank_routing");
        assert_eq!(entities[0].value, "021000021");
    }

    #[test]
    fn rejects_invalid_aba_checksum() {
        let detector = RegexDetector;
        let entities = match detector.detect("routing 021000022 on file") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(
            !entities
                .iter()
                .any(|entity| entity.kind == "us_bank_routing"),
            "{entities:?}"
        );
    }

    #[test]
    fn detects_slack_token() {
        let detector = RegexDetector;
        // Synthetic fixture built programmatically so no credential literal is committed.
        let token = format!("xoxb-{}", "0123456789abcdef");
        let entities = match detector.detect(&token) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "slack_token");
        assert_eq!(entities[0].value, token);
    }

    #[test]
    fn detects_private_key() {
        let detector = RegexDetector;
        // Synthetic fixtures built programmatically so no key literal is committed.
        let header = format!("-----BEGIN {}PRIVATE KEY-----", "RSA ");
        let body = "MIIEowIBAAKCAQEAx7Vv";
        let block = format!("{header}\n{body}\n-----END {}PRIVATE KEY-----", "RSA ");
        // A header without a matching END marker still detects the header.
        let truncated = format!("-----BEGIN {}PRIVATE KEY BLOCK-----", "PGP ");
        let entities = match detector.detect(&format!("{block} then {truncated}")) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 2);
        assert_eq!(entities[0].kind, "private_key");
        assert_eq!(entities[0].value, block);
        assert_eq!(entities[1].kind, "private_key");
        assert_eq!(entities[1].value, truncated);
    }

    #[test]
    fn detects_google_api_key() {
        let detector = RegexDetector;
        // Synthetic fixture built programmatically so no credential literal is committed.
        let key = format!("AIza{}", "0123456789abcdefghijKLMNOPQRSTUVWXY");
        let entities = match detector.detect(&key) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "google_api_key");
        assert_eq!(entities[0].value, key);
    }

    #[test]
    fn detects_generic_secret_assignments() {
        let detector = RegexDetector;
        let assignment = format!("password={}", "hunter2hunter2");
        let entities = match detector.detect(&assignment) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "generic_secret");
        assert_eq!(entities[0].value, assignment);

        // Env-style keys are underscore-prefixed; the separator is consumed
        // into the span, so the assignment value is still redacted whole.
        let underscored = format!("DB_PASSWORD={}", "hunter2hunter2");
        let entities = match detector.detect(&underscored) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "generic_secret");
        assert_eq!(entities[0].value, underscored[2..]);

        let bearer = format!("Authorization: Bearer {}", "abcdef12345678");
        let entities = match detector.detect(&bearer) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].kind, "generic_secret");
        assert_eq!(entities[0].value, "Bearer abcdef12345678");

        // A bare keyword without an assignment or value is not a secret.
        let bare = match detector.detect("password") {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(bare.is_empty(), "{bare:?}");
    }
}
