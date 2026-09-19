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
mod tests;
