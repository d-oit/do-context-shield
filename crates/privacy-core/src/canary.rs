//! Keyed canary boundary markers.
//!
//! A canary is an HMAC-SHA256 tag over the session scope, keyed by a per-install
//! secret. Sanitized output carries it as an HTML comment so an egress proxy
//! holding the same key can confirm the text passed through the local shield.
//! The tag is derived from the scope only: it never contains vault plaintext,
//! and it cannot be forged without the key.

use std::fmt::Write as _;

use do_context_shield_plugin_api::ScopeId;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Domain separator, so the same key can never produce a tag for another purpose.
const DOMAIN: &[u8] = b"do-context-shield-canary-v1\0";
/// Marker prefix written before the token.
const MARKER_PREFIX: &str = "<!-- do-context-shield-canary: ";
/// Marker suffix written after the token.
const MARKER_SUFFIX: &str = " -->";
/// Minimum accepted key length in bytes.
pub const MIN_KEY_BYTES: usize = 32;

/// Canary failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanaryError {
    /// The key is shorter than [`MIN_KEY_BYTES`].
    #[error("canary key must be at least {MIN_KEY_BYTES} bytes")]
    KeyTooShort,
}

/// The canary token for `scope` under `key`, as lowercase hex.
///
/// # Errors
///
/// Returns [`CanaryError::KeyTooShort`] when `key` is under [`MIN_KEY_BYTES`].
pub fn canary_token(key: &[u8], scope: &ScopeId) -> Result<String, CanaryError> {
    let mac = mac_for(key, scope)?;
    Ok(hex(&mac.finalize().into_bytes()))
}

/// The full HTML-comment marker for `scope` under `key`.
///
/// # Errors
///
/// Returns [`CanaryError::KeyTooShort`] when `key` is under [`MIN_KEY_BYTES`].
pub fn canary_marker(key: &[u8], scope: &ScopeId) -> Result<String, CanaryError> {
    Ok(format!(
        "{MARKER_PREFIX}{}{MARKER_SUFFIX}",
        canary_token(key, scope)?
    ))
}

/// Whether `text` contains a canary marker valid for `scope` under `key`.
///
/// The presented tag is checked with `hmac`'s constant-time `verify_slice`, not
/// a string comparison.
///
/// # Errors
///
/// Returns [`CanaryError::KeyTooShort`] when `key` is under [`MIN_KEY_BYTES`].
pub fn verify_canary(key: &[u8], scope: &ScopeId, text: &str) -> Result<bool, CanaryError> {
    let mac = mac_for(key, scope)?;
    let Some(start) = text.find(MARKER_PREFIX) else {
        return Ok(false);
    };
    let rest = &text[start + MARKER_PREFIX.len()..];
    let Some(end) = rest.find(MARKER_SUFFIX) else {
        return Ok(false);
    };
    let Some(presented) = decode_hex(&rest[..end]) else {
        return Ok(false);
    };
    Ok(mac.verify_slice(&presented).is_ok())
}

fn mac_for(key: &[u8], scope: &ScopeId) -> Result<Hmac<Sha256>, CanaryError> {
    if key.len() < MIN_KEY_BYTES {
        return Err(CanaryError::KeyTooShort);
    }
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| CanaryError::KeyTooShort)?;
    mac.update(DOMAIN);
    mac.update(scope.0.as_bytes());
    Ok(mac)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        (0u8..32).collect()
    }

    fn scope(name: &str) -> ScopeId {
        ScopeId(name.to_owned())
    }

    fn token(key: &[u8], scope_name: &str) -> String {
        match canary_token(key, &scope(scope_name)) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn marker(key: &[u8], scope_name: &str) -> String {
        match canary_marker(key, &scope(scope_name)) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn token_is_stable_and_fixed_width() {
        let first = token(&key(), "s1");
        assert_eq!(first, token(&key(), "s1"));
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn token_differs_across_scopes_and_keys() {
        let base = token(&key(), "s1");
        let mut other_key = key();
        other_key[0] ^= 0xff;
        assert_ne!(base, token(&key(), "s2"));
        assert_ne!(base, token(&other_key, "s1"));
    }

    #[test]
    fn short_key_is_rejected() {
        assert_eq!(
            canary_token(&[1u8; 8], &scope("s1")),
            Err(CanaryError::KeyTooShort)
        );
    }

    #[test]
    fn marker_verifies_only_for_its_scope_and_key() {
        let text = format!("safe body\n{}\n", marker(&key(), "s1"));
        assert_eq!(verify_canary(&key(), &scope("s1"), &text), Ok(true));
        assert_eq!(verify_canary(&key(), &scope("s2"), &text), Ok(false));
        let mut other = key();
        other[31] ^= 1;
        assert_eq!(verify_canary(&other, &scope("s1"), &text), Ok(false));
    }

    #[test]
    fn forged_or_missing_markers_fail_closed() {
        let forged = format!("{MARKER_PREFIX}{}{MARKER_SUFFIX}", "00".repeat(32));
        assert_eq!(verify_canary(&key(), &scope("s1"), &forged), Ok(false));
        assert_eq!(
            verify_canary(&key(), &scope("s1"), "no marker here"),
            Ok(false)
        );
        let truncated = format!("{MARKER_PREFIX}abcd");
        assert_eq!(verify_canary(&key(), &scope("s1"), &truncated), Ok(false));
    }
}
