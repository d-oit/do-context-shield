//! Low-level cryptographic unit tests for envelope construction and parsing.

use super::*;
use crate::encrypted::{decode_hex, decrypt, encode_hex, encrypt, is_envelope};

const KEY_BYTES: usize = 32;

/// Random key from the OS entropy source.
fn random_key() -> VaultKey {
    let mut bytes = [0u8; KEY_BYTES];
    match getrandom::fill(&mut bytes) {
        Ok(()) => VaultKey::new(bytes),
        Err(error) => panic!("unexpected error: {error}"),
    }
}

/// Encrypt `plaintext` and parse the envelope for decryption.
fn envelope(plaintext: &[u8], key: &VaultKey) -> serde_json::Value {
    let bytes = match encrypt(plaintext, key) {
        Ok(bytes) => bytes,
        Err(error) => panic!("unexpected error: {error}"),
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

#[test]
fn key_hex_round_trips_and_rejects_bad_input() {
    let mut expected_bytes = [0_u8; KEY_BYTES];
    if let Err(error) = getrandom::fill(&mut expected_bytes) {
        panic!("unexpected error: {error}");
    }
    let encoded = encode_hex(&expected_bytes);
    let parsed = match VaultKey::from_hex(&encoded) {
        Ok(parsed) => parsed,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let expected = VaultKey::new(expected_bytes);
    let decrypted = match decrypt(envelope(b"hex key check", &expected), &parsed) {
        Ok(plaintext) => plaintext,
        Err(error) => panic!("parsed hex key did not match the expected bytes: {error}"),
    };
    assert_eq!(decrypted, b"hex key check");

    // Surrounding whitespace is tolerated; a wrong length or character is not.
    assert!(VaultKey::from_hex(&format!("  {}  \n", "0f".repeat(KEY_BYTES))).is_ok());
    for bad in [
        "",
        "00",
        &"00".repeat(KEY_BYTES - 1),
        &"00".repeat(KEY_BYTES + 1),
    ] {
        assert!(VaultKey::from_hex(bad).is_err(), "{bad}");
    }
    assert!(VaultKey::from_hex(&"zz".repeat(KEY_BYTES)).is_err());
}

#[test]
fn encrypt_decrypt_round_trips_and_hides_the_payload() {
    let plaintext = br#"{"mappings":[{"original":"alice@example.com"}]}"#;
    let key = random_key();
    let envelope = match encrypt(plaintext, &key) {
        Ok(bytes) => bytes,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let text = String::from_utf8_lossy(&envelope).into_owned();
    assert!(!text.contains("alice@example.com"), "{text}");
    let value: serde_json::Value = match serde_json::from_slice(&envelope) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(is_envelope(&value));
    let decrypted = match decrypt(value, &key) {
        Ok(bytes) => bytes,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(decrypted, plaintext);
}

#[test]
fn each_write_uses_a_fresh_nonce() {
    let key = random_key();
    let first = match encrypt(b"state", &key) {
        Ok(bytes) => bytes,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let second = match encrypt(b"state", &key) {
        Ok(bytes) => bytes,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_ne!(first, second, "identical state must not reuse a nonce");
    let nonce = |bytes: &[u8]| -> String {
        let value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        value["nonce"].as_str().unwrap_or_default().to_owned()
    };
    assert_ne!(nonce(&first), nonce(&second));
}

#[test]
fn a_wrong_key_fails_closed() {
    let right = random_key();
    let wrong = random_key();
    let error = match decrypt(envelope(b"state", &right), &wrong) {
        Ok(bytes) => panic!("expected a failure, got {} bytes", bytes.len()),
        Err(error) => error,
    };
    assert!(error.to_string().contains("wrong key"), "{error}");
}

#[test]
fn a_modified_payload_or_marker_fails_closed() {
    let key = random_key();
    for (field, replacement) in [("payload", "00"), ("nonce", "00"), ("version", "99")] {
        let bytes = match encrypt(b"state", &key) {
            Ok(bytes) => bytes,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        value[field] = serde_json::Value::String(replacement.to_owned());
        assert!(decrypt(value, &key).is_err(), "{field}");
    }
}

#[test]
fn unsupported_cipher_fails_closed() {
    let key = random_key();
    let bytes = match encrypt(b"state", &key) {
        Ok(bytes) => bytes,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    value["cipher"] = serde_json::Value::String("aes-gcm".to_owned());
    let error = match decrypt(value, &key) {
        Ok(_) => panic!("expected an unsupported-cipher error"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("unsupported vault cipher"),
        "{error}"
    );
}

#[test]
fn hex_codec_round_trips() {
    for bytes in [vec![], vec![0x00, 0xff, 0x10], vec![0xab; 40]] {
        let hex = encode_hex(&bytes);
        assert_eq!(decode_hex(&hex).ok(), Some(bytes.clone()), "{hex}");
        assert_eq!(decode_hex(&hex.to_uppercase()).ok(), Some(bytes), "{hex}");
    }
    assert!(decode_hex("0").is_err());
    assert!(decode_hex("gg").is_err());
}

#[test]
fn envelope_detection_requires_both_markers() {
    for text in [r#"{"version":1}"#, r#"{"cipher":"x"}"#] {
        let value: serde_json::Value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(!is_envelope(&value), "{text}");
    }
}
