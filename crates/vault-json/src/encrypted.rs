//! At-rest encryption for the JSON vault.
//!
//! The file is a small JSON envelope — format version, cipher name, the nonce,
//! and the hex-encoded ciphertext — so a wrong key, a truncated file, or a
//! future format version fails closed with a named reason instead of being
//! misread as vault state. XChaCha20-Poly1305 is used with a fresh random
//! 192-bit nonce per write; the AEAD tag authenticates the payload, and the
//! format marker is bound as associated data.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use do_context_shield_plugin_api::VaultError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Format version written to the envelope and bound as associated data.
const VERSION: u32 = 2;
/// Cipher name written to the envelope.
const CIPHER: &str = "xchacha20poly1305";
/// Nonce size of XChaCha20-Poly1305.
const NONCE_BYTES: usize = 24;
/// Key size of XChaCha20-Poly1305.
const KEY_BYTES: usize = 32;
/// Associated data binding a ciphertext to this format and version.
const ASSOCIATED_DATA: &[u8] = b"do-context-shield-json-vault:v2";

/// Raw 32-byte key for encrypting the JSON vault at rest.
///
/// Deliberately has no `Debug` implementation, so a key cannot be formatted
/// into a log line or an error by accident.
pub struct VaultKey([u8; KEY_BYTES]);

impl VaultKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Read a key from a file holding exactly 64 hex characters.
    ///
    /// Surrounding whitespace (for example a trailing newline) is ignored. On
    /// Unix the file must not be readable or writable by group or others;
    /// elsewhere the permission check is skipped because the platform has no
    /// equivalent mode.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the file cannot be read, is accessible
    /// beyond its owner (Unix), or does not hold exactly 32 hex-encoded bytes.
    pub fn from_file(path: &Path) -> Result<Self, VaultError> {
        #[cfg(unix)]
        check_key_file_permissions(path)?;
        let text = fs::read_to_string(path).map_err(|error| {
            VaultError::Message(format!(
                "cannot read vault key file `{}`: {error}",
                path.display()
            ))
        })?;
        Self::from_hex(&text)
    }

    /// Parse exactly 64 hex characters into a key.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the text is not exactly 32 hex-encoded bytes.
    pub fn from_hex(text: &str) -> Result<Self, VaultError> {
        let bytes = decode_hex(text)?;
        if bytes.len() != KEY_BYTES {
            return Err(VaultError::Message(format!(
                "vault key must be {KEY_BYTES} bytes ({} hex characters), got {} bytes",
                KEY_BYTES * 2,
                bytes.len()
            )));
        }
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}

/// Reject a key file that other users on the machine could read.
#[cfg(unix)]
fn check_key_file_permissions(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|error| {
            VaultError::Message(format!(
                "cannot read vault key file `{}`: {error}",
                path.display()
            ))
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(VaultError::Message(format!(
            "vault key file `{}` is accessible beyond its owner (mode {:03o}); restrict it with `chmod 600`",
            path.display(),
            mode & 0o777
        )));
    }
    Ok(())
}

/// Encrypted vault file envelope.
#[derive(Deserialize, Serialize)]
struct Envelope {
    version: u32,
    cipher: String,
    nonce: String,
    payload: String,
}

/// Whether `value` carries the encrypted-envelope markers.
pub(super) fn is_envelope(value: &serde_json::Value) -> bool {
    value.get("version").is_some() && value.get("cipher").is_some()
}

/// Encrypt serialized vault state into envelope JSON.
///
/// # Errors
///
/// Returns [`VaultError`] when the system entropy source is unavailable, the
/// AEAD fails, or the envelope cannot be serialized.
pub(super) fn encrypt(state_json: &[u8], key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|error| {
        VaultError::Message(format!(
            "cannot obtain entropy for the vault nonce ({error})"
        ))
    })?;
    let ciphertext = cipher(key)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: state_json,
                aad: ASSOCIATED_DATA,
            },
        )
        .map_err(|_| VaultError::Message("vault encryption failed".to_owned()))?;
    let envelope = Envelope {
        version: VERSION,
        cipher: CIPHER.to_owned(),
        nonce: encode_hex(&nonce),
        payload: encode_hex(&ciphertext),
    };
    serde_json::to_vec(&envelope).map_err(|error| super::json_error(&error))
}

/// Decrypt an envelope file value into the serialized vault state.
///
/// # Errors
///
/// Returns [`VaultError`] when the envelope is malformed, uses an unsupported
/// version or cipher, or fails authentication with `key` (wrong key or a
/// modified file).
pub(super) fn decrypt(value: serde_json::Value, key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let envelope: Envelope =
        serde_json::from_value(value).map_err(|error| super::json_error(&error))?;
    if envelope.version != VERSION {
        return Err(VaultError::Message(format!(
            "unsupported vault format version {} (this build reads version {VERSION})",
            envelope.version
        )));
    }
    if envelope.cipher != CIPHER {
        return Err(VaultError::Message(format!(
            "unsupported vault cipher `{}` (this build reads `{CIPHER}`)",
            envelope.cipher
        )));
    }
    let nonce = decode_hex(&envelope.nonce)?;
    if nonce.len() != NONCE_BYTES {
        return Err(VaultError::Message(format!(
            "vault nonce must be {NONCE_BYTES} bytes, got {}",
            nonce.len()
        )));
    }
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    nonce_bytes.copy_from_slice(&nonce);
    let payload = decode_hex(&envelope.payload)?;
    cipher(key)?
        .decrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: &payload,
                aad: ASSOCIATED_DATA,
            },
        )
        .map_err(|_| {
            VaultError::Message(
                "vault could not be decrypted with the configured key (wrong key or modified file)"
                    .to_owned(),
            )
        })
}

/// Build the AEAD instance for `key`.
fn cipher(key: &VaultKey) -> Result<XChaCha20Poly1305, VaultError> {
    XChaCha20Poly1305::new_from_slice(&key.0)
        .map_err(|_| VaultError::Message("vault key must be 32 bytes".to_owned()))
}

/// Lowercase hex for `bytes`.
fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

/// Decode hex, ignoring surrounding whitespace.
///
/// # Errors
///
/// Returns [`VaultError`] for an odd number of characters or a non-hex digit.
fn decode_hex(text: &str) -> Result<Vec<u8>, VaultError> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return Err(VaultError::Message(
            "hex payload has an odd number of characters".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?);
    }
    Ok(bytes)
}

/// Value of one hex digit.
fn hex_digit(byte: u8) -> Result<u8, VaultError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VaultError::Message(
            "hex payload contains a non-hex character".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Random key from the OS entropy source.
    ///
    /// The tests assert properties that hold for any key (the round trip, and
    /// that a different key cannot decrypt), so random material keeps literal
    /// key bytes out of cryptographic call sites — static analysis flags
    /// hard-coded cryptographic values even in tests.
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
        let parsed = match VaultKey::from_hex(&"ab".repeat(KEY_BYTES)) {
            Ok(parsed) => parsed,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(parsed.0, [0xab; KEY_BYTES]);

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
}
