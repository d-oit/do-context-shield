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
    /// Unix the file must not be readable or writable by group or others; on
    /// Windows its DACL must restrict allow ACEs to the current user, SYSTEM,
    /// and Built-in Administrators. Other platforms skip the permission check.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the file cannot be read, violates its
    /// platform's permission policy, or does not hold exactly 32 hex-encoded
    /// bytes. The message names only the operation and failure class: never the
    /// resolved path, the OS error text, or any key material.
    pub fn from_file(path: &Path) -> Result<Self, VaultError> {
        #[cfg(any(unix, windows))]
        check_key_file_permissions(path)?;
        let text = fs::read_to_string(path).map_err(|error| key_file_read_error(&error))?;
        Self::from_hex(&text)
    }

    /// Parse exactly 64 hex characters into a key.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the text is not exactly 32 hex-encoded bytes.
    /// The message states the required format only: never the parsed text or
    /// any decoded bytes.
    pub fn from_hex(text: &str) -> Result<Self, VaultError> {
        let bytes = decode_hex(text)?;
        if bytes.len() != KEY_BYTES {
            return Err(VaultError::Message(
                "invalid vault key format: the key must be exactly 32 bytes, encoded as 64 hex characters (`openssl rand -hex 32` writes one)"
                    .to_owned(),
            ));
        }
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}

/// Fixed operation label for a key-file read failure.
///
/// The message names the failure class and the flag that carries the path —
/// never the resolved path, the OS error text, or the file contents, which
/// would disclose user names, project names, or mounted-secret locations to
/// anyone reading a log line or an error report.
fn key_file_read_error(error: &std::io::Error) -> VaultError {
    let text = if error.kind() == std::io::ErrorKind::NotFound {
        "vault key file does not exist; check the path given to `--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`"
    } else {
        "cannot read the vault key file (inaccessible, a directory, or not valid UTF-8)"
    };
    VaultError::Message(text.to_owned())
}

/// Reject a key file that other users on the machine could read.
///
/// The message names the operation, the failure class, and the fix — never
/// the path, the OS error text, or the mode bits, which would describe the
/// file system layout to anyone reading a log line.
#[cfg(unix)]
pub(super) fn check_key_file_permissions(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|error| key_file_read_error(&error))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(VaultError::Message(
            "vault key file permissions must be owner-only; restrict it with `chmod 600` (the path is passed as `--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`)"
                .to_owned(),
        ));
    }
    Ok(())
}
#[cfg(windows)]
fn sid_bytes_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let rev = bytes[0];
    let sub_count = bytes[1] as usize;
    if bytes.len() < 8 + sub_count * 4 {
        return None;
    }
    let mut auth_bytes = [0u8; 8];
    auth_bytes[2..8].copy_from_slice(&bytes[2..8]);
    let auth = u64::from_be_bytes(auth_bytes);
    let mut subs = Vec::with_capacity(sub_count);
    for i in 0..sub_count {
        let start = 8 + i * 4;
        let sub_bytes: [u8; 4] = bytes[start..start + 4].try_into().ok()?;
        subs.push(u32::from_le_bytes(sub_bytes));
    }
    let mut sid_string = format!("S-{rev}-{auth}");
    for sub in subs {
        use std::fmt::Write as _;
        let _ = write!(sid_string, "-{sub}");
    }
    Some(sid_string)
}

#[cfg(windows)]
pub(super) fn check_key_file_permissions(path: &Path) -> Result<(), VaultError> {
    fs::metadata(path).map_err(|error| key_file_read_error(&error))?;
    let path_str = path.to_str().ok_or_else(|| {
        VaultError::Message("cannot read the vault key file (not valid UTF-8)".to_owned())
    })?;
    let acl = windows_acl::acl::ACL::from_file_path(path_str, false).map_err(|_| {
        key_file_read_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })?;
    let entries = acl.all().map_err(|_| {
        key_file_read_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })?;
    if entries.is_empty() {
        return Err(VaultError::Message(
            "vault key file permissions must be owner-only; in Windows, restrict ACLs to the current user (the path is passed as `--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`)"
                .to_owned(),
        ));
    }

    let current_sid = windows_acl::helper::current_user()
        .and_then(|user| windows_acl::helper::name_to_sid(&user, None).ok())
        .and_then(|bytes| sid_bytes_to_string(&bytes));

    let mut has_owner_allow = false;

    for entry in entries {
        match entry.entry_type {
            windows_acl::acl::AceType::AccessAllow => {
                let sid = &entry.string_sid;
                let is_current_user = current_sid.as_deref().is_some_and(|cur| cur == sid);
                let is_system = sid == "S-1-5-18";
                let is_admin = sid == "S-1-5-32-544";
                if is_current_user || is_system || is_admin {
                    if is_current_user || (current_sid.is_none() && (is_system || is_admin)) {
                        has_owner_allow = true;
                    }
                } else {
                    return Err(VaultError::Message(
                        "vault key file permissions must be owner-only; in Windows, restrict ACLs to the current user (the path is passed as `--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`)"
                            .to_owned(),
                    ));
                }
            }
            windows_acl::acl::AceType::AccessDeny
            | windows_acl::acl::AceType::AccessDenyCallback
            | windows_acl::acl::AceType::AccessDenyObject
            | windows_acl::acl::AceType::AccessDenyCallbackObject
            | windows_acl::acl::AceType::SystemAudit
            | windows_acl::acl::AceType::SystemAuditCallback
            | windows_acl::acl::AceType::SystemAuditObject
            | windows_acl::acl::AceType::SystemAuditCallbackObject
            | windows_acl::acl::AceType::SystemMandatoryLabel
            | windows_acl::acl::AceType::SystemResourceAttribute => {
                // Deny entries and SACL metadata do not grant access.
            }
            _ => {
                // Fail closed on callback allows, object allows, and unknown ACE types.
                return Err(VaultError::Message(
                    "vault key file permissions must be owner-only; in Windows, restrict ACLs to the current user (the path is passed as `--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`)"
                        .to_owned(),
                ));
            }
        }
    }

    if !has_owner_allow {
        return Err(VaultError::Message(
            "vault key file permissions must be owner-only; in Windows, restrict ACLs to the current user (the path is passed as `--vault-key-file` or `DO_CONTEXT_SHIELD_VAULT_KEY_FILE`)"
                .to_owned(),
        ));
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
    getrandom::fill(&mut nonce)
        .map_err(|_| VaultError::Message("cannot obtain entropy for the vault nonce".to_owned()))?;
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
    serde_json::to_vec(&envelope)
        .map_err(|_| VaultError::Message("cannot serialize the vault envelope".to_owned()))
}

/// Decrypt an envelope file value into the serialized vault state.
///
/// # Errors
///
/// Returns [`VaultError`] when the envelope is malformed, uses an unsupported
/// version or cipher, or fails authentication with `key` (wrong key or a
/// modified file). The messages are fixed operation labels: no envelope
/// content, ciphertext, key bytes, or path is echoed back.
pub(super) fn decrypt(value: serde_json::Value, key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    let envelope: Envelope = serde_json::from_value(value).map_err(|_| {
        VaultError::Message(
            "vault envelope is malformed (expected `version`, `cipher`, `nonce`, and `payload` fields)"
                .to_owned(),
        )
    })?;
    if envelope.version != VERSION {
        return Err(VaultError::Message(format!(
            "unsupported vault format version (this build reads version {VERSION})"
        )));
    }
    if envelope.cipher != CIPHER {
        return Err(VaultError::Message(format!(
            "unsupported vault cipher (this build reads `{CIPHER}`)"
        )));
    }
    let nonce = decode_hex(&envelope.nonce)?;
    if nonce.len() != NONCE_BYTES {
        return Err(VaultError::Message(format!(
            "vault nonce must be {NONCE_BYTES} bytes"
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
pub(super) fn encode_hex(bytes: &[u8]) -> String {
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
/// The messages are fixed labels: the parsed text and the offending character
/// are never echoed, so a key or ciphertext byte cannot leak through an error.
pub(super) fn decode_hex(text: &str) -> Result<Vec<u8>, VaultError> {
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
