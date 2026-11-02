//! Loader for the canary HMAC key file.
//!
//! The canary key is deliberately separate from the vault key: a leaked canary
//! key must not expose vault ciphertext, and rotating one must not rotate the
//! other. The file format matches the vault key (64 hex characters) and the
//! same owner-only permission rule applies on Unix.
//!
//! Diagnostics name the operation and a safe failure class only. The resolved
//! path can disclose a username, a project name, or a mounted-secret location,
//! and an OS error string can echo it again, so neither is ever formatted into
//! an error; remediation points at the flag instead.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use do_context_shield_core::canary::MIN_KEY_BYTES;

/// Read a canary key: 64 hex characters (32 bytes), optionally newline-terminated.
///
/// # Errors
///
/// Returns an error when the file is unreadable, accessible beyond its owner
/// (Unix), or does not hold exactly `MIN_KEY_BYTES * 2` hex characters. The
/// message names the failure class, never the path, key text, or OS error text.
pub(crate) fn read_canary_key(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    check_owner_only(path)?;
    let text = fs::read_to_string(path).map_err(|error| key_file_read_error(&error))?;
    let hex = text.trim_end_matches(['\r', '\n']);
    if hex.len() != MIN_KEY_BYTES * 2 {
        return Err(format!(
            "canary key file must hold exactly {} hex characters; check `--canary-key-file`",
            MIN_KEY_BYTES * 2
        )
        .into());
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("canary key file holds non-hex characters; check `--canary-key-file`".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "canary key file holds an invalid hex encoding".into())
}

/// A path-free, OS-text-free read failure label: the two cases an operator can
/// act on differently are "nothing there" and "not a readable secret file".
fn key_file_read_error(error: &std::io::Error) -> Box<dyn std::error::Error> {
    if error.kind() == ErrorKind::NotFound {
        "canary key file does not exist; check the path given to `--canary-key-file`".into()
    } else {
        "cannot read the canary key file (inaccessible, a directory, or not valid UTF-8); check `--canary-key-file`".into()
    }
}

#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            "canary key file does not exist; check the path given to `--canary-key-file`".to_owned()
        } else {
            "cannot inspect the canary key file (inaccessible); check `--canary-key-file`"
                .to_owned()
        }
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(
            "canary key file is accessible beyond its owner; restrict it with `chmod 600`".into(),
        );
    }
    Ok(())
}
