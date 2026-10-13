//! Loader for the canary HMAC key file.
//!
//! The canary key is deliberately separate from the vault key: a leaked canary
//! key must not expose vault ciphertext, and rotating one must not rotate the
//! other. The file format matches the vault key (64 hex characters) and the
//! same owner-only permission rule applies on Unix.

use std::fs;
use std::path::Path;

use do_context_shield_core::canary::MIN_KEY_BYTES;

/// Read a canary key: 64 hex characters (32 bytes), optionally newline-terminated.
///
/// # Errors
///
/// Returns an error when the file is unreadable, accessible beyond its owner
/// (Unix), or does not hold exactly `MIN_KEY_BYTES * 2` hex characters.
pub(crate) fn read_canary_key(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    check_owner_only(path)?;
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read canary key file `{}`: {error}", path.display()))?;
    let hex = text.trim_end_matches(['\r', '\n']);
    if hex.len() != MIN_KEY_BYTES * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "canary key file `{}` must hold exactly {} hex characters",
            path.display(),
            MIN_KEY_BYTES * 2
        )
        .into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|error| format!("canary key file holds invalid hex: {error}").into())
}

#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|error| format!("cannot stat canary key file `{}`: {error}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "canary key file `{}` is accessible beyond its owner (mode {mode:03o}); restrict it with `chmod 600`",
            path.display()
        )
        .into());
    }
    Ok(())
}
