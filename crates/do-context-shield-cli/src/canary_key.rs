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
    #[cfg(any(unix, windows))]
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
fn check_owner_only(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            "canary key file does not exist; check the path given to `--canary-key-file`".to_owned()
        } else {
            "cannot inspect the canary key file (inaccessible); check `--canary-key-file`"
                .to_owned()
        }
    })?;
    let path_str = path
        .to_str()
        .ok_or("cannot read the canary key file (not valid UTF-8)")?;
    let acl = windows_acl::acl::ACL::from_file_path(path_str, false).map_err(
        |_| "cannot inspect the canary key file (inaccessible); check `--canary-key-file`",
    )?;
    let entries = acl.all().map_err(
        |_| "cannot inspect the canary key file (inaccessible); check `--canary-key-file`",
    )?;
    if entries.is_empty() {
        return Err(
            "canary key file is accessible beyond its owner; restrict it to the current user in Windows".into(),
        );
    }

    let current_sid = windows_acl::helper::current_user()
        .and_then(|user| windows_acl::helper::name_to_sid(&user, None).ok())
        .and_then(|bytes| sid_bytes_to_string(&bytes));

    let mut has_owner_allow = false;

    for entry in entries {
        if entry.entry_type == windows_acl::acl::AceType::AccessAllow {
            let sid = &entry.string_sid;
            let is_current_user = current_sid.as_deref().is_some_and(|cur| cur == sid);
            let is_system = sid == "S-1-5-18";
            let is_admin = sid == "S-1-5-32-544";
            if is_current_user || is_system || is_admin {
                if is_current_user || (current_sid.is_none() && (is_system || is_admin)) {
                    has_owner_allow = true;
                }
            } else {
                return Err(
                    "canary key file is accessible beyond its owner; restrict it with `chmod 600`"
                        .into(),
                );
            }
        }
    }

    if !has_owner_allow {
        return Err(
            "canary key file is accessible beyond its owner; restrict it to the current user in Windows".into(),
        );
    }
    Ok(())
}
