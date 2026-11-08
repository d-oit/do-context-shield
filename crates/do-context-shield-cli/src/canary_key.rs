//! Loader for the canary HMAC key file.
//!
//! The canary key is deliberately separate from the vault key: a leaked canary
//! key must not expose vault ciphertext, and rotating one must not rotate the
//! other. The file format matches the vault key (64 hex characters) and the
//! same platform-specific permission policy applies.
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
/// Returns an error when the file is unreadable, violates its Unix mode or
/// Windows DACL policy, or does not hold exactly `MIN_KEY_BYTES * 2` hex
/// characters. The message names the failure class, never the path, key text,
/// or OS error text.
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

    let current_sid = current_user_sid()
        .ok_or("cannot inspect the canary key file (inaccessible); check `--canary-key-file`")?;

    let mut has_owner_allow = false;

    for entry in entries {
        match entry.entry_type {
            windows_acl::acl::AceType::AccessAllow => {
                let sid = &entry.string_sid;
                let is_current_user = current_sid.as_str() == sid.as_str();
                let is_system = sid == "S-1-5-18";
                let is_admin = sid == "S-1-5-32-544";
                if is_current_user || is_system || is_admin {
                    if is_current_user {
                        has_owner_allow = true;
                    }
                } else {
                    return Err(
                        "canary key file is accessible beyond its owner; restrict it to the current user in Windows"
                            .into(),
                    );
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
                return Err(
                    "canary key file is accessible beyond its owner; restrict it to the current user in Windows"
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

#[cfg(windows)]
fn current_user_sid() -> Option<String> {
    use winsafe::{self as w, co};

    let token = w::HACCESSTOKEN::GetCurrentThreadEffectiveToken();
    let info = token
        .GetTokenInformation(co::TOKEN_INFORMATION_CLASS::User)
        .ok()?;
    let w::TokenInfo::User(user) = info else {
        return None;
    };
    user.User.Sid().map(|sid| sid.to_string())
}
#[cfg(all(test, windows))]
#[test]
fn effective_token_sid_matches_windows_identity() {
    let actual =
        current_user_sid().unwrap_or_else(|| panic!("cannot read effective Windows token SID"));
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output();
    let expected = match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => panic!(
            "PowerShell could not read the current Windows SID: {}",
            output.status
        ),
        Err(error) => panic!("cannot execute PowerShell to read the current Windows SID: {error}"),
    };
    assert!(
        actual == expected,
        "effective token SID must match WindowsIdentity.GetCurrent().User.Value"
    );
}
