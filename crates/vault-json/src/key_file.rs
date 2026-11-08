//! Secure creation of key files shared by the vault and canary commands.

use crate::encrypted::{KEY_BYTES, encode_hex};
use do_context_shield_plugin_api::VaultError;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const CREATE_ERROR: &str = "cannot create a key file with restrictive permissions";
const GENERATE_ERROR: &str = "cannot generate key file material";
const PUBLISH_ERROR: &str = "cannot publish key file atomically; destination may exist or same-directory hard links may be unavailable";
const CLEANUP_ERROR: &str =
    "cannot clean up a private temporary key file; check the destination directory before retrying";

/// Create a new random 32-byte key file without replacing an existing path.
///
/// The file contains 64 lowercase hexadecimal characters and a newline. On
/// Unix, it is created with mode `0600`. On Windows, its DACL is replaced and
/// protected before key material is written; allow ACEs are limited to the
/// current user, SYSTEM, and Built-in Administrators. A same-directory hard
/// link publishes the completed file atomically without replacing a target.
///
/// # Errors
///
/// Returns a fixed, non-sensitive [`VaultError`] if randomness, permission
/// setup, writing, cleanup, or atomic publication fails. The destination is
/// never overwritten.
pub fn create_key_file(path: &Path) -> Result<(), VaultError> {
    if path.file_name().is_none() {
        return Err(message(CREATE_ERROR));
    }

    let mut key = [0_u8; KEY_BYTES];
    getrandom::fill(&mut key).map_err(|_| message(GENERATE_ERROR))?;
    let mut contents = encode_hex(&key);
    contents.push('\n');

    let temporary_path = temporary_key_path(path)?;
    let mut file = open_temporary_key_file(&temporary_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .is_err()
        {
            drop(file);
            return Err(cleanup_failure(&temporary_path, CREATE_ERROR));
        }
    }
    #[cfg(windows)]
    if set_restrictive_windows_dacl(&file).is_err() {
        drop(file);
        return Err(cleanup_failure(&temporary_path, CREATE_ERROR));
    }

    if file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        return Err(cleanup_failure(&temporary_path, CREATE_ERROR));
    }
    drop(file);

    // The same-directory hard link publishes the fully written, already
    // restricted file without replacing an existing destination.
    if fs::hard_link(&temporary_path, path).is_err() {
        return Err(cleanup_failure(&temporary_path, PUBLISH_ERROR));
    }
    if !published_contents_match(path, contents.as_bytes()) {
        return Err(cleanup_failure(&temporary_path, PUBLISH_ERROR));
    }

    if !remove_temporary_file(&temporary_path) {
        return Err(message(CLEANUP_ERROR));
    }
    Ok(())
}

/// Build a random same-directory temporary path for atomic publication.
///
/// # Errors
///
/// Returns a fixed error if the temporary-name randomness is unavailable.
fn temporary_key_path(path: &Path) -> Result<PathBuf, VaultError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut suffix = [0_u8; 16];
    getrandom::fill(&mut suffix).map_err(|_| message(GENERATE_ERROR))?;
    Ok(parent.join(format!(
        ".do-context-shield-{}.key.tmp",
        encode_hex(&suffix)
    )))
}

/// Open a new temporary file with restrictive platform defaults.
///
/// # Errors
///
/// Returns a fixed error if the file cannot be opened exclusively.
fn open_temporary_key_file(path: &Path) -> Result<File, VaultError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        options
            .share_mode(0)
            .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC);
    }

    options.open(path).map_err(|_| message(CREATE_ERROR))
}

/// Remove a temporary path, treating an already-absent file as cleaned up.
fn remove_temporary_file(path: &Path) -> bool {
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}
/// Verify the published file contents using a fixed-size stack buffer.
fn published_contents_match(path: &Path, expected: &[u8]) -> bool {
    if expected.len() != KEY_BYTES * 2 + 1 {
        return false;
    }
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if metadata.len() != expected.len() as u64 {
        return false;
    }
    let mut actual = [0_u8; KEY_BYTES * 2 + 1];
    file.read_exact(&mut actual).is_ok() && actual.as_slice() == expected
}

/// Prefer the original fixed error unless protected temporary material remains.
fn cleanup_failure(path: &Path, original: &'static str) -> VaultError {
    if remove_temporary_file(path) {
        message(original)
    } else {
        message(CLEANUP_ERROR)
    }
}

fn message(text: &str) -> VaultError {
    VaultError::Message(text.to_owned())
}

#[cfg(windows)]
/// Replace inherited access entries with the required protected allow-list.
///
/// # Errors
///
/// Returns a fixed error if the handle ACL cannot be read, replaced, or
/// verified. No key bytes are written before this succeeds.
fn set_restrictive_windows_dacl(file: &File) -> Result<(), VaultError> {
    use std::os::windows::io::AsRawHandle;
    use windows_acl::acl::{ACL, AceType};
    use windows_acl::helper::{sid_to_string, string_to_sid};

    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

    let mut acl =
        ACL::from_file_handle(file.as_raw_handle(), false).map_err(|_| message(CREATE_ERROR))?;
    for entry in acl.all().map_err(|_| message(CREATE_ERROR))? {
        if entry.string_sid.is_empty() {
            return Err(message(CREATE_ERROR));
        }
        let sid = string_to_sid(&entry.string_sid).map_err(|_| message(CREATE_ERROR))?;
        acl.remove_entry(sid.as_ptr().cast_mut().cast(), Some(entry.entry_type), None)
            .map_err(|_| message(CREATE_ERROR))?;
    }
    if !acl.all().map_err(|_| message(CREATE_ERROR))?.is_empty() {
        return Err(message(CREATE_ERROR));
    }

    let username = windows_acl::helper::current_user().ok_or_else(|| message(CREATE_ERROR))?;
    let user_sid =
        windows_acl::helper::name_to_sid(&username, None).map_err(|_| message(CREATE_ERROR))?;
    let current_sid =
        sid_to_string(user_sid.as_ptr().cast_mut().cast()).map_err(|_| message(CREATE_ERROR))?;
    let system_sid = string_to_sid("S-1-5-18").map_err(|_| message(CREATE_ERROR))?;
    let admin_sid = string_to_sid("S-1-5-32-544").map_err(|_| message(CREATE_ERROR))?;

    for sid in [&user_sid, &system_sid, &admin_sid] {
        match acl.allow(sid.as_ptr().cast_mut().cast(), false, FILE_ALL_ACCESS) {
            Ok(true) => {}
            Ok(false) | Err(_) => return Err(message(CREATE_ERROR)),
        }
    }

    // windows-acl applies every DACL mutation with
    // PROTECTED_DACL_SECURITY_INFORMATION, preventing inherited ACEs.
    let entries = acl.all().map_err(|_| message(CREATE_ERROR))?;
    let expected = [current_sid.as_str(), "S-1-5-18", "S-1-5-32-544"];
    if entries.len() != expected.len()
        || entries.iter().any(|entry| {
            entry.entry_type != AceType::AccessAllow
                || entry.flags != 0
                || entry.mask != FILE_ALL_ACCESS
                || !expected.contains(&entry.string_sid.as_str())
        })
    {
        return Err(message(CREATE_ERROR));
    }
    Ok(())
}
