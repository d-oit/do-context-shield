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

#[cfg(not(windows))]
type TemporaryKeyFile = File;

#[cfg(windows)]
struct TemporaryKeyFile {
    file: File,
    // Keep the CREATE_NEW handle alive until the std file closes; it denies FILE_SHARE_DELETE.
    _creation_handle: winsafe::guard::CloseHandleGuard<winsafe::HFILE>,
}

/// Create a new random 32-byte key file without replacing an existing path.
///
/// The file contains 64 lowercase hexadecimal characters and a newline.
/// On Unix, it is created with mode `0600`. On Windows, the initial `CREATE_NEW`
/// call receives a protected DACL limited to the effective user, SYSTEM, and
/// Built-in Administrators; the file ACL is verified before any key material
/// is written. A same-directory hard link publishes the completed file
/// atomically without replacing a target.
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
    if write_and_sync_key_contents(&mut file, contents.as_bytes()).is_err() {
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

/// Open a new temporary file exclusively with restrictive platform permissions.
///
/// # Errors
///
/// Returns a fixed error if the file cannot be opened securely.
#[cfg(not(windows))]
fn open_temporary_key_file(path: &Path) -> Result<TemporaryKeyFile, VaultError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path).map_err(|_| message(CREATE_ERROR))
}

#[cfg(windows)]
/// Open a key file whose protected DACL was supplied during `CREATE_NEW`.
///
/// # Errors
///
/// Returns a fixed error if the descriptor, initial ACL, or file handle is invalid.
fn open_temporary_key_file(path: &Path) -> Result<TemporaryKeyFile, VaultError> {
    let (handle, current_sid) = create_temporary_key_file_handle(path)?;
    if verify_restrictive_windows_dacl(&handle, &current_sid).is_err() {
        drop(handle);
        return Err(cleanup_failure(path, CREATE_ERROR));
    }

    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        drop(handle);
        return Err(cleanup_failure(path, CREATE_ERROR));
    };
    Ok(TemporaryKeyFile {
        file,
        _creation_handle: handle,
    })
}

#[cfg(windows)]
/// Create a file handle with a protected DACL in the initial `CREATE_NEW` operation.
///
/// # Errors
///
/// Returns a fixed error if token lookup, descriptor setup, or file creation fails.
fn create_temporary_key_file_handle(
    path: &Path,
) -> Result<(winsafe::guard::CloseHandleGuard<winsafe::HFILE>, String), VaultError> {
    use windows_permissions::wrappers::ConvertStringSecurityDescriptorToSecurityDescriptor;
    use winsafe::{self as w, co};

    let current_sid = current_user_sid().ok_or_else(|| message(CREATE_ERROR))?;
    let sddl = format!("D:P(A;;FA;;;{current_sid})(A;;FA;;;SY)(A;;FA;;;BA)");
    let parsed_descriptor = ConvertStringSecurityDescriptorToSecurityDescriptor(&sddl)
        .map_err(|_| message(CREATE_ERROR))?;
    let dacl = parsed_descriptor
        .dacl()
        .ok_or_else(|| message(CREATE_ERROR))?;

    let mut descriptor = w::InitializeSecurityDescriptor().map_err(|_| message(CREATE_ERROR))?;
    descriptor.Dacl = std::ptr::from_ref(dacl).cast_mut().cast::<w::ACL>();
    descriptor.Control = co::SE::DACL_PRESENT | co::SE::DACL_PROTECTED;
    let mut attributes = w::SECURITY_ATTRIBUTES::default();
    attributes.set_bInheritHandle(false);
    attributes.set_lpSecurityDescriptor(Some(&mut descriptor));

    let path_str = path.to_str().ok_or_else(|| message(CREATE_ERROR))?;
    let (handle, _) = w::HFILE::CreateFile(
        path_str,
        co::GENERIC::READ | co::GENERIC::WRITE,
        Some(co::FILE_SHARE::READ | co::FILE_SHARE::WRITE),
        Some(&attributes),
        co::DISPOSITION::CREATE_NEW,
        co::FILE_ATTRIBUTE::NORMAL,
        None,
        None,
        None,
    )
    .map_err(|_| message(CREATE_ERROR))?;
    Ok((handle, current_sid))
}

#[cfg(not(windows))]
/// Write key material and sync it to storage.
///
/// # Errors
///
/// Returns an I/O error if writing or syncing fails.
fn write_and_sync_key_contents(
    file: &mut TemporaryKeyFile,
    contents: &[u8],
) -> std::io::Result<()> {
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(windows)]
/// Write key material and sync it to storage while retaining the creation handle.
///
/// # Errors
///
/// Returns an I/O error if writing or syncing fails.
fn write_and_sync_key_contents(
    file: &mut TemporaryKeyFile,
    contents: &[u8],
) -> std::io::Result<()> {
    file.file.write_all(contents)?;
    file.file.sync_all()
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
pub(super) fn current_user_sid() -> Option<String> {
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

#[cfg(windows)]
/// Verify that a newly created key-file handle has the exact protected allow-list.
///
/// # Errors
///
/// Returns a fixed error if the DACL is unreadable or differs from the required allow-list.
fn verify_restrictive_windows_dacl(
    handle: &winsafe::guard::CloseHandleGuard<winsafe::HFILE>,
    current_sid: &str,
) -> Result<(), VaultError> {
    use windows_acl::acl::{ACL, AceType};

    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

    let acl = ACL::from_file_handle(handle.ptr(), false).map_err(|_| message(CREATE_ERROR))?;
    let entries = acl.all().map_err(|_| message(CREATE_ERROR))?;
    let expected = [current_sid, "S-1-5-18", "S-1-5-32-544"];
    let mut found = [false; 3];

    if entries.len() != expected.len() {
        return Err(message(CREATE_ERROR));
    }
    for entry in entries {
        if entry.entry_type != AceType::AccessAllow
            || entry.flags != 0
            || entry.mask != FILE_ALL_ACCESS
        {
            return Err(message(CREATE_ERROR));
        }
        let Some(index) = expected
            .iter()
            .position(|sid| *sid == entry.string_sid.as_str())
        else {
            return Err(message(CREATE_ERROR));
        };
        if found[index] {
            return Err(message(CREATE_ERROR));
        }
        found[index] = true;
    }
    if found.iter().any(|was_found| !was_found) {
        return Err(message(CREATE_ERROR));
    }
    Ok(())
}

#[cfg(all(test, windows))]
/// Create a temporary key file through the initial `CREATE_NEW` helper for immediate-DACL tests.
///
/// # Errors
///
/// Returns a fixed error if the DACL is not restrictive before any later file operation.
pub(super) fn create_temporary_file_for_test(path: &Path) -> Result<(), VaultError> {
    let (handle, current_sid) = create_temporary_key_file_handle(path)?;
    if verify_restrictive_windows_dacl(&handle, &current_sid).is_err() {
        drop(handle);
        return Err(cleanup_failure(path, CREATE_ERROR));
    }
    drop(handle);
    Ok(())
}
