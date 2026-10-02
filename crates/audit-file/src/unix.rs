use do_context_shield_plugin_api::{AuditError, AuditEvent};
use fs2::FileExt as LockExt;
use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};
use rustix::process::geteuid;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt as UnixFileExt, MetadataExt};
use std::path::{Path, PathBuf};

const OPEN_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::APPEND)
    .union(OFlags::CREATE)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const CREATE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
}

struct FileLock<'a> {
    file: &'a File,
}

impl<'a> FileLock<'a> {
    /// Lock the opened audit file exclusively.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the advisory lock cannot be acquired.
    fn exclusive(file: &'a File) -> Result<Self, AuditError> {
        LockExt::lock_exclusive(file).map_err(|error| io_error("audit lock", &error))?;
        Ok(Self { file })
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        // Closing the descriptor releases the lock even if this best-effort
        // explicit unlock fails.
        let _ = LockExt::unlock(self.file);
    }
}

/// Resolve the startup path, create if needed, and validate its current log.
///
/// # Errors
///
/// Returns [`AuditError`] when the path, parent, file metadata, lock, path
/// identity, or existing JSONL boundary is invalid or inaccessible.
pub(super) fn open(path: &Path) -> Result<(PathBuf, FileIdentity), AuditError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(AuditError::Message(
            "audit destination must name a file".to_owned(),
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error("audit working directory", &error))?
            .join(path)
    };
    let parent = absolute.parent().ok_or_else(|| {
        AuditError::Message("audit destination must have an existing parent".to_owned())
    })?;
    let parent_metadata = fs::metadata(parent).map_err(|error| io_error("audit parent", &error))?;
    if !parent_metadata.is_dir() {
        return Err(AuditError::Message(
            "audit destination parent must be a directory".to_owned(),
        ));
    }

    let file = open_file(&absolute)?;
    let _lock = FileLock::exclusive(&file)?;
    let identity = validate_descriptor(&file)?;
    validate_path_identity(&absolute, identity)?;
    validate_jsonl_boundary(&file)?;
    Ok((absolute, identity))
}

/// Reopen, revalidate, and append one complete serialized event.
///
/// # Errors
///
/// Returns [`AuditError`] when the destination was replaced, has insecure
/// metadata or JSONL boundaries, cannot be locked or appended, or fails flush
/// or data synchronization.
pub(super) fn record(
    path: &Path,
    expected_identity: FileIdentity,
    event: &AuditEvent,
) -> Result<(), AuditError> {
    let file = open_file(path)?;
    let _lock = FileLock::exclusive(&file)?;
    let identity = validate_descriptor(&file)?;
    if identity != expected_identity {
        return Err(AuditError::Message(
            "audit destination changed since sink opened".to_owned(),
        ));
    }
    validate_path_identity(path, identity)?;
    validate_jsonl_boundary(&file)?;

    let mut record = serde_json::to_vec(event)
        .map_err(|_| AuditError::Message("audit event serialization failed".to_owned()))?;
    record.push(b'\n');
    let mut writer = &file;
    writer
        .write_all(&record)
        .map_err(|error| io_error("audit append", &error))?;
    writer
        .flush()
        .map_err(|error| io_error("audit flush", &error))?;
    file.sync_data()
        .map_err(|error| io_error("audit sync", &error))?;
    Ok(())
}

fn open_file(path: &Path) -> Result<File, AuditError> {
    let descriptor: OwnedFd = rustix_fs::open(path, OPEN_FLAGS, CREATE_MODE)
        .map_err(|error| rustix_io_error("audit destination open", error))?;
    let file = File::from(descriptor);
    validate_descriptor(&file)?;
    Ok(file)
}

fn validate_descriptor(file: &File) -> Result<FileIdentity, AuditError> {
    let metadata = rustix_fs::fstat(file)
        .map_err(|error| rustix_io_error("audit descriptor metadata", error))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_nlink != 1
    {
        return Err(AuditError::Message(
            "audit destination must be a single-link regular file".to_owned(),
        ));
    }
    if metadata.st_uid != geteuid().as_raw() {
        return Err(AuditError::Message(
            "audit destination must be owned by the effective user".to_owned(),
        ));
    }
    if metadata.st_mode & 0o077 != 0 {
        return Err(AuditError::Message(
            "audit destination permissions must be owner-only (chmod 600)".to_owned(),
        ));
    }
    Ok(FileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

fn validate_path_identity(path: &Path, identity: FileIdentity) -> Result<(), AuditError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("audit destination path validation", &error))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(AuditError::Message(
            "audit destination must be a single-link regular file".to_owned(),
        ));
    }
    if metadata.dev() != identity.device || metadata.ino() != identity.inode {
        return Err(AuditError::Message(
            "audit destination changed while opening".to_owned(),
        ));
    }
    Ok(())
}

/// Validate the first record and the final newline without scanning history.
///
/// # Errors
///
/// Returns [`AuditError`] when the file cannot be read, has an unterminated
/// final record, or its first line is not an [`AuditEvent`].
fn validate_jsonl_boundary(file: &File) -> Result<(), AuditError> {
    let metadata = rustix_fs::fstat(file)
        .map_err(|error| rustix_io_error("audit boundary metadata", error))?;
    if metadata.st_size == 0 {
        return Ok(());
    }

    let file_length = u64::try_from(metadata.st_size).map_err(|_| {
        AuditError::Message("audit destination has a negative file size".to_owned())
    })?;
    let mut final_byte = [0_u8; 1];
    let final_read = file
        .read_at(&mut final_byte, file_length - 1)
        .map_err(|error| io_error("audit final-byte read", &error))?;
    if final_read != 1 || final_byte[0] != b'\n' {
        return Err(AuditError::Message(
            "audit destination has an unterminated JSONL tail".to_owned(),
        ));
    }

    let mut first_line = Vec::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 4096];
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|error| io_error("audit first-record read", &error))?;
        if read == 0 {
            return Err(AuditError::Message(
                "audit destination has a malformed JSONL boundary".to_owned(),
            ));
        }
        let chunk = &buffer[..read];
        if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
            first_line.extend_from_slice(&chunk[..=newline]);
            break;
        }
        first_line.extend_from_slice(chunk);
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            AuditError::Message("audit destination has a malformed JSONL boundary".to_owned())
        })?;
    }
    if first_line.pop() != Some(b'\n') {
        return Err(AuditError::Message(
            "audit destination has a malformed JSONL boundary".to_owned(),
        ));
    }
    serde_json::from_slice::<AuditEvent>(&first_line).map_err(|_| {
        AuditError::Message("audit destination has a malformed JSONL boundary".to_owned())
    })?;
    Ok(())
}

fn io_error(operation: &'static str, error: &io::Error) -> AuditError {
    AuditError::Message(format!("{operation} failed ({:?})", error.kind()))
}

fn rustix_io_error(operation: &'static str, error: rustix::io::Errno) -> AuditError {
    let error: io::Error = error.into();
    io_error(operation, &error)
}
