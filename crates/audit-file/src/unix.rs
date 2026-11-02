use do_context_shield_plugin_api::{AuditError, AuditEvent};
use fs2::FileExt as LockExt;
use rustix::fs::{self as rustix_fs, FileType, Mode, OFlags};
use rustix::process::geteuid;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt as UnixFileExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::Retention;
use crate::chain::{self, ChainTail, GENESIS_PREVIOUS};

const OPEN_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::APPEND)
    .union(OFlags::CREATE)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const CREATE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
/// Bound on how much of the file is read to recover the append point.
const MAX_TAIL_BYTES: u64 = 256 * 1024;

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

/// Resolve the startup path, create if needed, and verify the whole chain.
///
/// # Errors
///
/// Returns [`AuditError`] when the path, parent, file metadata, lock, path
/// identity, or existing chain is invalid or inaccessible, and refuses a
/// legacy (version-1) file so an append can never mix formats.
pub(super) fn open(path: &Path) -> Result<(PathBuf, FileIdentity, ChainTail), AuditError> {
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
    let size = file_len(&file)?;
    let contents = read_contents(&file, size)?;
    let tail = match chain::scan(&contents) {
        Ok(tail) if tail.records == 0 && !contents.is_empty() => {
            return Err(AuditError::Message(
                "audit destination is a legacy v1 file; start a new destination file and preserve this one"
                    .to_owned(),
            ));
        }
        Ok(tail) => tail,
        Err(report) => {
            return Err(verification_error(&report));
        }
    };
    Ok((absolute, identity, tail))
}

/// Reopen, revalidate, and append one chained record.
///
/// The chain is extended from the file's own tail under an exclusive lock, so
/// independent sinks (and processes) cannot fork it. With a configured
/// [`Retention`], a record that would exceed the bound rotates the current
/// file to `<name>.1` and starts a fresh chain instead.
///
/// # Errors
///
/// Returns [`AuditError`] when the destination was replaced, has insecure
/// metadata, cannot be locked, its tail is malformed, retention rotation
/// fails, or the append fails to flush or sync.
pub(super) fn record(
    path: &Path,
    expected_identity: FileIdentity,
    retention: Retention,
    event: &AuditEvent,
) -> Result<FileIdentity, AuditError> {
    let file = open_file(path)?;
    let _lock = FileLock::exclusive(&file)?;
    let identity = validate_descriptor(&file)?;
    if identity != expected_identity {
        return Err(AuditError::Message(
            "audit destination changed since sink opened".to_owned(),
        ));
    }
    validate_path_identity(path, identity)?;

    let size = file_len(&file)?;
    let tail = tail_of(&file, size)?;
    let next_sequence = tail
        .records
        .checked_add(1)
        .ok_or_else(|| AuditError::Message("audit chain sequence is exhausted".to_owned()))?;
    let line = envelope_line(event, next_sequence, &tail.previous_hash)?;

    if size > 0 && should_rotate(retention, tail.records, size, line.len()) {
        rotate(path)?;
        let (fresh, fresh_identity) = create_fresh(path)?;
        let _fresh_lock = FileLock::exclusive(&fresh)?;
        let fresh_line = envelope_line(event, 1, GENESIS_PREVIOUS)?;
        write_line(&fresh, &fresh_line)?;
        return Ok(fresh_identity);
    }

    write_line(&file, &line)?;
    Ok(identity)
}

/// Whether appending `next_len` bytes would exceed the configured bound.
///
/// Both bounds are opt-in; `None` keeps the historical unbounded behavior.
fn should_rotate(retention: Retention, records: u64, size: u64, next_len: usize) -> bool {
    let next_len = u64::try_from(next_len).unwrap_or(u64::MAX);
    let too_many = retention
        .max_records
        .is_some_and(|max| records.saturating_add(1) > max);
    let too_big = retention
        .max_bytes
        .is_some_and(|max| size.saturating_add(next_len) > max);
    too_many || too_big
}

/// Build one envelope line, hashing the exact event bytes the verifier sees.
fn envelope_line(
    event: &AuditEvent,
    sequence: u64,
    previous_hash: &str,
) -> Result<Vec<u8>, AuditError> {
    let bytes = chain::event_bytes(event)
        .map_err(|()| AuditError::Message("audit event serialization failed".to_owned()))?;
    let record_hash = chain::compute_record_hash(previous_hash, sequence, &bytes);
    let envelope = chain::Envelope {
        v: chain::FORMAT_VERSION,
        sequence,
        previous_hash: previous_hash.to_owned(),
        record_hash,
        event: event.clone(),
    };
    envelope
        .encode_line()
        .map_err(|()| AuditError::Message("audit event serialization failed".to_owned()))
}

/// Append one complete line and durably persist it.
fn write_line(file: &File, line: &[u8]) -> Result<(), AuditError> {
    let mut writer = file;
    writer
        .write_all(line)
        .map_err(|error| io_error("audit append", &error))?;
    writer
        .flush()
        .map_err(|error| io_error("audit flush", &error))?;
    file.sync_data()
        .map_err(|error| io_error("audit sync", &error))
}

/// Rename the current log to `<name>.1`, replacing a previous rotation.
///
/// The old file is preserved rather than deleted; each file is an independent
/// chain, and verification is per file.
fn rotate(path: &Path) -> Result<(), AuditError> {
    let Some(name) = path.file_name() else {
        return Err(AuditError::Message(
            "audit destination must name a file".to_owned(),
        ));
    };
    let mut rotated_name = name.to_os_string();
    rotated_name.push(".1");
    let rotated = path.with_file_name(rotated_name);
    fs::rename(path, &rotated).map_err(|error| io_error("audit rotation", &error))
}

/// Create the post-rotation log with owner-only permissions, failing if the
/// path reappeared.
fn create_fresh(path: &Path) -> Result<(File, FileIdentity), AuditError> {
    let flags = OFlags::WRONLY
        .union(OFlags::CREATE)
        .union(OFlags::EXCL)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    let descriptor: OwnedFd = rustix_fs::open(path, flags, CREATE_MODE)
        .map_err(|error| rustix_io_error("audit rotation create", error))?;
    let file = File::from(descriptor);
    let identity = validate_descriptor(&file)?;
    validate_path_identity(path, identity)?;
    Ok((file, identity))
}

/// Recover the append point from the last record, bounded to one tail window.
fn tail_of(file: &File, size: u64) -> Result<ChainTail, AuditError> {
    if size == 0 {
        return Ok(ChainTail {
            records: 0,
            previous_hash: GENESIS_PREVIOUS.to_owned(),
        });
    }
    let line = read_last_line(file, size)?;
    chain::append_point(&line).map_err(|report| verification_error(&report))
}

/// Read the final newline-terminated record, without scanning the whole log.
fn read_last_line(file: &File, size: u64) -> Result<Vec<u8>, AuditError> {
    let mut final_byte = [0_u8; 1];
    let read = file
        .read_at(&mut final_byte, size - 1)
        .map_err(|error| io_error("audit final-byte read", &error))?;
    if read != 1 || final_byte[0] != b'\n' {
        return Err(AuditError::Message(
            "audit destination has an unterminated JSONL tail".to_owned(),
        ));
    }
    let body_end = size - 1;
    if body_end == 0 {
        return Ok(Vec::new());
    }
    let region_start = body_end.saturating_sub(MAX_TAIL_BYTES);
    let region_len = usize::try_from(body_end - region_start)
        .map_err(|_| AuditError::Message("audit tail is too large to read".to_owned()))?;
    let mut region = vec![0_u8; region_len];
    read_exact_at(file, &mut region, region_start)?;
    let line_start = match region.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => index + 1,
        None if region_start == 0 => 0,
        None => {
            return Err(AuditError::Message(
                "audit tail record is too large to verify".to_owned(),
            ));
        }
    };
    Ok(region[line_start..].to_vec())
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

fn file_len(file: &File) -> Result<u64, AuditError> {
    let metadata = rustix_fs::fstat(file)
        .map_err(|error| rustix_io_error("audit boundary metadata", error))?;
    u64::try_from(metadata.st_size)
        .map_err(|_| AuditError::Message("audit destination has a negative size".to_owned()))
}

/// Read the whole file for chain verification at open.
fn read_contents(file: &File, size: u64) -> Result<Vec<u8>, AuditError> {
    let len = usize::try_from(size)
        .map_err(|_| AuditError::Message("audit destination is too large to verify".to_owned()))?;
    let mut contents = vec![0_u8; len];
    read_exact_at(file, &mut contents, 0)?;
    Ok(contents)
}

fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> Result<(), AuditError> {
    let mut read = 0_usize;
    while read < buffer.len() {
        let count = file
            .read_at(
                &mut buffer[read..],
                offset + u64::try_from(read).unwrap_or(u64::MAX),
            )
            .map_err(|error| io_error("audit read", &error))?;
        if count == 0 {
            return Err(AuditError::Message(
                "audit destination shrank while reading".to_owned(),
            ));
        }
        read += count;
    }
    Ok(())
}

/// A verification failure as a scrubbed sink error: report fields only.
fn verification_error(report: &crate::VerificationReport) -> AuditError {
    AuditError::Message(format!(
        "audit destination failed chain verification ({report})"
    ))
}

fn io_error(operation: &'static str, error: &io::Error) -> AuditError {
    AuditError::Message(format!("{operation} failed ({:?})", error.kind()))
}

fn rustix_io_error(operation: &'static str, error: rustix::io::Errno) -> AuditError {
    let error: io::Error = error.into();
    io_error(operation, &error)
}
