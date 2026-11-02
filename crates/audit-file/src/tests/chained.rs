//! Chained-record sink tests: tampering, legacy refusal, and rotation.

use super::*;
use std::os::unix::fs::PermissionsExt;

fn sink_with(path: &Path, retention: Retention) -> FileAuditSink {
    match FileAuditSink::open_with(path, retention) {
        Ok(sink) => sink,
        Err(error) => panic!("audit sink should open: {error}"),
    }
}

fn record_all(sink: &mut FileAuditSink, sessions: &[&str]) {
    for session in sessions {
        if let Err(error) = sink.record(&event(session)) {
            panic!("audit append failed: {error}");
        }
    }
}

fn verified(path: &Path) -> VerificationReport {
    match verify_file(path) {
        Ok(report) => report,
        Err(error) => panic!("verification failed to read: {error}"),
    }
}

fn sessions_at(path: &Path) -> Vec<String> {
    read_events(path)
        .into_iter()
        .map(|event| event.session)
        .collect()
}

#[test]
fn default_retention_stays_unbounded_and_never_rotates() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("audit.jsonl");
    let mut sink = sink_with(&path, Retention::unbounded());
    record_all(&mut sink, &["one", "two", "three"]);
    assert_eq!(sessions_at(&path), ["one", "two", "three"]);
    assert_eq!(verified(&path), VerificationReport::Verified { records: 3 });
    assert!(!path.with_file_name("audit.jsonl.1").exists());
}

#[test]
fn zero_bounds_are_treated_as_unset() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("audit.jsonl");
    let mut sink = sink_with(
        &path,
        Retention {
            max_records: Some(0),
            max_bytes: Some(0),
        },
    );
    record_all(&mut sink, &["one", "two"]);
    assert_eq!(sessions_at(&path), ["one", "two"]);
    assert!(!path.with_file_name("audit.jsonl.1").exists());
}

#[test]
fn record_retention_rotates_at_the_exact_boundary() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("audit.jsonl");
    let mut sink = sink_with(
        &path,
        Retention {
            max_records: Some(2),
            max_bytes: None,
        },
    );
    record_all(&mut sink, &["one", "two", "three"]);

    let rotated = path.with_file_name("audit.jsonl.1");
    assert_eq!(sessions_at(&rotated), ["one", "two"]);
    assert_eq!(sessions_at(&path), ["three"]);
    assert_eq!(
        verified(&rotated),
        VerificationReport::Verified { records: 2 }
    );
    assert_eq!(verified(&path), VerificationReport::Verified { records: 1 });
    let mode = match fs::metadata(&path) {
        Ok(metadata) => metadata.permissions().mode() & 0o777,
        Err(error) => panic!("cannot inspect rotated audit mode: {error}"),
    };
    assert_eq!(mode & 0o077, 0, "rotated file must stay owner-only");
}

#[test]
fn byte_retention_rotates_before_exceeding_the_bound() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("audit.jsonl");
    let mut sink = sink_with(
        &path,
        Retention {
            max_records: None,
            max_bytes: Some(1),
        },
    );
    record_all(&mut sink, &["one", "two"]);

    let rotated = path.with_file_name("audit.jsonl.1");
    // The first record always fits (an empty file cannot rotate further),
    // and the second rotates into a fresh chain.
    assert_eq!(sessions_at(&rotated), ["one"]);
    assert_eq!(sessions_at(&path), ["two"]);
}

#[test]
fn a_tampered_chain_is_refused_on_open_and_left_byte_for_byte() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("audit.jsonl");
    let mut sink = sink_with(&path, Retention::unbounded());
    record_all(&mut sink, &["first", "second"]);
    let mut contents = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) => panic!("cannot read fixture: {error}"),
    };
    let needle = b"second";
    let Some(position) = contents
        .windows(needle.len())
        .position(|window| window == needle)
    else {
        panic!("fixture lost its session value");
    };
    contents[position..position + needle.len()].copy_from_slice(b"SECOND");
    if let Err(error) = fs::write(&path, &contents) {
        panic!("cannot tamper with fixture: {error}");
    }
    let before = fs::read(&path).unwrap_or_default();
    let error = match FileAuditSink::open(&path) {
        Ok(_) => panic!("a tampered chain must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("record_hash_mismatch"), "{error}");
    assert!(
        !error.contains("second") && !error.contains("SECOND"),
        "{error}"
    );
    assert_eq!(fs::read(&path).ok(), Some(before));
}

#[test]
fn a_legacy_file_is_refused_and_never_upgraded() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("legacy.jsonl");
    let mut legacy = match serde_json::to_vec(&event("legacy")) {
        Ok(line) => line,
        Err(error) => panic!("cannot serialize legacy event: {error}"),
    };
    legacy.push(b'\n');
    if let Err(error) = fs::write(&path, &legacy) {
        panic!("cannot create legacy fixture: {error}");
    }
    if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
        panic!("cannot restrict legacy fixture: {error}");
    }
    let error = match FileAuditSink::open(&path) {
        Ok(_) => panic!("appending to a legacy file must be refused"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("legacy v1"), "{error}");
    assert_eq!(fs::read(&path).ok(), Some(legacy));
    assert_eq!(verified(&path), VerificationReport::Legacy { records: 1 });
}

#[test]
fn deleted_and_reordered_records_are_detected() {
    let directory = match tempfile::tempdir() {
        Ok(directory) => directory,
        Err(error) => panic!("cannot create fixture directory: {error}"),
    };
    let path = directory.path().join("audit.jsonl");
    let mut sink = sink_with(&path, Retention::unbounded());
    record_all(&mut sink, &["one", "two", "three"]);
    let contents = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) => panic!("cannot read fixture: {error}"),
    };
    let lines: Vec<&[u8]> = contents.split(|byte| *byte == b'\n').collect();
    // `lines` ends with an empty segment after the final newline.
    let mut reordered = Vec::new();
    reordered.extend_from_slice(lines[0]);
    reordered.push(b'\n');
    reordered.extend_from_slice(lines[2]);
    reordered.push(b'\n');
    reordered.extend_from_slice(lines[1]);
    reordered.push(b'\n');
    if let Err(error) = fs::write(&path, &reordered) {
        panic!("cannot reorder fixture: {error}");
    }
    let report = verified(&path);
    assert!(!report.is_ok());
    assert_eq!(report.record_index(), 2);
    assert_eq!(report.category(), Some("sequence_gap"));
}
