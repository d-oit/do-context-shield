//! Chain-format tests: verification categories never carry record content.

use super::*;
use do_context_shield_plugin_api::{AuditOperation, AuditOutcome, ScopeId};

fn event(session: &str) -> AuditEvent {
    AuditEvent::new(
        AuditOperation::Forget,
        &ScopeId(session.to_owned()),
        AuditOutcome::Ok,
    )
}

/// Serialize `events` as one valid chained file.
fn chained(events: &[AuditEvent]) -> Vec<u8> {
    let mut previous = GENESIS_PREVIOUS.to_owned();
    let mut contents = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let sequence = u64::try_from(index).unwrap_or(0) + 1;
        let Ok(bytes) = event_bytes(event) else {
            panic!("test event failed to serialize")
        };
        let record_hash = compute_record_hash(&previous, sequence, &bytes);
        let envelope = Envelope {
            v: FORMAT_VERSION,
            sequence,
            previous_hash: previous.clone(),
            record_hash: record_hash.clone(),
            event: event.clone(),
        };
        let Ok(mut line) = envelope.encode_line() else {
            panic!("test envelope failed to encode")
        };
        previous = record_hash;
        contents.append(&mut line);
    }
    contents
}

fn lines(contents: &[u8]) -> Vec<Vec<u8>> {
    let mut segments: Vec<Vec<u8>> = contents
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::to_vec)
        .collect();
    if segments.last().is_some_and(Vec::is_empty) {
        segments.pop();
    }
    segments
}

fn join(lines: &[Vec<u8>]) -> Vec<u8> {
    let mut contents = Vec::new();
    for line in lines {
        contents.extend_from_slice(line);
        contents.push(b'\n');
    }
    contents
}

#[test]
fn verifies_a_continuous_chain() {
    let contents = chained(&[event("first"), event("second"), event("third")]);
    assert_eq!(
        verify(&contents),
        VerificationReport::Verified { records: 3 }
    );
    assert_eq!(scan(&contents).map(|tail| tail.records), Ok(3));
}

#[test]
fn detects_a_modified_record() {
    let events = [event("first"), event("second"), event("third")];
    let mut contents = chained(&events);
    // Change the second record's event without rehashing it.
    let needle = b"second";
    let Some(position) = contents
        .windows(needle.len())
        .position(|window| window == needle)
    else {
        panic!("fixture lost its session value");
    };
    contents[position..position + needle.len()].copy_from_slice(b"SECOND");
    assert_eq!(
        verify(&contents),
        VerificationReport::Failure {
            record_index: 2,
            category: VerifyCategory::RecordHashMismatch,
        }
    );
}

#[test]
fn detects_a_deleted_or_reordered_record() {
    let contents = chained(&[event("first"), event("second"), event("third")]);
    let parts = lines(&contents);
    assert_eq!(parts.len(), 3);

    // Delete the middle record: the third record's sequence no longer matches.
    let deleted = join(&[parts[0].clone(), parts[2].clone()]);
    assert_eq!(
        verify(&deleted),
        VerificationReport::Failure {
            record_index: 2,
            category: VerifyCategory::SequenceGap,
        }
    );

    // Reorder records 2 and 3.
    let reordered = join(&[parts[0].clone(), parts[2].clone(), parts[1].clone()]);
    assert_eq!(
        verify(&reordered),
        VerificationReport::Failure {
            record_index: 2,
            category: VerifyCategory::SequenceGap,
        }
    );

    // An edited `previous_hash` is caught by the record's own hash.
    let first = String::from_utf8_lossy(&parts[0]).into_owned();
    let tampered_first = first.replacen(
        GENESIS_PREVIOUS,
        "1111111111111111111111111111111111111111111111111111111111111111",
        1,
    );
    let tampered = join(&[
        tampered_first.into_bytes(),
        parts[1].clone(),
        parts[2].clone(),
    ]);
    assert_eq!(
        verify(&tampered),
        VerificationReport::Failure {
            record_index: 1,
            category: VerifyCategory::PreviousHashMismatch,
        }
    );
}

#[test]
fn detects_truncation_and_malformed_lines() {
    let contents = chained(&[event("first"), event("second")]);
    let truncated = &contents[..contents.len() - 1];
    assert_eq!(
        verify(truncated),
        VerificationReport::Failure {
            record_index: 0,
            category: VerifyCategory::Truncated,
        }
    );

    let mut parts = lines(&contents);
    parts.push(b"not a record".to_vec());
    assert_eq!(
        verify(&join(&parts)),
        VerificationReport::Failure {
            record_index: 3,
            category: VerifyCategory::Malformed,
        }
    );
}

#[test]
fn recognizes_empty_legacy_and_unknown_versions() {
    assert_eq!(verify(b""), VerificationReport::Empty);

    let legacy = match serde_json::to_vec(&event("legacy")) {
        Ok(line) => line,
        Err(error) => panic!("cannot serialize test event: {error}"),
    };
    let mut legacy_file = legacy;
    legacy_file.push(b'\n');
    assert_eq!(
        verify(&legacy_file),
        VerificationReport::Legacy { records: 1 }
    );

    let unknown = b"{\"v\":9,\"sequence\":1}\n";
    assert_eq!(
        verify(unknown),
        VerificationReport::UnsupportedVersion { record_index: 1 }
    );
}

#[test]
fn append_point_extends_a_valid_tail_and_rejects_a_modified_one() {
    let contents = chained(&[event("first"), event("second")]);
    let parts = lines(&contents);
    let tail = match append_point(&parts[1]) {
        Ok(tail) => tail,
        Err(report) => panic!("valid tail rejected: {report}"),
    };
    assert_eq!(tail.records, 2);
    let last: Envelope = match serde_json::from_slice(&parts[1]) {
        Ok(envelope) => envelope,
        Err(error) => panic!("tail envelope is not valid JSON: {error}"),
    };
    assert_eq!(tail.previous_hash, last.record_hash);

    let mut modified = parts[1].clone();
    let needle = b"second";
    let Some(position) = modified
        .windows(needle.len())
        .position(|window| window == needle)
    else {
        panic!("fixture lost its session value");
    };
    modified[position..position + needle.len()].copy_from_slice(b"SECOND");
    assert!(matches!(
        append_point(&modified),
        Err(VerificationReport::Failure {
            category: VerifyCategory::RecordHashMismatch,
            ..
        })
    ));
}

#[test]
fn reports_never_carry_record_values() {
    let canary = "CANARY-SESSION-DO-NOT-PRINT";
    let contents = chained(&[event("first"), event(canary)]);
    let mut modified = contents.clone();
    let needle = canary.as_bytes();
    let Some(position) = modified
        .windows(needle.len())
        .position(|window| window == needle)
    else {
        panic!("fixture lost its canary");
    };
    modified[position..position + needle.len()].copy_from_slice(b"CANARY-SESSION-DO-NOT-PRINX");
    let report = verify(&modified);
    let rendered = report.to_string();
    assert!(!report.is_ok());
    assert!(
        !rendered.contains(canary),
        "report leaked the value: {rendered}"
    );
    assert!(!format!("{report:?}").contains(canary));
}
