use super::*;
use do_context_shield_plugin_api::{AuditOperation, AuditOutcome, ScopeId};
use std::fs;

fn event(session: &str) -> AuditEvent {
    AuditEvent::new(
        AuditOperation::Forget,
        &ScopeId(session.to_owned()),
        AuditOutcome::Ok,
    )
}

fn read_events(path: &Path) -> Vec<AuditEvent> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) => panic!("cannot read audit fixture ({:?})", error.kind()),
    };
    contents
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| match serde_json::from_slice(line) {
            Ok(event) => event,
            Err(error) => panic!("cannot decode audit fixture ({:?})", error.classify()),
        })
        .collect()
}

#[cfg(unix)]
mod unix_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const FIFO_CHILD: &str = "DO_CONTEXT_SHIELD_AUDIT_FIFO_CHILD";

    #[test]
    fn creates_owner_private_file_and_appends_across_instances() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let path = directory.path().join("audit.jsonl");
        let mut first = match FileAuditSink::open(&path) {
            Ok(sink) => sink,
            Err(error) => panic!("private audit file should open: {error}"),
        };
        let mode = match fs::metadata(&path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777,
            Err(error) => panic!("cannot inspect audit mode: {error}"),
        };
        assert_eq!(mode & 0o077, 0);
        assert_eq!(mode & 0o600, 0o600);
        assert!(first.record(&event("first")).is_ok());

        let mut second = match FileAuditSink::open(&path) {
            Ok(sink) => sink,
            Err(error) => panic!("second audit sink should open: {error}"),
        };
        assert!(second.record(&event("second")).is_ok());
        let events = read_events(&path);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].session, "first");
        assert_eq!(events[1].session, "second");
    }

    #[test]
    fn rejects_insecure_permissions_without_chmod_or_content_change() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let path = directory.path().join("insecure.jsonl");
        let bytes = b"operator data\n";
        if let Err(error) = fs::write(&path, bytes) {
            panic!("cannot create permission fixture: {error}");
        }
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o644)) {
            panic!("cannot set permission fixture: {error}");
        }

        let error = match FileAuditSink::open(&path) {
            Ok(_) => panic!("group-readable audit file must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("chmod 600"));
        assert_eq!(fs::read(&path).ok().as_deref(), Some(bytes.as_slice()));
        assert_eq!(
            fs::metadata(&path)
                .map(|m| m.permissions().mode() & 0o777)
                .ok(),
            Some(0o644)
        );
    }

    #[test]
    fn rejects_symlink_hardlink_directory_and_missing_parent() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let target = directory.path().join("target.jsonl");
        let protected = b"unchanged\n";
        if let Err(error) = fs::write(&target, protected) {
            panic!("cannot create target fixture: {error}");
        }
        if let Err(error) = fs::set_permissions(&target, fs::Permissions::from_mode(0o600)) {
            panic!("cannot restrict target fixture: {error}");
        }

        let link = directory.path().join("symbolic.jsonl");
        if let Err(error) = symlink(&target, &link) {
            panic!("cannot create symbolic-link fixture: {error}");
        }
        assert!(FileAuditSink::open(&link).is_err());
        assert_eq!(
            fs::read(&target).ok().as_deref(),
            Some(protected.as_slice())
        );

        let hard = directory.path().join("hard.jsonl");
        if let Err(error) = fs::hard_link(&target, &hard) {
            panic!("cannot create hard-link fixture: {error}");
        }
        assert!(FileAuditSink::open(&hard).is_err());
        assert_eq!(
            fs::read(&target).ok().as_deref(),
            Some(protected.as_slice())
        );

        assert!(FileAuditSink::open(directory.path()).is_err());
        let missing_parent = directory.path().join("missing/child/audit.jsonl");
        assert!(FileAuditSink::open(&missing_parent).is_err());
        assert!(!directory.path().join("missing").exists());
    }

    #[test]
    fn rejects_fifo_without_blocking_the_test_process() {
        if let Some(path) = std::env::var_os(FIFO_CHILD) {
            assert!(FileAuditSink::open(Path::new(&path)).is_err());
            return;
        }

        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let path = directory.path().join("audit.fifo");
        let status = Command::new("mkfifo")
            .arg("-m")
            .arg("0600")
            .arg(&path)
            .status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => panic!("cannot create FIFO fixture: mkfifo exited with {status}"),
            Err(error) => panic!("cannot spawn mkfifo command: {error}"),
        }
        let executable = match std::env::current_exe() {
            Ok(executable) => executable,
            Err(error) => panic!("cannot locate test process: {error}"),
        };
        let mut child = match Command::new(executable)
            .arg("--exact")
            .arg("tests::unix_tests::rejects_fifo_without_blocking_the_test_process")
            .env(FIFO_CHILD, &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => panic!("cannot start bounded FIFO fixture: {error}"),
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "FIFO child failed: {status}");
                    break;
                }
                Ok(None) if started.elapsed() < Duration::from_secs(2) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("FIFO open exceeded its two-second bound");
                }
                Err(error) => panic!("cannot poll FIFO child: {error}"),
            }
        }
    }

    #[test]
    fn rejects_wrong_format_and_unterminated_tail_without_rewriting() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let path = directory.path().join("malformed.jsonl");
        if let Err(error) = fs::write(&path, b"not an audit record\n") {
            panic!("cannot create malformed fixture: {error}");
        }
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            panic!("cannot restrict malformed fixture: {error}");
        }
        let before = fs::read(&path).unwrap_or_default();
        assert!(FileAuditSink::open(&path).is_err());
        assert_eq!(fs::read(&path).ok(), Some(before));

        let valid_unterminated = directory.path().join("unterminated.jsonl");
        let line = match serde_json::to_vec(&event("fixture")) {
            Ok(line) => line,
            Err(error) => panic!("cannot serialize test event: {error}"),
        };
        if let Err(error) = fs::write(&valid_unterminated, &line) {
            panic!("cannot create unterminated fixture: {error}");
        }
        if let Err(error) =
            fs::set_permissions(&valid_unterminated, fs::Permissions::from_mode(0o600))
        {
            panic!("cannot restrict unterminated fixture: {error}");
        }
        assert!(FileAuditSink::open(&valid_unterminated).is_err());
        assert_eq!(fs::read(&valid_unterminated).ok(), Some(line));
    }

    #[test]
    fn observes_permission_and_inode_replacement_after_open() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let path = directory.path().join("audit.jsonl");
        let mut sink = match FileAuditSink::open(&path) {
            Ok(sink) => sink,
            Err(error) => panic!("audit sink should open: {error}"),
        };
        assert!(sink.record(&event("original")).is_ok());
        let before_chmod = fs::read(&path).unwrap_or_default();
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o644)) {
            panic!("cannot change audit mode: {error}");
        }
        assert!(sink.record(&event("after-chmod")).is_err());
        assert_eq!(fs::read(&path).ok(), Some(before_chmod));
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            panic!("cannot restore audit mode: {error}");
        }

        let archived = directory.path().join("archived.jsonl");
        if let Err(error) = fs::rename(&path, &archived) {
            panic!("cannot archive audit fixture: {error}");
        }
        if let Err(error) = fs::write(&path, b"") {
            panic!("cannot replace audit fixture: {error}");
        }
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            panic!("cannot restrict replacement fixture: {error}");
        }
        assert!(sink.record(&event("replacement")).is_err());
        assert!(
            read_events(&archived)
                .iter()
                .any(|item| item.session == "original")
        );
        assert_eq!(fs::read(&path).ok(), Some(Vec::new()));

        if let Err(error) = fs::remove_file(&path) {
            panic!("cannot remove replacement fixture: {error}");
        }
        if let Err(error) = fs::rename(&archived, &path) {
            panic!("cannot restore audit fixture: {error}");
        }
        assert!(sink.record(&event("recovered")).is_ok());
        assert_eq!(read_events(&path).len(), 2);
    }

    #[test]
    fn concurrent_independent_sinks_write_complete_unique_records() {
        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create fixture directory: {error}"),
        };
        let path = directory.path().join("concurrent.jsonl");
        if let Err(error) = FileAuditSink::open(&path) {
            panic!("audit sink should create the shared file: {error}");
        }
        let writers = 4;
        let per_writer = 8;
        let mut handles = Vec::new();
        for writer in 0..writers {
            let path = path.clone();
            handles.push(thread::spawn(move || {
                let mut sink = FileAuditSink::open(&path)?;
                for sequence in 0..per_writer {
                    let session = format!("writer-{writer}-{sequence}");
                    sink.record(&event(&session))?;
                }
                Ok::<(), AuditError>(())
            }));
        }
        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => panic!("concurrent audit writer failed: {error}"),
                Err(panic_payload) => panic!("concurrent audit writer panicked: {panic_payload:?}"),
            }
        }

        let actual = read_events(&path);
        let expected_count = writers * per_writer;
        assert_eq!(actual.len(), expected_count);
        let sessions: BTreeSet<_> = actual.iter().map(|item| item.session.as_str()).collect();
        assert_eq!(sessions.len(), expected_count);
        for writer in 0..writers {
            for sequence in 0..per_writer {
                let expected = format!("writer-{writer}-{sequence}");
                assert!(sessions.contains(expected.as_str()));
            }
        }
    }
}

#[cfg(not(unix))]
#[test]
fn opt_in_sink_reports_unsupported_filesystem_guarantees() {
    let error = match FileAuditSink::open(Path::new("audit.jsonl")) {
        Ok(_) => panic!("non-Unix audit sink must be unavailable"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AuditError::Message(message)
            if message == "file audit logging requires Unix filesystem guarantees"
    ));
}
