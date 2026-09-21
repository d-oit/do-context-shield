use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn temp_path() -> PathBuf {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "do-context-shield-vault-test-{}-{id}.json",
        std::process::id()
    ))
}

fn stored(vault: &mut JsonVault, scope: &ScopeId, kind: &str, original: &str) -> Mapping {
    match vault.get_or_insert(scope, kind, original) {
        Ok(mapping) => mapping,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn resolved(vault: &JsonVault, scope: &ScopeId, token: &str) -> Option<Mapping> {
    match vault.resolve(scope, token) {
        Ok(mapping) => mapping,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn open(path: &PathBuf) -> JsonVault {
    match JsonVault::open(path) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn scope(name: &str) -> ScopeId {
    ScopeId(name.to_owned())
}

fn cleanup(path: &PathBuf) {
    fs::remove_file(path).ok();
    fs::remove_file(lock_path(path)).ok();
    fs::remove_file(path.with_extension("json.tmp")).ok();
}

#[test]
fn mappings_survive_reopen_and_share_counters() {
    let path = temp_path();
    let scope = scope("s");
    let first = match JsonVault::open(&path) {
        Ok(mut vault) => stored(&mut vault, &scope, "email", "alice@example.com"),
        Err(error) => panic!("unexpected error: {error}"),
    };
    let mut reopened = match JsonVault::open(&path) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    };
    match reopened.resolve(&scope, &first.token) {
        Ok(resolved) => assert_eq!(resolved, Some(first.clone())),
        Err(error) => panic!("unexpected error: {error}"),
    }
    let second = stored(&mut reopened, &scope, "email", "bob@example.com");
    assert_ne!(first.token, second.token);
    assert!(second.token.ends_with("_2__"));
    cleanup(&path);
}

#[test]
fn same_value_under_different_kinds_gets_distinct_tokens() {
    let path = temp_path();
    let mut vault = match JsonVault::open(&path) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let scope = scope("s");
    let email = stored(&mut vault, &scope, "email", "alice@example.com");
    let person = stored(&mut vault, &scope, "person", "alice@example.com");
    assert_ne!(email.token, person.token);
    cleanup(&path);
}

#[test]
fn delete_scope_persists_and_reloads() {
    let path = temp_path();
    let doomed = scope("doomed");
    let kept = scope("kept");
    let mut vault = open(&path);
    let gone = stored(&mut vault, &doomed, "email", "alice@example.com");
    let kept_mapping = stored(&mut vault, &kept, "email", "bob@example.com");
    match vault.delete_scope(&doomed) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }

    let mut reopened = open(&path);
    assert_eq!(resolved(&reopened, &doomed, &gone.token), None);
    assert_eq!(
        resolved(&reopened, &kept, &kept_mapping.token),
        Some(kept_mapping)
    );
    assert!(
        reopened
            .state
            .mappings
            .iter()
            .all(|record| record.scope != "doomed"),
        "deleted scope still on disk"
    );
    // The deleted scope's counter is gone, so it restarts at 1.
    let reissued = stored(&mut reopened, &doomed, "email", "carol@example.com");
    assert_eq!(reissued.token, "__DO_PRIVATE_EMAIL_1__");
    cleanup(&path);
}

#[test]
fn concurrent_writers_keep_every_mapping() {
    let path = temp_path();
    let scope = scope("s");
    let handles: Vec<_> = [open(&path), open(&path)]
        .into_iter()
        .zip(["a", "b"])
        .map(|(mut vault, tag)| {
            let scope = scope.clone();
            std::thread::spawn(move || {
                for index in 0..10 {
                    stored(
                        &mut vault,
                        &scope,
                        "email",
                        &format!("{tag}{index}@example.com"),
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic!("writer thread panicked: {payload:?}"),
        }
    }

    let reopened = open(&path);
    assert_eq!(reopened.state.mappings.len(), 20);
    let tokens: std::collections::HashSet<&str> = reopened
        .state
        .mappings
        .iter()
        .map(|record| record.mapping.token.as_str())
        .collect();
    assert_eq!(tokens.len(), 20, "tokens were reused across writers");
    cleanup(&path);
}

#[test]
fn corrupt_file_is_an_error() {
    let path = temp_path();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).ok();
        }
    }
    fs::write(&path, "{not json").ok();
    assert!(
        JsonVault::open(&path).is_err(),
        "expected corrupt file error"
    );
    cleanup(&path);
}

#[cfg(unix)]
#[test]
fn vault_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_path();
    let mut vault = match JsonVault::open(&path) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    };
    stored(&mut vault, &scope("s"), "email", "alice@example.com");
    let mode = match fs::metadata(&path) {
        Ok(metadata) => metadata.permissions().mode() & 0o777,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(mode, 0o600);
    cleanup(&path);
}

#[test]
fn externally_deleted_vault_starts_over() {
    let path = temp_path();
    let scope = scope("s");
    let mut vault = open(&path);
    let first = stored(&mut vault, &scope, "email", "alice@example.com");
    assert_eq!(first.token, "__DO_PRIVATE_EMAIL_1__");
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) => panic!("cannot remove the vault file: {error}"),
    }
    // Writes reload the file first: a vault deleted outside this process is
    // empty, so the counter restarts instead of resurrecting stale mappings.
    let second = stored(&mut vault, &scope, "email", "bob@example.com");
    assert_eq!(second.token, "__DO_PRIVATE_EMAIL_1__");
    assert_eq!(vault.state.mappings.len(), 1, "stale mappings survived");
    cleanup(&path);
}

#[test]
fn write_state_surfaces_flush_failures() {
    /// Accepts buffered bytes, fails the flush they would be written by.
    struct FullDisk;
    impl io::Write for FullDisk {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"))
        }
    }
    match write_state(FullDisk, &State::default()) {
        Ok(()) => panic!("a failed flush must not report success"),
        Err(error) => assert!(error.to_string().contains("disk full"), "{error}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn failed_write_keeps_the_existing_vault() {
    let path = temp_path();
    let scope = scope("s");
    let tmp = path.with_extension("json.tmp");
    let mut vault = open(&path);
    let first = stored(&mut vault, &scope, "email", "alice@example.com");
    // The temp file becomes a symlink to /dev/full: opening and truncating
    // succeed, but the buffered write fails with ENOSPC when it flushes.
    match std::os::unix::fs::symlink("/dev/full", &tmp) {
        Ok(()) => {}
        Err(error) => panic!("cannot create the temp symlink: {error}"),
    }
    assert!(
        vault
            .get_or_insert(&scope, "email", "bob@example.com")
            .is_err(),
        "a failed write must not report success"
    );
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) => panic!("cannot remove the temp symlink: {error}"),
    }
    // The failed write must not have replaced the healthy vault file.
    let mut reopened = open(&path);
    assert_eq!(
        resolved(&reopened, &scope, &first.token),
        Some(first.clone())
    );
    // The surviving file kept the counter, so the next write continues at 2.
    let next = stored(&mut reopened, &scope, "email", "carol@example.com");
    assert_eq!(next.token, "__DO_PRIVATE_EMAIL_2__");
    cleanup(&path);
}
