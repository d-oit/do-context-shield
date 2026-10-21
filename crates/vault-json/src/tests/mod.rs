use super::*;
use do_context_shield_plugin_api::Vault;
use std::sync::atomic::{AtomicU64, Ordering};

mod batch;
mod encrypted;
mod ttl;

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
    // Windows virus scanners briefly deny access to brand-new files in the
    // temp dir (os error 5), which flaked parallel suite runs about one run
    // in four. Retry a transient open failure with backoff; a persistent
    // failure still panics below, and production `JsonVault::open` keeps
    // failing closed on the first error. Linux CI never hits this path.
    let mut attempts = 0;
    loop {
        match JsonVault::open(path) {
            Ok(vault) => return vault,
            Err(error) => {
                assert!(attempts < 50, "unexpected error: {error}");
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}
#[test]
fn a_missing_parent_directory_is_created_for_the_vault_and_its_lock() {
    let path = temp_path().join("nested").join("vault.json");
    let mut vault = open(&path);
    let mapping = stored(&mut vault, &scope("s1"), "email", "alice@example.com");
    drop(vault);
    let fresh = open(&path);
    assert_eq!(
        resolved(&fresh, &scope("s1"), &mapping.token).map(|mapping| mapping.original),
        Some("alice@example.com".to_owned())
    );
}

#[test]
fn persist_locked_creates_missing_parents_without_a_lock() {
    // `persist_locked` must create its own parents: every public caller
    // happens to hold the exclusive lock (which also creates them), so a
    // test through `get_or_insert` cannot tell whether this copy runs. A
    // mutant deleting the `!` here would only surface on the direct path.
    let path = temp_path().join("direct").join("vault.json");
    let vault = JsonVault {
        path: path.clone(),
        state: State::default(),
        format: Format::Plaintext,
        ttl: None,
    };
    match vault.persist_locked() {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    assert!(path.exists(), "persist must create {}", path.display());
}

#[cfg(unix)]
#[test]
fn opening_an_existing_vault_tightens_it_to_owner_private() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_path();
    // A file created outside this process with lax permissions: opening it
    // must tighten it to owner-only, not leave it readable by others.
    match std::fs::write(&path, b"{\"mappings\":[],\"counters\":[]}") {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    drop(open(&path));
    let mode = match std::fs::metadata(&path) {
        Ok(metadata) => metadata.permissions().mode(),
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(
        mode & 0o777,
        0o600,
        "vault must be owner-private after open"
    );
}

fn scope(name: &str) -> ScopeId {
    ScopeId(name.to_owned())
}

fn cleanup(path: &PathBuf) {
    fs::remove_file(path).ok();
    fs::remove_file(lock_path(path)).ok();
    fs::remove_file(path.with_extension("json.tmp")).ok();
}

/// Assert `token` is a minted placeholder for `kind`/`counter`.
fn assert_token(token: &str, kind: &str, counter: u64) {
    let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
    assert!(
        token.starts_with(&prefix),
        "`{token}` does not start with `{prefix}`"
    );
}

#[test]
fn mappings_survive_reopen_and_share_counters() {
    let path = temp_path();
    let scope = scope("s");
    let mut vault = open(&path);
    let first = stored(&mut vault, &scope, "email", "alice@example.com");
    let mut reopened = open(&path);
    match reopened.resolve(&scope, &first.token) {
        Ok(resolved) => assert_eq!(resolved, Some(first.clone())),
        Err(error) => panic!("unexpected error: {error}"),
    }
    let second = stored(&mut reopened, &scope, "email", "bob@example.com");
    assert_ne!(first.token, second.token);
    assert_token(&second.token, "EMAIL", 2);
    cleanup(&path);
}

#[test]
fn counters_are_independent_per_scope_and_kind() {
    let path = temp_path();
    let mut vault = open(&path);
    let first_scope = scope("counter-a");
    let second_scope = scope("counter-b");
    let first = stored(&mut vault, &first_scope, "email", "one@example.com");
    assert_token(&first.token, "EMAIL", 1);
    let other_scope = stored(&mut vault, &second_scope, "email", "two@example.com");
    assert_token(&other_scope.token, "EMAIL", 1);
    let other_kind = stored(&mut vault, &first_scope, "phone", "+15550000");
    assert_token(&other_kind.token, "PHONE", 1);
    cleanup(&path);
}

#[test]
fn same_value_under_different_kinds_gets_distinct_tokens() {
    let path = temp_path();
    let mut vault = open(&path);
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
    assert_token(&reissued.token, "EMAIL", 1);
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
    assert_token(&first.token, "EMAIL", 1);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) => panic!("cannot remove the vault file: {error}"),
    }
    // Reads also honor external deletion instead of serving the cached mapping.
    assert_eq!(resolved(&vault, &scope, &first.token), None);
    // Writes reload the file first: a vault deleted outside this process is
    // empty, so the counter restarts instead of resurrecting stale mappings.
    let second = stored(&mut vault, &scope, "email", "bob@example.com");
    assert_token(&second.token, "EMAIL", 1);
    assert_ne!(
        first.token, second.token,
        "fresh entropy for the new mapping"
    );
    assert_eq!(vault.state.mappings.len(), 1, "stale mappings survived");
    cleanup(&path);
}

#[test]
fn legacy_tokens_are_not_resolved_and_are_rotated_on_reinsert() {
    let path = temp_path();
    let legacy = serde_json::json!({
        "mappings": [{
            "scope": "s",
            "mapping": {
                "kind": "email",
                "original": "alice@example.com",
                "token": "__DO_PRIVATE_EMAIL_1__"
            }
        }],
        "counters": [{"scope": "s", "kind": "email", "value": 1}]
    });
    let bytes = match serde_json::to_vec(&legacy) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot serialize legacy vault: {error}"),
    };
    if let Err(error) = fs::write(&path, bytes) {
        panic!("cannot write legacy vault: {error}");
    }

    let mut vault = open(&path);
    let legacy_token = "__DO_PRIVATE_EMAIL_1__";
    assert_eq!(resolved(&vault, &scope("s"), legacy_token), None);

    let replacement = stored(&mut vault, &scope("s"), "email", "alice@example.com");
    assert_token(&replacement.token, "EMAIL", 2);
    assert_ne!(replacement.token, legacy_token);
    assert_eq!(resolved(&vault, &scope("s"), legacy_token), None);
    assert_eq!(
        resolved(&vault, &scope("s"), &replacement.token),
        Some(replacement)
    );
    cleanup(&path);
}

#[test]
fn an_existing_instance_observes_external_scope_deletion() {
    let path = temp_path();
    let mut first = open(&path);
    let mapping = stored(&mut first, &scope("s"), "email", "alice@example.com");

    let mut second = open(&path);
    match second.delete_scope(&scope("s")) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }

    assert_eq!(resolved(&first, &scope("s"), &mapping.token), None);
    cleanup(&path);
}

#[test]
fn fabricated_tokens_do_not_resolve() {
    let path = temp_path();
    let mut vault = open(&path);
    let session = scope("s");
    let mapping = stored(&mut vault, &session, "email", "alice@example.com");
    // A guessed counter without the minted entropy does not resolve, so a
    // model cannot enumerate session values it was never shown.
    assert_eq!(resolved(&vault, &session, "__DO_PRIVATE_EMAIL_1__"), None);
    assert_eq!(
        resolved(&vault, &session, "__DO_PRIVATE_EMAIL_1_0000000000000000__"),
        None
    );
    assert_eq!(
        resolved(&vault, &session, &mapping.token),
        Some(mapping.clone())
    );
    // Scopes never share a token for the same value and kind.
    let second = stored(&mut vault, &scope("other"), "email", "alice@example.com");
    assert_ne!(mapping.token, second.token);
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
    match write_bytes(FullDisk, b"state") {
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
    assert_token(&next.token, "EMAIL", 2);
    cleanup(&path);
}
