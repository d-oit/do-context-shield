//! Batched vault access: one authoritative snapshot per call for both
//! resolution (`restore`) and insertion (the pseudonymizing transformer).

use super::*;
use do_context_shield_plugin_api::Vault;

#[test]
fn resolve_many_reads_one_snapshot_and_keeps_results_aligned() {
    let path = temp_path();
    let session = scope("s");
    let mut vault = open(&path);
    let first = stored(&mut vault, &session, "email", "alice@example.com");
    let second = stored(&mut vault, &session, "email", "bob@example.com");
    let tokens = [
        second.token.as_str(),
        "__DO_PRIVATE_EMAIL_9_0000000000000000__",
        first.token.as_str(),
    ];
    let batch = match vault.resolve_many(&session, &tokens) {
        Ok(batch) => batch,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(batch.len(), tokens.len());
    assert_eq!(batch[0], Some(second.clone()));
    assert_eq!(batch[1], None);
    assert_eq!(batch[2], Some(first.clone()));
    // Another scope never resolves these tokens.
    match vault.resolve_many(&scope("other"), &tokens) {
        Ok(batch) => assert_eq!(batch, vec![None, None, None]),
        Err(error) => panic!("unexpected error: {error}"),
    }
    cleanup(&path);
}

#[test]
fn resolve_many_observes_a_cross_process_deletion() {
    let path = temp_path();
    let session = scope("s");
    let mut vault = open(&path);
    let mapping = stored(&mut vault, &session, "email", "alice@example.com");
    let tokens = [mapping.token.as_str()];
    match vault.resolve_many(&session, &tokens) {
        Ok(batch) => assert_eq!(batch, vec![Some(mapping.clone())]),
        Err(error) => panic!("unexpected error: {error}"),
    }

    // A second instance (another process) revokes the scope; the next batch
    // call must read the file again instead of reusing the earlier snapshot.
    let mut other = open(&path);
    match other.delete_scope(&session) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    match vault.resolve_many(&session, &tokens) {
        Ok(batch) => assert_eq!(batch, vec![None]),
        Err(error) => panic!("unexpected error: {error}"),
    }
    cleanup(&path);
}

#[test]
fn get_or_insert_many_persists_once_and_shares_counters() {
    let path = temp_path();
    let session = scope("s");
    let mut vault = open(&path);
    let items = [
        ("email", "alice@example.com"),
        ("email", "bob@example.com"),
        ("email", "alice@example.com"),
    ];
    let batch = match vault.get_or_insert_many(&session, &items) {
        Ok(batch) => batch,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(batch.len(), 3);
    assert_token(&batch[0].token, "EMAIL", 1);
    assert_token(&batch[1].token, "EMAIL", 2);
    assert_eq!(
        batch[2].token, batch[0].token,
        "a value repeated within one call resolves to one mapping"
    );

    // Another process sees the whole batch, and counters continue from it.
    let mut other = open(&path);
    assert_eq!(
        resolved(&other, &session, &batch[1].token),
        Some(batch[1].clone())
    );
    let next = stored(&mut other, &session, "email", "carol@example.com");
    assert_token(&next.token, "EMAIL", 3);
    cleanup(&path);
}

#[test]
fn get_or_insert_many_failure_leaves_the_file_unchanged() {
    let path = temp_path();
    let session = scope("s");
    let mut vault = open(&path);
    let first = stored(&mut vault, &session, "email", "alice@example.com");
    let before = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read the vault file: {error}"),
    };

    // An invalid kind fails the whole batch before anything is persisted.
    let items = [("email", "bob@example.com"), ("bad__kind", "x")];
    match vault.get_or_insert_many(&session, &items) {
        Ok(_) => panic!("expected an error for the invalid kind"),
        Err(error) => assert!(matches!(error, VaultError::Message(_)), "{error}"),
    }
    let after = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read the vault file: {error}"),
    };
    assert_eq!(before, after, "a failed batch must not rewrite the file");

    // The next call reloads from disk, so the counter continues after `first`.
    let next = stored(&mut vault, &session, "email", "carol@example.com");
    assert_token(&next.token, "EMAIL", 2);
    assert_eq!(
        resolved(&vault, &session, &first.token),
        Some(first.clone())
    );
    cleanup(&path);
}
