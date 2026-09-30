//! TTL semantics for the persisted vault: reads hide expired mappings, locked
//! writes and `expire` purge them, counters never reset, and records written
//! before a TTL was configured are stamped instead of purged on sight.

use super::*;
use do_context_shield_plugin_api::{Vault, mint_placeholder};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Current Unix seconds (0 when the clock precedes the epoch).
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Write a vault file directly so old timestamps can be seeded without
/// waiting for a clock.
fn seed(path: &PathBuf, records: &[(&str, &str, Option<u64>)]) {
    let mappings: Vec<serde_json::Value> = records
        .iter()
        .map(|(token, original, created_at)| {
            serde_json::json!({
                "scope": "s",
                "mapping": {"kind": "email", "original": original, "token": token},
                "created_at": created_at,
            })
        })
        .collect();
    let state = serde_json::json!({
        "mappings": mappings,
        "counters": [{"scope": "s", "kind": "email", "value": 7}],
    });
    if let Err(error) = fs::write(path, state.to_string()) {
        panic!("cannot seed the vault file: {error}");
    }
}

/// Raw token set of a vault file, for asserting what a purge left behind.
fn stored_tokens(path: &PathBuf) -> Vec<String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read the vault file: {error}"),
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => panic!("vault file is not JSON: {error}"),
    };
    value
        .get("mappings")
        .and_then(serde_json::Value::as_array)
        .map(|records| {
            records
                .iter()
                .filter_map(|record| {
                    record
                        .pointer("/mapping/token")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn expired_mappings_stop_resolving_and_are_purged_on_write() {
    let path = temp_path();
    let session = scope("s");
    let old = match mint_placeholder("email", 1) {
        Ok(token) => token,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let fresh = match mint_placeholder("email", 2) {
        Ok(token) => token,
        Err(error) => panic!("unexpected error: {error}"),
    };
    seed(
        &path,
        &[
            (
                old.as_str(),
                "old@example.com",
                Some(now().saturating_sub(3_600)),
            ),
            (fresh.as_str(), "fresh@example.com", Some(now())),
        ],
    );

    let mut vault = open(&path).with_ttl(Duration::from_secs(60));
    assert_eq!(resolved(&vault, &session, &old), None, "expired must hide");
    assert!(
        resolved(&vault, &session, &fresh).is_some(),
        "a fresh mapping still resolves"
    );

    // A locked write purges the expired record; the counter keeps counting.
    let next = stored(&mut vault, &session, "email", "carol@example.com");
    assert_token(&next.token, "EMAIL", 8);
    let mut tokens = stored_tokens(&path);
    tokens.sort();
    let mut expected = vec![fresh.clone(), next.token.clone()];
    expected.sort();
    assert_eq!(tokens, expected, "only the fresh and new mappings remain");

    cleanup(&path);
}

#[test]
fn a_zero_ttl_hides_immediately_and_expire_purges_without_resetting_counters() {
    let path = temp_path();
    let session = scope("s");
    let mut vault = open(&path).with_ttl(Duration::ZERO);
    let first = stored(&mut vault, &session, "email", "alice@example.com");
    assert_token(&first.token, "EMAIL", 1);
    assert_eq!(
        resolved(&vault, &session, &first.token),
        None,
        "a zero TTL expires every stamped mapping immediately"
    );

    match vault.expire() {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    assert!(stored_tokens(&path).is_empty(), "expire purges the file");

    // The counter is not reset: an expired token is never reissued.
    let second = stored(&mut vault, &session, "email", "bob@example.com");
    assert_token(&second.token, "EMAIL", 2);
    cleanup(&path);
}

#[test]
fn undated_records_are_stamped_by_expire_instead_of_being_purged() {
    let path = temp_path();
    let session = scope("s");
    let legacy = match mint_placeholder("email", 4) {
        Ok(token) => token,
        Err(error) => panic!("unexpected error: {error}"),
    };
    seed(&path, &[(legacy.as_str(), "legacy@example.com", None)]);

    let mut vault = open(&path).with_ttl(Duration::from_secs(3600));
    assert!(
        resolved(&vault, &session, &legacy).is_some(),
        "a record without a timestamp predates the TTL and still resolves"
    );
    match vault.expire() {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    assert_eq!(
        stored_tokens(&path),
        vec![legacy.clone()],
        "stamping must not delete the mapping"
    );
    assert!(
        resolved(&vault, &session, &legacy).is_some(),
        "a stamped record keeps resolving until its TTL elapses"
    );
    cleanup(&path);
}

#[test]
fn expire_without_a_ttl_leaves_the_file_alone() {
    let path = temp_path();
    let session = scope("s");
    let mut vault = open(&path);
    let mapping = stored(&mut vault, &session, "email", "alice@example.com");
    let before = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read the vault file: {error}"),
    };
    match vault.expire() {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    let after = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read the vault file: {error}"),
    };
    assert_eq!(before, after, "no TTL means no rewrite");
    assert_eq!(
        resolved(&vault, &session, &mapping.token),
        Some(mapping.clone())
    );
    cleanup(&path);
}
