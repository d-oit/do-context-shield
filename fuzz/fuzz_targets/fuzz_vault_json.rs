#![no_main]

use do_context_shield_plugin_api::{ScopeId, Vault};
use do_context_shield_vault_json::JsonVault;
use libfuzzer_sys::fuzz_target;

/// The value the round-trip check inserts. Only the *persisted* state is
/// fuzzed, so this stays fixed.
const VALUE: &str = "round-trip@example.com";

/// The original value a token resolves to, panicking on a vault error.
fn resolve_original(vault: &JsonVault, scope: &ScopeId, token: &str) -> Option<String> {
    match vault.resolve(scope, token) {
        Ok(mapping) => mapping.map(|mapping| mapping.original),
        Err(error) => panic!("resolving a token this instance minted failed: {error}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let temp_dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => return,
    };
    let vault_path = temp_dir.path().join("fuzz_vault.json");
    if std::fs::write(&vault_path, data).is_err() {
        return;
    }

    // Malformed persisted state must come back as a typed error — never a
    // panic, and never a vault that silently invents (or destroys) data.
    let Ok(mut vault) = JsonVault::open(&vault_path) else {
        let Ok(after) = std::fs::read(&vault_path) else {
            panic!("a refused vault file was removed");
        };
        assert_eq!(
            after, data,
            "a refused vault file was rewritten instead of left alone"
        );
        return;
    };

    let scope = ScopeId("fuzz-scope".to_owned());
    let Ok(mapping) = vault.get_or_insert(&scope, "email", VALUE) else {
        return;
    };

    // The token minted in this instance resolves back to its value.
    assert_eq!(
        resolve_original(&vault, &scope, &mapping.token).as_deref(),
        Some(VALUE),
        "a token minted in this instance does not resolve to its value"
    );

    // Persistence: a second instance over the same file resolves it too.
    drop(vault);
    let Ok(mut reopened) = JsonVault::open(&vault_path) else {
        panic!("reopening the file this vault just wrote failed");
    };
    assert_eq!(
        resolve_original(&reopened, &scope, &mapping.token).as_deref(),
        Some(VALUE),
        "a persisted token does not resolve from a fresh instance"
    );

    // Deletion is scoped and immediate.
    if let Err(error) = reopened.delete_scope(&scope) {
        panic!("deleting a scope this vault just wrote failed: {error}");
    }
    assert!(
        resolve_original(&reopened, &scope, &mapping.token).is_none(),
        "a deleted mapping still resolves"
    );
});
