#![no_main]

use do_context_shield_plugin_api::{ScopeId, Vault};
use do_context_shield_vault_json::JsonVault;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let temp_dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => return,
    };
    let vault_path = temp_dir.path().join("fuzz_vault.json");

    // Write arbitrary bytes to the vault file path
    if std::fs::write(&vault_path, data).is_err() {
        return;
    }

    // Try opening the JsonVault with malformed state bytes.
    // It must return a typed VaultError or succeed, but never panic.
    if let Ok(mut vault) = JsonVault::open(&vault_path) {
        let scope = ScopeId("fuzz-scope".to_owned());
        let _ = vault.get_or_insert(&scope, "email", "test@example.com");
        let _ = vault.resolve(&scope, "__DO_PRIVATE_EMAIL_1__");
        let _ = vault.delete_scope(&scope);
    }
});
