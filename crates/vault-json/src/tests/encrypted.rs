//! Vault-level tests for the encrypted format and the migration path.

use super::*;
use do_context_shield_plugin_api::Vault;

fn key(seed: u8) -> VaultKey {
    VaultKey::new([seed; 32])
}

fn open_encrypted(path: &PathBuf, seed: u8) -> JsonVault {
    match JsonVault::open_encrypted(path, key(seed)) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    }
}

fn file_text(path: &PathBuf) -> String {
    match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("cannot read {}: {error}", path.display()),
    }
}

#[test]
fn encrypted_vault_round_trips_and_hides_values() {
    let path = temp_path();
    let scope = scope("s");
    let mapping = {
        let mut vault = open_encrypted(&path, 1);
        stored(&mut vault, &scope, "email", "alice@example.com")
    };

    // The file is an envelope, not vault state: no original value is readable.
    let text = file_text(&path);
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("\"cipher\""), "{text}");

    let reopened = open_encrypted(&path, 1);
    assert_eq!(resolved(&reopened, &scope, &mapping.token), Some(mapping));
    cleanup(&path);
}

#[test]
fn a_wrong_key_is_rejected_on_open() {
    let path = temp_path();
    let mut vault = open_encrypted(&path, 1);
    stored(&mut vault, &scope("s"), "email", "alice@example.com");

    let error = match JsonVault::open_encrypted(&path, key(2)) {
        Ok(_) => panic!("a wrong key must not open the vault"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("wrong key"), "{error}");
    cleanup(&path);
}

#[test]
fn format_mismatches_fail_closed_in_both_directions() {
    let path = temp_path();
    let scope = scope("s");
    let mapping = {
        let mut vault = open(&path);
        stored(&mut vault, &scope, "email", "alice@example.com")
    };

    // A key pointed at a plaintext vault demands an explicit migration.
    let error = match JsonVault::open_encrypted(&path, key(1)) {
        Ok(_) => panic!("a plaintext vault must not open with a key"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("not encrypted"), "{error}");

    // Migration preserves the mappings and flips the format.
    match JsonVault::encrypt_in_place(&path, key(1)) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    let text = file_text(&path);
    assert!(!text.contains("alice@example.com"), "{text}");
    let encrypted = open_encrypted(&path, 1);
    assert_eq!(
        resolved(&encrypted, &scope, &mapping.token),
        Some(mapping.clone())
    );

    // Without a key the encrypted file is rejected, not misread.
    let error = match JsonVault::open(&path) {
        Ok(_) => panic!("an encrypted vault must not open without a key"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("is encrypted"), "{error}");
    cleanup(&path);
}

#[test]
fn a_stale_plaintext_handle_cannot_overwrite_an_encrypted_vault() {
    let path = temp_path();
    let mut plaintext = open(&path);
    stored(&mut plaintext, &scope("s"), "email", "alice@example.com");
    match JsonVault::encrypt_in_place(&path, key(1)) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }

    // The old handle still thinks the file is plaintext: its next insert must
    // fail closed instead of rewriting the encrypted state.
    let error = match plaintext.get_or_insert(&scope("s"), "email", "bob@example.com") {
        Ok(mapping) => panic!("expected a fail-closed error, got {}", mapping.token),
        Err(error) => error,
    };
    assert!(error.to_string().contains("is encrypted"), "{error}");
    cleanup(&path);
}

#[test]
fn migration_rejects_missing_and_already_encrypted_files() {
    let missing = temp_path();
    let error = match JsonVault::encrypt_in_place(&missing, key(1)) {
        Ok(()) => panic!("expected a missing-file error"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("does not exist"), "{error}");

    let path = temp_path();
    let mut vault = open_encrypted(&path, 1);
    stored(&mut vault, &scope("s"), "email", "alice@example.com");
    let error = match JsonVault::encrypt_in_place(&path, key(1)) {
        Ok(()) => panic!("expected an already-encrypted error"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("already encrypted"), "{error}");
    cleanup(&path);
}

#[test]
fn open_with_key_file_selects_the_format() {
    let vault_path = temp_path();
    let key_path = temp_path().with_extension("key");
    if let Err(error) = fs::write(&key_path, "cd".repeat(32)) {
        panic!("cannot write {}: {error}", key_path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)) {
            panic!("cannot restrict {}: {error}", key_path.display());
        }
    }

    // No key file: plaintext, as if the flag were absent.
    let mut plaintext = match JsonVault::open_with_key_file(&vault_path, None) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    };
    stored(&mut plaintext, &scope("s"), "email", "alice@example.com");

    // With a key file the same path is read as an encrypted envelope, so the
    // plaintext state above is rejected instead of being misread.
    let error = match JsonVault::open_with_key_file(&vault_path, Some(&key_path)) {
        Ok(_) => panic!("a plaintext vault must not open with a key file"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("not encrypted"), "{error}");

    cleanup(&key_path);
    cleanup(&vault_path);
}

#[test]
fn key_files_are_read_and_permission_checked() {
    // Hex with a trailing newline, as `openssl rand -hex 32` writes it.
    let path = temp_path().with_extension("key");
    let hex = "ab".repeat(32);
    if let Err(error) = fs::write(&path, format!("{hex}\n")) {
        panic!("cannot write {}: {error}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            panic!("cannot restrict {}: {error}", path.display());
        }
    }
    let key = match VaultKey::from_file(&path) {
        Ok(key) => key,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let vault_path = temp_path();
    let mut vault = match JsonVault::open_encrypted(&vault_path, key) {
        Ok(vault) => vault,
        Err(error) => panic!("unexpected error: {error}"),
    };
    stored(&mut vault, &scope("s"), "email", "alice@example.com");

    // A key readable by other users is rejected before its bytes are used.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o644)) {
            panic!("cannot open {}: {error}", path.display());
        }
        let error = match VaultKey::from_file(&path) {
            Ok(_) => panic!("a world-readable key file must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("chmod 600"), "{error}");
    }

    cleanup(&path);
    cleanup(&vault_path);
}
