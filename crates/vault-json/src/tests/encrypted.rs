//! Vault-level tests for the encrypted format and the migration path.

use super::*;
use do_context_shield_plugin_api::Vault;

fn key(seed: u8) -> VaultKey {
    VaultKey::new([seed; 32])
}

fn open_encrypted(path: &PathBuf, seed: u8) -> JsonVault {
    // Same transient-denial retry as `super::open`: fresh temp-dir files can
    // be briefly denied on Windows while a scanner holds them. Expected
    // errors (wrong key, corrupt file) are asserted at their call sites and
    // must keep failing fast, so they do not go through this helper.
    let mut attempts = 0;
    loop {
        match JsonVault::open_encrypted(path, key(seed)) {
            Ok(vault) => return vault,
            Err(error) => {
                assert!(attempts < 50, "unexpected error: {error}");
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
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

#[test]
#[allow(clippy::too_many_lines)]
fn error_diagnostics_omit_paths_keys_and_ciphertext() {
    // The path itself is the disclosure (user names, project names, mounted
    // secret locations), so a canary directory name stands in for it next to
    // canary key text and the ciphertext hiding a canary plaintext: every
    // rendered error below must omit all three.
    let canary = "canary-project-do-not-print";
    // The canary component sits under the per-process `temp_path()` root, so
    // the asserted substring appears in every path below without parallel
    // checkouts racing on a fixed directory name.
    let root = temp_path();
    let dir = root.join(canary);
    fs::remove_dir_all(&root).ok();
    if let Err(error) = fs::create_dir_all(&dir) {
        panic!("cannot create {}: {error}", dir.display());
    }
    let key_path = dir.join("vault.key");
    let canary_hex = "cf".repeat(32);
    let write_key = |contents: &str| {
        if let Err(error) = fs::write(&key_path, contents) {
            panic!("cannot write {}: {error}", key_path.display());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)) {
                panic!("cannot restrict {}: {error}", key_path.display());
            }
        }
    };
    // `VaultKey` has no `Debug`, so `unwrap_err` is unavailable.
    let key_error = |result: Result<VaultKey, VaultError>| match result {
        Ok(_) => panic!("expected a key-file error"),
        Err(error) => error.to_string(),
    };

    // Missing file: its own category, without the resolved path.
    let missing = key_error(VaultKey::from_file(&dir.join("absent.key")));

    // Invalid hex and wrong length: format categories without the contents.
    write_key(&"zz".repeat(32));
    let invalid_hex = key_error(VaultKey::from_file(&key_path));
    write_key("ab");
    let wrong_length = key_error(VaultKey::from_file(&key_path));

    assert!(missing.contains("does not exist"), "{missing}");
    assert!(invalid_hex.contains("non-hex"), "{invalid_hex}");
    assert!(wrong_length.contains("64 hex characters"), "{wrong_length}");
    assert_ne!(missing, invalid_hex);
    assert_ne!(missing, wrong_length);
    assert_ne!(invalid_hex, wrong_length);

    // A loose key file: actionable remediation without the path or mode bits.
    #[cfg(unix)]
    let permission = {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::write(&key_path, format!("{canary_hex}\n")) {
            panic!("cannot write {}: {error}", key_path.display());
        }
        if let Err(error) = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)) {
            panic!("cannot loosen {}: {error}", key_path.display());
        }
        key_error(VaultKey::from_file(&key_path))
    };
    write_key(&format!("{canary_hex}\n"));

    // Wrong key and a modified payload share one category — an AEAD cannot
    // tell a wrong key from flipped ciphertext — and neither echoes the key
    // text, the ciphertext, or the plaintext it hides. The key file above
    // holds `canary_hex`, which is `key(0xcf)`.
    let vault_path = dir.join("vault.json");
    let plaintext = "canary@example.com";
    {
        let mut vault = open_encrypted(&vault_path, 0xcf);
        stored(&mut vault, &scope("s"), "email", plaintext);
    }
    let wrong_key = match JsonVault::open_encrypted(&vault_path, key(2)) {
        Ok(_) => panic!("a wrong key must not open the vault"),
        Err(error) => error.to_string(),
    };
    assert!(wrong_key.contains("wrong key"), "{wrong_key}");

    let value: serde_json::Value = match serde_json::from_str(&file_text(&vault_path)) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let payload = value["payload"].as_str().unwrap_or_default().to_owned();
    assert!(!payload.is_empty(), "the envelope must carry a payload");
    let mut flipped: Vec<char> = payload.chars().collect();
    if let Some(digit) = flipped.first_mut() {
        *digit = if *digit == '0' { '1' } else { '0' };
    }
    let mut tampered = value.clone();
    tampered["payload"] = serde_json::Value::String(flipped.into_iter().collect());
    if let Err(error) = fs::write(&vault_path, tampered.to_string()) {
        panic!("cannot write {}: {error}", vault_path.display());
    }
    let modified = match JsonVault::open_encrypted(&vault_path, key(0xcf)) {
        Ok(_) => panic!("a modified vault must not open"),
        Err(error) => error.to_string(),
    };
    assert!(modified.contains("wrong key"), "{modified}");

    // A structurally detectable tamper (truncated nonce) keeps its own
    // category, distinct from the authentication-failure one.
    let mut truncated = value;
    truncated["nonce"] = serde_json::Value::String("00".to_owned());
    if let Err(error) = fs::write(&vault_path, truncated.to_string()) {
        panic!("cannot write {}: {error}", vault_path.display());
    }
    let truncated_nonce = match JsonVault::open_encrypted(&vault_path, key(0xcf)) {
        Ok(_) => panic!("a truncated nonce must not open the vault"),
        Err(error) => error.to_string(),
    };
    assert!(truncated_nonce.contains("nonce"), "{truncated_nonce}");

    for message in [
        &missing,
        &invalid_hex,
        &wrong_length,
        &wrong_key,
        &modified,
        &truncated_nonce,
    ] {
        assert!(!message.contains(canary), "{message}");
        assert!(!message.contains(canary_hex.as_str()), "{message}");
        assert!(!message.contains(plaintext), "{message}");
        assert!(!message.contains(payload.as_str()), "{message}");
    }
    assert_ne!(wrong_key, missing);
    assert_ne!(wrong_key, invalid_hex);
    assert_ne!(wrong_key, wrong_length);
    assert_ne!(wrong_key, truncated_nonce);

    // The permission category stays distinct from the read and format ones.
    #[cfg(unix)]
    {
        assert!(permission.contains("chmod 600"), "{permission}");
        assert_ne!(permission, missing);
        assert_ne!(permission, invalid_hex);
        assert_ne!(permission, wrong_key);
        assert!(!permission.contains(canary), "{permission}");
        assert!(!permission.contains(canary_hex.as_str()), "{permission}");
    }

    cleanup(&vault_path);
    cleanup(&key_path);
    fs::remove_dir_all(&root).ok();
}
