//! Black-box tests for the encrypted JSON vault and its migration.

mod common;

use common::{cmd, temp_dir};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Write a key file holding `hex` (owner-only on Unix) and return its path.
fn write_key(dir: &Path, name: &str, hex: &str) -> PathBuf {
    let path = dir.join(name);
    if let Err(error) = std::fs::write(&path, format!("{hex}\n")) {
        panic!("cannot write {}: {error}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
            panic!("cannot restrict {}: {error}", path.display());
        }
    }
    path
}

/// `sanitize|restore --session s --vault-file <vault> [--vault-key-file <key>]`.
fn vault_command(
    dir: &Path,
    subcommand: &str,
    vault: &Path,
    key: Option<&Path>,
) -> assert_cmd::Command {
    let mut command = cmd(dir);
    command
        .args([OsString::from(subcommand), OsString::from("--session")])
        .arg("s")
        .arg("--vault-file")
        .arg(vault);
    if let Some(key) = key {
        command.arg("--vault-key-file").arg(key);
    }
    command
}

/// `sanitize` with the given vault and key (when set), asserting success.
fn sanitize(dir: &Path, vault: &Path, key: Option<&Path>, input: &str) -> String {
    let assert = vault_command(dir, "sanitize", vault, key)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// `restore` with the given vault and key (when set), asserting success.
fn restore(dir: &Path, vault: &Path, key: Option<&Path>, input: &str) -> String {
    let assert = vault_command(dir, "restore", vault, key)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// Vault file contents, or an empty string when nothing was written.
fn vault_contents(vault: &Path) -> String {
    std::fs::read_to_string(vault).unwrap_or_default()
}

/// `path` as a TOML basic-string literal: backslashes are escape characters,
/// so Windows paths must be doubled or TOML fails with a unicode-escape error.
fn toml_literal(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

#[test]
fn encrypted_round_trip_keeps_values_out_of_the_file() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let key = write_key(dir.path(), "vault.key", &"ab".repeat(32));

    let sanitized = sanitize(dir.path(), &vault, Some(&key), "mail alice@example.com");
    common::assert_contains_placeholder(&sanitized, "EMAIL", 1);
    let contents = vault_contents(&vault);
    assert!(!contents.contains("alice@example.com"), "{contents}");
    assert!(contents.contains("\"cipher\""), "{contents}");

    assert_eq!(
        restore(dir.path(), &vault, Some(&key), &sanitized),
        "mail alice@example.com"
    );
}

#[test]
fn a_missing_or_wrong_key_fails_closed() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let key = write_key(dir.path(), "vault.key", &"ab".repeat(32));
    let other = write_key(dir.path(), "other.key", &"cd".repeat(32));
    let sanitized = sanitize(dir.path(), &vault, Some(&key), "alice@example.com");

    // Without a key the encrypted file is rejected, not misread as state.
    vault_command(dir.path(), "restore", &vault, None)
        .write_stdin(sanitized.clone())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("is encrypted"));

    // A different key cannot decrypt it.
    vault_command(dir.path(), "restore", &vault, Some(&other))
        .write_stdin(sanitized.clone())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("wrong key"));
}

#[test]
fn encrypt_vault_migrates_a_plaintext_file() {
    let dir = temp_dir();
    let vault = dir.path().join("vault.json");
    let key = write_key(dir.path(), "vault.key", &"ef".repeat(32));

    // Baseline: without a key the vault is plaintext on disk.
    let sanitized = sanitize(dir.path(), &vault, None, "alice@example.com");
    assert!(vault_contents(&vault).contains("alice@example.com"));

    cmd(dir.path())
        .arg("encrypt-vault")
        .arg("--vault-file")
        .arg(&vault)
        .arg("--vault-key-file")
        .arg(&key)
        .assert()
        .success();

    let contents = vault_contents(&vault);
    assert!(!contents.contains("alice@example.com"), "{contents}");
    // The mapping survived and now needs the key.
    assert_eq!(
        restore(dir.path(), &vault, Some(&key), &sanitized),
        "alice@example.com"
    );
    vault_command(dir.path(), "restore", &vault, None)
        .write_stdin(sanitized.clone())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("is encrypted"));

    // A second migration of the already-encrypted file is rejected.
    cmd(dir.path())
        .arg("encrypt-vault")
        .arg("--vault-file")
        .arg(&vault)
        .arg("--vault-key-file")
        .arg(&key)
        .assert()
        .code(1)
        .stderr(predicates::str::contains("already encrypted"));
}

#[test]
fn the_key_file_can_come_from_the_environment() {
    let dir = temp_dir();
    let vault = dir.path().join("env.json");
    let key = write_key(dir.path(), "env.key", &"11".repeat(32));

    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_VAULT_FILE", &vault)
        .env("DO_CONTEXT_SHIELD_VAULT_KEY_FILE", &key)
        .args(["sanitize", "--session", "s"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_contains_placeholder(&sanitized, "EMAIL", 1);
    assert!(vault_contents(&vault).contains("\"cipher\""));
}

#[test]
fn the_key_file_can_come_from_the_config_file() {
    let dir = temp_dir();
    let vault = dir.path().join("configured.json");
    let key = write_key(dir.path(), "configured.key", &"22".repeat(32));
    let config = dir.path().join("do-context-shield.toml");
    let toml = format!(
        "[vault]\nvault_file = {}\nvault_key_file = {}\n",
        toml_literal(&vault),
        toml_literal(&key)
    );
    if let Err(error) = std::fs::write(&config, toml) {
        panic!("cannot write {}: {error}", config.display());
    }

    // The working-directory config supplies both the vault and its key.
    let assert = cmd(dir.path())
        .args(["sanitize", "--session", "s"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_contains_placeholder(&sanitized, "EMAIL", 1);
    assert!(vault_contents(&vault).contains("\"cipher\""));
}

#[cfg(unix)]
#[test]
fn a_key_readable_by_others_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir();
    let vault = dir.path().join("loose.json");
    let key = write_key(dir.path(), "loose.key", &"33".repeat(32));
    if let Err(error) = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)) {
        panic!("cannot open {}: {error}", key.display());
    }

    vault_command(dir.path(), "sanitize", &vault, Some(&key))
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("chmod 600"));
}
