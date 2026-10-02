//! Local audit sink construction and protected-path collision checks.

use do_context_shield_audit_file::FileAuditSink;
use do_context_shield_plugin_api::{AuditError, AuditSink};
use std::path::Path;

/// Construct a private local audit sink without overlapping vault state.
///
/// The destination is checked against the vault file, key file, and the JSON
/// vault's lock and temporary paths before the sink creates anything. Existing
/// files and existing parent directories are canonicalized so relative paths
/// and parent symlinks cannot evade the comparison.
///
/// # Errors
///
/// Returns [`AuditError`] when the audit path aliases protected vault state,
/// when canonicalization fails for a reason other than a missing parent, or
/// when the strict local file sink cannot create or validate its destination.
pub fn file_audit_sink(
    path: &Path,
    vault_file: Option<&Path>,
    vault_key_file: Option<&Path>,
) -> Result<Box<dyn AuditSink>, AuditError> {
    #[cfg(not(unix))]
    {
        let _ = (vault_file, vault_key_file);
        return Ok(Box::new(FileAuditSink::open(path)?));
    }

    #[cfg(unix)]
    {
        if let Some(vault_file) = vault_file {
            reject_alias(path, vault_file, "vault_file", "--vault-file")?;
            let lock = vault_file.with_extension("json.lock");
            reject_alias(
                path,
                &lock,
                "vault_file.with_extension(\"json.lock\")",
                "--vault-file",
            )?;
            let temporary = vault_file.with_extension("json.tmp");
            reject_alias(
                path,
                &temporary,
                "vault_file.with_extension(\"json.tmp\")",
                "--vault-file",
            )?;
        }
        if let Some(vault_key_file) = vault_key_file {
            reject_alias(path, vault_key_file, "vault_key_file", "--vault-key-file")?;
        }
        Ok(Box::new(FileAuditSink::open(path)?))
    }
}

#[cfg(unix)]
fn reject_alias(
    audit_path: &Path,
    protected_path: &Path,
    protected_field: &'static str,
    protected_flag: &'static str,
) -> Result<(), AuditError> {
    let audit_identity = canonical_destination(audit_path)?;
    let protected_identity = canonical_destination(protected_path)?;
    if audit_identity.is_some() && audit_identity == protected_identity {
        return Err(AuditError::Message(format!(
            "`audit_file` (`--audit-file`) must differ from `{protected_field}` (`{protected_flag}`)"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn canonical_destination(path: &Path) -> Result<Option<std::path::PathBuf>, AuditError> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let Some(file_name) = path.file_name() else {
                return Ok(None);
            };
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            match std::fs::canonicalize(parent) {
                Ok(parent) => Ok(Some(parent.join(file_name))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(safe_io_error("audit path canonicalization", &error)),
            }
        }
        Err(error) => Err(safe_io_error("audit path canonicalization", &error)),
    }
}

#[cfg(unix)]
fn safe_io_error(operation: &'static str, error: &std::io::Error) -> AuditError {
    AuditError::Message(format!("{operation} failed ({:?})", error.kind()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn rejects_vault_key_and_auxiliary_path_aliases_before_creation() {
        let current_dir = match std::env::current_dir() {
            Ok(path) => path,
            Err(error) => panic!("cannot locate test working directory: {error}"),
        };
        let directory = match tempfile::tempdir_in(&current_dir) {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create test directory: {error}"),
        };
        let vault = directory.path().join("vault.json");
        let key = directory.path().join("vault.key");
        if let Err(error) = fs::write(&vault, b"vault bytes") {
            panic!("cannot create vault fixture: {error}");
        }
        if let Err(error) = fs::write(&key, b"key bytes") {
            panic!("cannot create key fixture: {error}");
        }

        let relative_vault = match vault.strip_prefix(&current_dir) {
            Ok(path) => path,
            Err(error) => panic!("vault fixture should be relative to cwd: {error}"),
        };
        let error = match file_audit_sink(relative_vault, Some(&vault), Some(&key)) {
            Ok(_) => panic!("relative audit/vault alias must be refused"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--audit-file"));
        assert!(error.to_string().contains("--vault-file"));
        assert!(
            !error
                .to_string()
                .contains(&vault.to_string_lossy().to_string())
        );
        assert_eq!(
            fs::read(&vault).ok().as_deref(),
            Some(b"vault bytes".as_slice())
        );
        assert_eq!(
            fs::read(&key).ok().as_deref(),
            Some(b"key bytes".as_slice())
        );

        let key_error = match file_audit_sink(&key, None, Some(&key)) {
            Ok(_) => panic!("audit/key alias must be refused"),
            Err(error) => error,
        };
        assert!(key_error.to_string().contains("--vault-key-file"));

        for auxiliary in [
            vault.with_extension("json.lock"),
            vault.with_extension("json.tmp"),
        ] {
            let error = match file_audit_sink(&auxiliary, Some(&vault), None) {
                Ok(_) => panic!("audit/vault auxiliary alias must be refused"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("--vault-file"));
            assert!(!auxiliary.exists());
        }
    }

    #[test]
    fn rejects_parent_symlink_aliases() {
        let current_dir = match std::env::current_dir() {
            Ok(path) => path,
            Err(error) => panic!("cannot locate test working directory: {error}"),
        };
        let directory = match tempfile::tempdir_in(&current_dir) {
            Ok(directory) => directory,
            Err(error) => panic!("cannot create test directory: {error}"),
        };
        let vault = directory.path().join("vault.json");
        let alias_parent = directory.path().join("alias");
        if let Err(error) = fs::write(&vault, b"vault bytes") {
            panic!("cannot create vault fixture: {error}");
        }
        if let Err(error) = symlink(directory.path(), &alias_parent) {
            panic!("cannot create parent symlink fixture: {error}");
        }

        let alias = alias_parent.join("vault.json");
        let error = match file_audit_sink(&alias, Some(&vault), None) {
            Ok(_) => panic!("parent-symlink audit/vault alias must be refused"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--vault-file"));
        assert_eq!(
            fs::read(&vault).ok().as_deref(),
            Some(b"vault bytes".as_slice())
        );
    }
}
