//! CLI commands that create, migrate, or verify local files.

use crate::cli::{CreateKeyArgs, EncryptVaultArgs, VerifyAuditArgs};
use std::io::{self, Write};

/// Create a random key file with restrictive platform permissions.
///
/// # Errors
///
/// Returns an error if secure creation or stdout flushing fails.
pub(crate) fn create_key(args: &CreateKeyArgs) -> Result<(), Box<dyn std::error::Error>> {
    do_context_shield_vault_json::create_key_file(&args.output)?;
    println!("Created key file with restrictive permissions.");
    io::stdout().flush()?;
    Ok(())
}

/// Rewrite an existing plaintext JSON vault in the encrypted format.
///
/// Both paths come from the command line, not the configuration: a migration
/// rewrites the vault in place, so an ambient file must not trigger it.
///
/// # Errors
///
/// Returns an error if the key or vault cannot be read, validated, or rewritten.
pub(crate) fn encrypt_vault(args: &EncryptVaultArgs) -> Result<(), Box<dyn std::error::Error>> {
    let key = do_context_shield_vault_json::VaultKey::from_file(&args.vault_key_file)?;
    do_context_shield_vault_json::JsonVault::encrypt_in_place(&args.vault_file, key)?;
    Ok(())
}

/// Verify a local audit chain and report only safe metadata.
///
/// Exits 0 for a verified, empty, or recognized legacy v1 file (which is never
/// upgraded), and 1 on an integrity failure.
///
/// # Errors
///
/// Returns an error when the report cannot be serialized, stdout cannot be
/// flushed, or the audit file cannot be read.
pub(crate) fn verify_audit(args: &VerifyAuditArgs) -> Result<(), Box<dyn std::error::Error>> {
    let report = do_context_shield_audit_file::verify_file(&args.audit_file)?;
    if args.format == "json" {
        println!(
            "{}",
            serde_json::json!({
                "format": report.format(),
                "records": report.records(),
                "record_index": report.record_index(),
                "category": report.category(),
                "ok": report.is_ok(),
            })
        );
    } else {
        println!("{report}");
    }
    io::stdout().flush()?;
    if !report.is_ok() {
        std::process::exit(1);
    }
    Ok(())
}
