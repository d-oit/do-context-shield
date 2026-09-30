//! `[vault]` combination validation, kept out of `config.rs` so the loader
//! module stays under the LOC ceiling.

use super::VaultConfig;

/// Reject vault combinations that cannot select one consistent vault.
///
/// # Errors
///
/// Returns an error naming both contradictory fields, or the TTL with a
/// non-memory vault.
pub(super) fn validate_vault(vault: &VaultConfig) -> Result<(), Box<dyn std::error::Error>> {
    let file = vault.vault_file.is_some();
    let ttl = vault.vault_ttl_seconds.is_some();
    let key = vault.vault_key_file.is_some();
    match vault.vault.as_deref() {
        Some("process") => {
            if file {
                return Err(vault_file_conflict("process"));
            }
            if ttl {
                return Err(ttl_requires_memory("process"));
            }
            if key {
                return Err(key_requires_json_vault("process"));
            }
        }
        Some("memory") => {
            if file {
                return Err(vault_file_conflict("memory"));
            }
            if key {
                return Err(key_requires_json_vault("memory"));
            }
        }
        Some("json") => {
            if !file {
                return Err("config: vault `json` requires `vault_file`".into());
            }
            if ttl {
                return Err(ttl_requires_memory("json"));
            }
        }
        // No explicit vault name: a `vault_file` selects the JSON vault.
        _ => {
            if file && ttl {
                return Err(ttl_requires_memory("json"));
            }
            if key && !file {
                return Err(
                    "config: `vault_key_file` requires `vault_file` (the JSON vault)".into(),
                );
            }
        }
    }
    Ok(())
}

/// A `vault_key_file` alongside an explicit non-JSON vault name.
fn key_requires_json_vault(name: &str) -> Box<dyn std::error::Error> {
    format!(
        "config: vault `{name}` cannot be combined with `vault_key_file` (only the JSON vault encrypts at rest)"
    )
    .into()
}

/// A `vault_file` alongside an explicit non-JSON vault name.
fn vault_file_conflict(name: &str) -> Box<dyn std::error::Error> {
    format!(
        "config: vault `{name}` cannot be combined with `vault_file` (a vault file selects the JSON vault)"
    )
    .into()
}

/// A TTL that only the memory vault implements.
fn ttl_requires_memory(name: &str) -> Box<dyn std::error::Error> {
    format!("config: `vault_ttl_seconds` requires the memory vault (selected: `{name}`)").into()
}
