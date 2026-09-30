//! `[vault]` combination validation, kept out of `config.rs` so the loader
//! module stays under the LOC ceiling.

use super::{Resolved, VaultConfig};
use std::path::Path;

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
                return Err(ttl_needs_a_lifetime_vault("process"));
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
        // The JSON vault carries a write timestamp per mapping, so a TTL
        // applies to persisted state too; only the process vault has no
        // lifetime policy.
        Some("json") => {
            if !file {
                return Err("config: vault `json` requires `vault_file`".into());
            }
        }
        // No explicit vault name: a `vault_file` selects the JSON vault.
        _ => {
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

/// A TTL for the one vault that has no lifetime policy.
fn ttl_needs_a_lifetime_vault(name: &str) -> Box<dyn std::error::Error> {
    format!("config: `vault_ttl_seconds` requires the memory or JSON vault (selected: `{name}`)")
        .into()
}

/// The storage implementation a resolved selection names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VaultKind {
    /// Local executable over the process protocol.
    Process,
    /// File-backed JSON vault.
    Json,
    /// In-process memory vault.
    Memory,
}

/// The vault kind the resolved selection names, or the selection conflict.
///
/// One definition for both the runtime (`build_vault` constructs exactly what
/// this returns) and the `config` diagnostics (which reports it), so "which
/// vault will run" and "why this selection cannot run" cannot drift apart.
///
/// # Errors
///
/// Returns the conflict description for a vault combined with a
/// `vault_file`/`vault_key_file` it cannot use, a `json` selection without a
/// vault file, a key file without one, or an unknown vault name.
pub(crate) fn vault_kind(resolved: &Resolved) -> Result<VaultKind, Box<dyn std::error::Error>> {
    let file = resolved.vault_file.is_some();
    let key = resolved.vault_key_file.is_some();
    Ok(match resolved.vault.as_deref() {
        Some("process") => {
            if file {
                return Err(vault_file_selection_conflict("process"));
            }
            if key {
                return Err(vault_key_conflict("process"));
            }
            VaultKind::Process
        }
        Some("json") => {
            json_vault_file(resolved.vault_file.as_deref())?;
            VaultKind::Json
        }
        Some("memory") => {
            if file {
                return Err(vault_file_selection_conflict("memory"));
            }
            if key {
                return Err(vault_key_conflict("memory"));
            }
            VaultKind::Memory
        }
        Some(other) => return Err(format!("unknown vault plugin `{other}`").into()),
        // No explicit vault name: a `vault_file` selects the JSON vault.
        None => {
            if file {
                VaultKind::Json
            } else if key {
                return Err(
                    "vault key file (`vault_key_file` or `--vault-key-file`) requires a vault file (`vault_file` or `--vault-file <path>`) for the JSON vault"
                        .into(),
                );
            } else {
                VaultKind::Memory
            }
        }
    })
}

/// Resolve the JSON vault path or explain what is missing.
///
/// # Errors
///
/// Returns an error when the resolved selection names no vault file.
pub(crate) fn json_vault_file(
    vault_file: Option<&Path>,
) -> Result<&Path, Box<dyn std::error::Error>> {
    vault_file.ok_or_else(|| {
        "vault `json` requires a vault file (`vault_file` or `--vault-file <path>`)".into()
    })
}

/// A `vault_file` alongside a vault that cannot use one, named as the runtime
/// selection error.
fn vault_file_selection_conflict(name: &str) -> Box<dyn std::error::Error> {
    format!("vault `{name}` cannot be combined with a vault file (`vault_file` or `--vault-file`)")
        .into()
}

/// A `vault_key_file` alongside a vault that cannot encrypt at rest, named as
/// the runtime selection error.
fn vault_key_conflict(name: &str) -> Box<dyn std::error::Error> {
    format!(
        "vault `{name}` cannot be combined with a vault key file (`vault_key_file` or `--vault-key-file`)"
    )
    .into()
}
