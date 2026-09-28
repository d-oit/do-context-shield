//! Vault construction from the MCP server configuration.
//!
//! Kept out of `lib.rs` so the server module stays under the LOC ceiling.

use crate::ServerConfig;
use do_context_shield_plugin_api::Vault;
use do_context_shield_plugin_process::ProcessVault;
use do_context_shield_vault_memory::MemoryVault;
use std::path::Path;
use std::time::Duration;

/// Build the mapping vault from the server configuration.
///
/// # Errors
///
/// Returns an error for an unknown vault name, a missing vault file, an
/// incompatible `vault_file`/`vault_key_file`/`vault` combination, a
/// `vault_ttl_seconds` that does not apply to the selected vault, or a key
/// file that cannot be read.
pub(crate) fn build_vault(
    config: &mut ServerConfig,
    timeout: Duration,
) -> Result<Box<dyn Vault>, Box<dyn std::error::Error>> {
    let ttl = config.vault_ttl_seconds;
    let vault: Box<dyn Vault> = match config.vault.as_deref() {
        Some("process") => {
            if config.vault_file.is_some() {
                return Err(
                    "vault `process` cannot be combined with a vault file (`vault_file` or `--vault-file`)"
                        .into(),
                );
            }
            if config.vault_key_file.is_some() {
                return Err(key_requires_json_vault("process"));
            }
            reject_ttl(ttl, "process")?;
            Box::new(ProcessVault::from_selection(
                config.vault_command.as_deref(),
                timeout,
            )?)
        }
        Some("json") => {
            reject_ttl(ttl, "json")?;
            let path = config.vault_file.take().ok_or(
                "vault `json` requires a vault file (`vault_file` or `--vault-file <path>`)",
            )?;
            let key_file = config.vault_key_file.take();
            json_vault(&path, key_file.as_deref())?
        }
        Some("memory") => {
            if config.vault_file.is_some() {
                return Err(
                    "vault `memory` cannot be combined with a vault file (`vault_file` or `--vault-file`)"
                        .into(),
                );
            }
            if config.vault_key_file.is_some() {
                return Err(key_requires_json_vault("memory"));
            }
            memory_vault(ttl)
        }
        Some(other) => return Err(format!("unknown vault plugin `{other}`").into()),
        None => {
            if let Some(path) = config.vault_file.take() {
                reject_ttl(ttl, "json")?;
                let key_file = config.vault_key_file.take();
                json_vault(&path, key_file.as_deref())?
            } else if config.vault_key_file.is_some() {
                return Err(
                    "`vault_key_file` (`--vault-key-file`) requires a vault file (`vault_file` or `--vault-file <path>`) for the JSON vault"
                        .into(),
                );
            } else {
                memory_vault(ttl)
            }
        }
    };
    Ok(vault)
}

/// File-backed JSON vault, encrypted when a key file is configured.
///
/// # Errors
///
/// Returns an error when the key file cannot be read or the vault file cannot
/// be opened in the selected format.
fn json_vault(
    path: &Path,
    key_file: Option<&Path>,
) -> Result<Box<dyn Vault>, Box<dyn std::error::Error>> {
    Ok(do_context_shield_plugin_registry::json_vault(
        path, key_file,
    )?)
}

/// A vault key file alongside a vault that cannot encrypt at rest.
fn key_requires_json_vault(name: &str) -> Box<dyn std::error::Error> {
    format!(
        "vault `{name}` cannot be combined with a vault key file (`vault_key_file` or `--vault-key-file`)"
    )
    .into()
}

/// Reject a TTL that the selected vault has no lifetime policy for.
fn reject_ttl(ttl: Option<u64>, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if ttl.is_some() {
        return Err(format!(
            "`vault_ttl_seconds` (`--vault-ttl-seconds`) requires the memory vault (selected: `{name}`)"
        )
        .into());
    }
    Ok(())
}

/// In-process memory vault; with a TTL, mappings stop resolving after it.
fn memory_vault(ttl_seconds: Option<u64>) -> Box<dyn Vault> {
    match ttl_seconds {
        Some(seconds) => Box::new(MemoryVault::with_ttl(Duration::from_secs(seconds))),
        None => Box::new(MemoryVault::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use do_context_shield_plugin_process::DEFAULT_TIMEOUT_MS;
    use std::path::PathBuf;

    #[test]
    fn vault_ttl_is_rejected_for_non_memory_vaults() {
        for name in ["json", "process"] {
            let mut config = ServerConfig {
                vault: Some(name.to_owned()),
                vault_command: Some("does-not-matter".to_owned()),
                vault_ttl_seconds: Some(60),
                ..ServerConfig::default()
            };
            let error = match build_vault(&mut config, Duration::from_millis(DEFAULT_TIMEOUT_MS)) {
                Ok(_) => panic!("expected the TTL to be rejected for `{name}`"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("requires the memory vault"), "{error}");
        }

        // A lone `vault_file` selects the JSON vault, which has no lifetime policy.
        let mut config = ServerConfig {
            vault_file: Some(PathBuf::from("/nonexistent/vault.json")),
            vault_ttl_seconds: Some(60),
            ..ServerConfig::default()
        };
        let error = match build_vault(&mut config, Duration::from_millis(DEFAULT_TIMEOUT_MS)) {
            Ok(_) => panic!("expected the TTL to be rejected for a JSON vault file"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("requires the memory vault"), "{error}");

        // The memory vault is the one vault a TTL applies to.
        let mut config = ServerConfig {
            vault: Some("memory".to_owned()),
            vault_ttl_seconds: Some(60),
            ..ServerConfig::default()
        };
        assert!(build_vault(&mut config, Duration::from_millis(DEFAULT_TIMEOUT_MS)).is_ok());
    }

    #[test]
    fn vault_key_file_requires_the_json_vault() {
        for name in ["memory", "process"] {
            let mut config = ServerConfig {
                vault: Some(name.to_owned()),
                vault_key_file: Some(PathBuf::from("/nonexistent/key")),
                ..ServerConfig::default()
            };
            let error = match build_vault(&mut config, Duration::from_millis(DEFAULT_TIMEOUT_MS)) {
                Ok(_) => panic!("expected the key file to be rejected for `{name}`"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("cannot be combined"), "{name}: {error}");
        }

        // A key without a vault file cannot select an encryptable vault.
        let mut config = ServerConfig {
            vault_key_file: Some(PathBuf::from("/nonexistent/key")),
            ..ServerConfig::default()
        };
        let error = match build_vault(&mut config, Duration::from_millis(DEFAULT_TIMEOUT_MS)) {
            Ok(_) => panic!("expected the key file to be rejected without a vault file"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("requires a vault file"), "{error}");

        // With a vault file the key file is read, and a missing one is named.
        let mut config = ServerConfig {
            vault_file: Some(PathBuf::from("/nonexistent/vault.json")),
            vault_key_file: Some(PathBuf::from("/nonexistent/key")),
            ..ServerConfig::default()
        };
        let error = match build_vault(&mut config, Duration::from_millis(DEFAULT_TIMEOUT_MS)) {
            Ok(_) => panic!("expected the missing key file to fail the vault build"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("vault key file"), "{error}");
    }
}
