//! `Vault` over the newline-delimited JSON protocol.
//!
//! Requests: `{"method":"vault_get_or_insert","scope":"...","kind":"...","original":"..."}`
//! and `{"method":"vault_resolve","scope":"...","token":"..."}`. Responses:
//! `{"token":"__DO_PRIVATE_EMAIL_1__"}` and
//! `{"mapping":{"kind","original","token"}}` (or `{"mapping":null}`).
//!
//! The child owns the mapping store: `ProcessVault` keeps only the command line
//! and starts one child per operation, so stability across calls is whatever
//! that store provides. A stateless child re-issues tokens per call.

use crate::ProcessConfig;
use crate::protocol;
use do_context_shield_plugin_api::{Mapping, ScopeId, Vault, VaultError, is_placeholder_token};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Guidance returned when no vault command is configured.
const NO_COMMAND: &str =
    "process vault unavailable (no command configured); pass `--vault-command <program> [args...]`";

/// Vault backed by a local executable over the NDJSON protocol.
pub struct ProcessVault {
    config: ProcessConfig,
}

impl ProcessVault {
    /// Build a vault from an explicit config.
    #[must_use]
    pub fn new(config: ProcessConfig) -> Self {
        Self { config }
    }

    /// Current configuration.
    #[must_use]
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Build a vault from an adapter selection.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when no usable command is configured, so a
    /// missing `--vault-command` fails at startup instead of on the first call.
    pub fn from_selection(command: Option<&str>, timeout: Duration) -> Result<Self, VaultError> {
        let command = command
            .filter(|command| !command.trim().is_empty())
            .ok_or_else(|| VaultError::Message(NO_COMMAND.to_owned()))?;
        Ok(Self::new(
            ProcessConfig::with_command(command.to_owned()).with_timeout(timeout),
        ))
    }

    /// Run one vault operation against the configured child.
    fn request<T: Serialize, R: DeserializeOwned>(&self, request: &T) -> Result<R, VaultError> {
        let Some((program, args)) = protocol::split_command(self.config.command.as_deref()) else {
            return Err(VaultError::Message(NO_COMMAND.to_owned()));
        };
        let encoded = protocol::encode("vault", request).map_err(VaultError::Message)?;
        let line = protocol::run_child("vault", program, &args, encoded, self.config.timeout)
            .map_err(VaultError::Message)?;
        protocol::decode("vault", &line).map_err(VaultError::Message)
    }
}

impl Default for ProcessVault {
    fn default() -> Self {
        Self::new(ProcessConfig::default())
    }
}

impl Vault for ProcessVault {
    /// Ask the configured child for a token, creating and storing one if needed.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when no command is configured, the child cannot be
    /// started, no response arrives within the configured timeout, or the
    /// response carries a token that `restore` cannot resolve.
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        let request = GetOrInsertRequest {
            method: "vault_get_or_insert",
            scope: &scope.0,
            kind,
            original,
        };
        let response: GetOrInsertResponse = self.request(&request)?;
        if !is_placeholder_token(&response.token) {
            return Err(VaultError::Message(format!(
                "process vault returned the token `{}` that `restore` cannot resolve",
                response.token
            )));
        }
        Ok(Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token: response.token,
        })
    }

    /// Ask the configured child to resolve a placeholder within a scope.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when no command is configured, the child cannot be
    /// started, no response arrives within the configured timeout, or the
    /// response does not echo the requested token.
    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        let request = ResolveRequest {
            method: "vault_resolve",
            scope: &scope.0,
            token,
        };
        let response: ResolveResponse = self.request(&request)?;
        match response.mapping {
            None => Ok(None),
            Some(mapping) if mapping.token == token => Ok(Some(mapping)),
            Some(_) => Err(VaultError::Message(
                "process vault resolved a token to a different token".to_owned(),
            )),
        }
    }
}

/// Request written as one JSON line on the child's stdin.
#[derive(Serialize)]
struct GetOrInsertRequest<'a> {
    method: &'static str,
    scope: &'a str,
    kind: &'a str,
    original: &'a str,
}

/// Response read as one JSON line from the child's stdout.
#[derive(Deserialize)]
struct GetOrInsertResponse {
    token: String,
}

/// Request written as one JSON line on the child's stdin.
#[derive(Serialize)]
struct ResolveRequest<'a> {
    method: &'static str,
    scope: &'a str,
    token: &'a str,
}

/// Response read as one JSON line from the child's stdout.
#[derive(Deserialize)]
struct ResolveResponse {
    #[serde(default)]
    mapping: Option<Mapping>,
}
