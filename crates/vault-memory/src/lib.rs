//! In-memory session-scoped vault.

use do_context_shield_plugin_api::{Mapping, ScopeId, Vault, VaultError};
use std::collections::HashMap;

/// Memory-only vault.
#[derive(Default)]
pub struct MemoryVault {
    mappings: HashMap<(String, String), Mapping>,
    counters: HashMap<(String, String), usize>,
}

impl Vault for MemoryVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        let key = (scope.0.clone(), original.to_owned());
        if let Some(mapping) = self.mappings.get(&key) {
            return Ok(mapping.clone());
        }

        let counter_key = (scope.0.clone(), kind.to_owned());
        let next = self
            .counters
            .entry(counter_key)
            .and_modify(|value| *value += 1)
            .or_insert(1);
        let token = format!("__DO_PRIVATE_{}_{}__", kind.to_ascii_uppercase(), next);
        let mapping = Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token,
        };
        self.mappings.insert(key, mapping.clone());
        Ok(mapping)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        Ok(self
            .mappings
            .iter()
            .find(|((saved_scope, _), mapping)| saved_scope == &scope.0 && mapping.token == token)
            .map(|(_, mapping)| mapping.clone()))
    }
}
