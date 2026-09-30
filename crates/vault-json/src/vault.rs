//! The [`Vault`] implementation for [`JsonVault`], kept out of `lib.rs` so the
//! storage-format module stays under the LOC ceiling.

use do_context_shield_plugin_api::{
    Mapping, ScopeId, Vault, VaultError, is_minted_placeholder_token, mint_placeholder,
};
use std::collections::{HashMap, HashSet};

use crate::{JsonVault, Lock, MappingRecord};

impl JsonVault {
    /// Insert or reuse one mapping in the already-reloaded state.
    ///
    /// The caller holds the exclusive lock and persists afterwards, so this is
    /// the single definition of the reuse/rotation rule for both the per-item
    /// and the batched path.
    fn insert_locked(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        if let Some(index) = self.state.mappings.iter().position(|record| {
            record.scope == scope.0
                && record.mapping.kind == kind
                && record.mapping.original == original
        }) {
            if is_minted_placeholder_token(&self.state.mappings[index].mapping.token) {
                return Ok(self.state.mappings[index].mapping.clone());
            }
            // A vault created before entropy-bearing tokens was introduced
            // must never keep its guessable token as a live alias. Rotate the
            // mapping on first use and make the old token permanently miss.
            let next = self.next_counter(scope, kind)?;
            let token = mint_placeholder(kind, next)?;
            self.state.mappings[index].mapping.token = token;
            return Ok(self.state.mappings[index].mapping.clone());
        }

        let next = self.next_counter(scope, kind)?;
        let mapping = Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token: mint_placeholder(kind, next)?,
        };
        self.state.mappings.push(MappingRecord {
            scope: scope.0.clone(),
            mapping: mapping.clone(),
        });
        Ok(mapping)
    }
}

impl Vault for JsonVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        // Serialize the whole reload-modify-persist cycle so concurrent
        // writers cannot lose each other's mappings or reuse a counter.
        let _lock = Lock::exclusive(&self.path)?;
        // Reload so sequential CLI processes share counters and mappings.
        self.reload_locked()?;
        let mapping = self.insert_locked(scope, kind, original)?;
        self.persist_locked()?;
        Ok(mapping)
    }

    fn get_or_insert_many(
        &mut self,
        scope: &ScopeId,
        items: &[(&str, &str)],
    ) -> Result<Vec<Mapping>, VaultError> {
        // One lock, one reload, one persist for the whole list: the per-item
        // method would rewrite the file once per entity. The snapshot is read
        // per call, never cached, so a deletion made between two calls stays
        // visible. A failure before the persist leaves the stored file
        // unchanged (the next call reloads it first).
        let _lock = Lock::exclusive(&self.path)?;
        self.reload_locked()?;
        let mut mappings = Vec::with_capacity(items.len());
        for (kind, original) in items {
            mappings.push(self.insert_locked(scope, kind, original)?);
        }
        self.persist_locked()?;
        Ok(mappings)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        let state = Self::read_state(&self.path, &self.format)?;
        Ok(state
            .mappings
            .into_iter()
            .find(|record| {
                record.scope == scope.0
                    && record.mapping.token == token
                    && is_minted_placeholder_token(&record.mapping.token)
            })
            .map(|record| record.mapping))
    }

    fn resolve_many(
        &self,
        scope: &ScopeId,
        tokens: &[&str],
    ) -> Result<Vec<Option<Mapping>>, VaultError> {
        // One authoritative read for the whole list: restoring a text with
        // many placeholders otherwise re-reads and re-parses the file once
        // per token. The read is per call, never cached, so a deletion made
        // between two calls stays visible.
        let state = Self::read_state(&self.path, &self.format)?;
        let wanted: HashSet<&str> = tokens.iter().copied().collect();
        let mut found: HashMap<&str, &Mapping> = HashMap::with_capacity(wanted.len());
        for record in &state.mappings {
            let token = record.mapping.token.as_str();
            if record.scope == scope.0
                && wanted.contains(token)
                && is_minted_placeholder_token(token)
            {
                found.entry(token).or_insert(&record.mapping);
            }
        }
        Ok(tokens
            .iter()
            .map(|token| found.get(token).map(|mapping| (*mapping).clone()))
            .collect())
    }

    fn delete_scope(&mut self, scope: &ScopeId) -> Result<(), VaultError> {
        let _lock = Lock::exclusive(&self.path)?;
        self.reload_locked()?;
        self.state.mappings.retain(|record| record.scope != scope.0);
        self.state.counters.retain(|record| record.scope != scope.0);
        self.persist_locked()
    }
}
