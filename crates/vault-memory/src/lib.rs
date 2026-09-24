//! In-memory session-scoped vault.

use do_context_shield_plugin_api::{
    Mapping, ScopeId, Vault, VaultError, is_minted_placeholder_token, mint_placeholder,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Memory-only vault.
#[derive(Default)]
pub struct MemoryVault {
    // Keyed by (scope, kind, original): the same value detected under
    // different kinds must yield distinct kind-tagged tokens.
    mappings: HashMap<(String, String, String), Entry>,
    counters: HashMap<(String, String), u64>,
    /// Optional lifetime after which a mapping stops resolving.
    ttl: Option<Duration>,
}

/// One stored mapping with its insertion time.
struct Entry {
    mapping: Mapping,
    created_at: Instant,
}

impl MemoryVault {
    /// Build a vault whose mappings stop resolving `ttl` after insertion.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl: Some(ttl),
            ..Self::default()
        }
    }

    /// Whether `entry` has outlived the configured TTL.
    fn expired(&self, entry: &Entry) -> bool {
        self.ttl
            .is_some_and(|ttl| entry.created_at.elapsed() >= ttl)
    }
}

impl Vault for MemoryVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        let key = (scope.0.clone(), kind.to_owned(), original.to_owned());
        if let Some(entry) = self.mappings.get(&key) {
            if !self.expired(entry) {
                return Ok(entry.mapping.clone());
            }
        }
        // Remove a stale entry before re-inserting it under the same key.
        self.mappings.remove(&key);

        let counter_key = (scope.0.clone(), kind.to_owned());
        let next = *self
            .counters
            .entry(counter_key)
            .and_modify(|value| *value += 1)
            .or_insert(1);
        let token = mint_placeholder(kind, next)?;
        let mapping = Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token,
        };
        self.mappings.insert(
            key,
            Entry {
                mapping: mapping.clone(),
                created_at: Instant::now(),
            },
        );
        Ok(mapping)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        Ok(self
            .mappings
            .iter()
            .find(|((saved_scope, _, _), entry)| {
                saved_scope == &scope.0
                    && entry.mapping.token == token
                    && is_minted_placeholder_token(&entry.mapping.token)
                    && !self.expired(entry)
            })
            .map(|(_, entry)| entry.mapping.clone()))
    }

    fn delete_scope(&mut self, scope: &ScopeId) -> Result<(), VaultError> {
        self.mappings
            .retain(|(saved_scope, _, _), _| saved_scope != &scope.0);
        self.counters
            .retain(|(saved_scope, _), _| saved_scope != &scope.0);
        Ok(())
    }

    fn expire(&mut self) -> Result<(), VaultError> {
        let ttl = self.ttl;
        self.mappings
            .retain(|_, entry| ttl.is_none_or(|ttl| entry.created_at.elapsed() < ttl));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(name: &str) -> ScopeId {
        ScopeId(name.to_owned())
    }

    fn stored(vault: &mut MemoryVault, scope: &ScopeId, kind: &str, original: &str) -> Mapping {
        match vault.get_or_insert(scope, kind, original) {
            Ok(mapping) => mapping,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn resolved(vault: &MemoryVault, scope: &ScopeId, token: &str) -> Option<Mapping> {
        match vault.resolve(scope, token) {
            Ok(mapping) => mapping,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    /// Assert `token` is a minted placeholder for `kind`/`counter`.
    fn assert_token(token: &str, kind: &str, counter: u64) {
        let prefix = format!("__DO_PRIVATE_{kind}_{counter}_");
        assert!(
            token.starts_with(&prefix),
            "`{token}` does not start with `{prefix}`"
        );
    }

    #[test]
    fn same_value_under_different_kinds_gets_distinct_tokens() {
        let mut vault = MemoryVault::default();
        let scope = scope("s");
        let email = stored(&mut vault, &scope, "email", "alice@example.com");
        let person = stored(&mut vault, &scope, "person", "alice@example.com");
        assert!(email.token.contains("EMAIL"));
        assert!(person.token.contains("PERSON"));
        assert_ne!(email.token, person.token);
    }

    #[test]
    fn repeated_inserts_are_stable_within_scope_and_kind() {
        let mut vault = MemoryVault::default();
        let scope = scope("s");
        let first = stored(&mut vault, &scope, "email", "alice@example.com");
        let second = stored(&mut vault, &scope, "email", "alice@example.com");
        assert_eq!(first.token, second.token);
    }

    #[test]
    fn scopes_are_isolated() {
        let mut vault = MemoryVault::default();
        // Counters are per scope+kind and every mapping mints its own entropy,
        // so identical inputs in different scopes get distinct tokens;
        // isolation still lives in `resolve`.
        let email = stored(&mut vault, &scope("one"), "email", "alice@example.com");
        let person = stored(&mut vault, &scope("two"), "person", "alice@example.com");
        for (scope, token) in [
            (&scope("two"), &email.token),
            (&scope("one"), &person.token),
        ] {
            assert_eq!(resolved(&vault, scope, token), None);
        }
        assert_eq!(resolved(&vault, &scope("one"), &email.token), Some(email));
    }

    #[test]
    fn delete_scope_removes_mappings() {
        let mut vault = MemoryVault::default();
        let doomed = scope("doomed");
        let kept = scope("kept");
        let gone = stored(&mut vault, &doomed, "email", "alice@example.com");
        let kept_mapping = stored(&mut vault, &kept, "email", "bob@example.com");
        match vault.delete_scope(&doomed) {
            Ok(()) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }
        assert_eq!(resolved(&vault, &doomed, &gone.token), None);
        assert_eq!(
            resolved(&vault, &kept, &kept_mapping.token),
            Some(kept_mapping)
        );
        // The deleted scope starts from a fresh counter.
        let recreated = stored(&mut vault, &doomed, "email", "alice@example.com");
        assert_token(&recreated.token, "EMAIL", 1);
        assert_ne!(gone.token, recreated.token, "fresh entropy after deletion");
    }

    #[test]
    fn fabricated_tokens_do_not_resolve() {
        let mut vault = MemoryVault::default();
        let session = scope("s");
        let mapping = stored(&mut vault, &session, "email", "alice@example.com");
        // A guessed counter without the minted entropy does not resolve, so a
        // model cannot enumerate session values it was never shown.
        assert_eq!(resolved(&vault, &session, "__DO_PRIVATE_EMAIL_1__"), None);
        assert_eq!(
            resolved(&vault, &session, "__DO_PRIVATE_EMAIL_1_0000000000000000__"),
            None
        );
        assert_eq!(
            resolved(&vault, &session, &mapping.token),
            Some(mapping.clone())
        );
        // Scopes never share a token for the same value and kind.
        let second = stored(&mut vault, &scope("other"), "email", "alice@example.com");
        assert_ne!(mapping.token, second.token);
    }

    #[test]
    fn ttl_expires_old_mappings() {
        let mut vault = MemoryVault::with_ttl(Duration::from_millis(1));
        let scope = scope("s");
        let mapping = stored(&mut vault, &scope, "email", "alice@example.com");
        std::thread::sleep(Duration::from_millis(5));
        match vault.expire() {
            Ok(()) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }
        assert_eq!(resolved(&vault, &scope, &mapping.token), None);
    }

    #[test]
    fn ttl_expires_without_an_expire_tick() {
        let mut vault = MemoryVault::with_ttl(Duration::from_millis(1));
        let scope = scope("s");
        let stale = stored(&mut vault, &scope, "email", "alice@example.com");
        std::thread::sleep(Duration::from_millis(5));
        // `resolve` must not resurrect an expired mapping even before `expire`.
        assert_eq!(resolved(&vault, &scope, &stale.token), None);
        // A fresh insert under the same key gets a new token.
        let reissued = stored(&mut vault, &scope, "email", "alice@example.com");
        assert_eq!(resolved(&vault, &scope, &reissued.token), Some(reissued));
    }

    #[test]
    fn ttl_preserves_fresh_mappings() {
        let mut vault = MemoryVault::with_ttl(Duration::from_secs(60));
        let scope = scope("s");
        let mapping = stored(&mut vault, &scope, "email", "alice@example.com");
        assert_eq!(resolved(&vault, &scope, &mapping.token), Some(mapping));
    }
}
