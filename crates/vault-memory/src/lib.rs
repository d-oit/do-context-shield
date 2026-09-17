//! In-memory session-scoped vault.

use do_context_shield_plugin_api::{Mapping, ScopeId, Vault, VaultError};
use std::collections::HashMap;

/// Memory-only vault.
#[derive(Default)]
pub struct MemoryVault {
    // Keyed by (scope, kind, original): the same value detected under
    // different kinds must yield distinct kind-tagged tokens.
    mappings: HashMap<(String, String, String), Mapping>,
    counters: HashMap<(String, String), usize>,
}

impl Vault for MemoryVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        let key = (scope.0.clone(), kind.to_owned(), original.to_owned());
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
            .find(|((saved_scope, _, _), mapping)| {
                saved_scope == &scope.0 && mapping.token == token
            })
            .map(|(_, mapping)| mapping.clone()))
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
        // Counters are per scope+kind, so identical inputs in different
        // scopes may share a token string; isolation lives in `resolve`.
        let email = stored(&mut vault, &scope("one"), "email", "alice@example.com");
        let person = stored(&mut vault, &scope("two"), "person", "alice@example.com");
        for (scope, token) in [
            (&scope("two"), &email.token),
            (&scope("one"), &person.token),
        ] {
            match vault.resolve(scope, token) {
                Ok(resolved) => assert_eq!(resolved, None),
                Err(error) => panic!("unexpected error: {error}"),
            }
        }
        match vault.resolve(&scope("one"), &email.token) {
            Ok(resolved) => assert_eq!(resolved, Some(email)),
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}
