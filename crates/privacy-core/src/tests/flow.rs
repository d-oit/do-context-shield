use super::*;

#[test]
fn sanitize_preserves_repeated_identity() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let result = match pipeline.sanitize(
        &scope,
        "mail alice@example.com then alice@example.com",
        &context(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let token = first_placeholder(&result.text);
    assert_eq!(result.text.matches(&token).count(), 2);
    assert!(!result.text.contains("alice@example.com"));
}

#[test]
fn restore_is_scope_limited() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let other = ScopeId("other".to_owned());
    let result = match pipeline.sanitize(&scope, "alice@example.com", &context()) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let restored = match pipeline.restore(&scope, &result.text) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let blocked = match pipeline.restore(&other, &result.text) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(restored, "alice@example.com");
    assert_eq!(blocked, result.text);
}

#[test]
fn restore_skips_malformed_placeholders_and_keeps_scanning() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let result = match pipeline.sanitize(&scope, "alice@example.com", &context()) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    let adversarial = format!("__DO_PRIVATE_ junk __DO_PRIVATE_ {}", result.text);
    let restored = match pipeline.restore(&scope, &adversarial) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(restored.contains("alice@example.com"));
    assert!(restored.contains("__DO_PRIVATE_ junk __DO_PRIVATE_ "));
}

#[test]
fn restore_leaves_redacted_and_truncated_tokens_untouched() {
    let pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    for input in [
        "__DO_PRIVATE_REDACTED__",
        "prefix __DO_PRIVATE_",
        "__DO_PRIVATE___",
    ] {
        match pipeline.restore(&scope, input) {
            Ok(output) => assert_eq!(output, input),
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}

#[test]
fn forget_removes_session_mappings() {
    let mut pipeline = pipeline();
    let scope = ScopeId("test".to_owned());
    let other = ScopeId("other".to_owned());
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    let other_result = match pipeline.sanitize(&other, "bob@example.com", &context()) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };

    match pipeline.forget(&scope) {
        Ok(()) => {}
        Err(error) => panic!("unexpected error: {error}"),
    }
    match pipeline.restore(&scope, &result.text) {
        Ok(restored) => assert_eq!(restored, result.text),
        Err(error) => panic!("unexpected error: {error}"),
    }
    match pipeline.restore(&other, &other_result.text) {
        Ok(restored) => assert_eq!(restored, "bob@example.com"),
        Err(error) => panic!("unexpected error: {error}"),
    }
}

/// A vault that stores and resolves mappings but never implements deletion, so
/// `delete_scope` stays on the trait default.
struct NonDeletingVault(MemoryVault);

impl Vault for NonDeletingVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        self.0.get_or_insert(scope, kind, original)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        self.0.resolve(scope, token)
    }
}

#[test]
fn unsupported_scope_deletion_fails_closed() {
    // `forget` is a revocation: a backend that cannot delete must say so
    // instead of reporting success while the mapping keeps resolving.
    let mut pipeline = PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(NonDeletingVault(MemoryVault::default())),
    );
    let scope = ScopeId("test".to_owned());
    let result = sanitize_ok(&mut pipeline, "alice@example.com");
    match pipeline.forget(&scope) {
        Err(PipelineError::Vault(_)) => {}
        other => panic!("forget must fail closed, got {other:?}"),
    }
    match pipeline.restore(&scope, &result.text) {
        Ok(restored) => assert_eq!(restored, "alice@example.com"),
        Err(error) => panic!("unexpected error: {error}"),
    }
}

/// A vault that keeps the trait's default `resolve_many` (a per-token loop),
/// like a third-party backend that has not adopted the batch method.
struct DefaultBatchVault(MemoryVault);

impl Vault for DefaultBatchVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        self.0.get_or_insert(scope, kind, original)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        self.0.resolve(scope, token)
    }
}

#[test]
fn restore_works_with_a_vault_that_keeps_the_default_batch_resolution() {
    // `restore` resolves through `Vault::resolve_many`; the default
    // implementation must stay a faithful per-token loop.
    let mut pipeline = PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(DefaultBatchVault(MemoryVault::default())),
    );
    let scope = ScopeId("test".to_owned());
    let result = sanitize_ok(&mut pipeline, "alice@example.com bob@example.com");
    match pipeline.restore(&scope, &result.text) {
        Ok(restored) => assert_eq!(restored, "alice@example.com bob@example.com"),
        Err(error) => panic!("unexpected error: {error}"),
    }
}
