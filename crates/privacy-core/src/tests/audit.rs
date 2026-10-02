use super::*;

use do_context_shield_plugin_api::AuditOperation;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct RecordingAuditSink(Arc<Mutex<Vec<AuditEvent>>>);

impl AuditSink for RecordingAuditSink {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        match self.0.lock() {
            Ok(mut events) => {
                events.push(event.clone());
                Ok(())
            }
            Err(error) => Err(AuditError::Message(format!(
                "recording sink mutex poisoned: {error}"
            ))),
        }
    }
}

fn audited_pipeline(events: &Arc<Mutex<Vec<AuditEvent>>>) -> PrivacyPipeline {
    pipeline().with_audit_sink(Box::new(RecordingAuditSink(Arc::clone(events))))
}

fn recorded_events(events: &Arc<Mutex<Vec<AuditEvent>>>) -> Vec<AuditEvent> {
    match events.lock() {
        Ok(events) => events.clone(),
        Err(error) => panic!("audit event lock poisoned: {error}"),
    }
}

#[test]
fn sanitize_records_action_counts_without_values_or_purpose() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut pipeline = audited_pipeline(&events);
    let scope = ScopeId("audit-scope".to_owned());
    let mut context = context();
    context.purpose = Some("audit-fixture-purpose".to_owned());
    let input = "alice@example.com and alice@example.com token=s3cr3t-value-1234";

    let result = match pipeline.sanitize(&scope, input, &context) {
        Ok(result) => result,
        Err(error) => panic!("unexpected sanitize failure: {error}"),
    };
    assert!(result.text.contains("__DO_PRIVATE_REDACTED__"));
    assert!(!result.text.contains("alice@example.com"));
    assert!(!result.text.contains("s3cr3t-value-1234"));

    let events = recorded_events(&events);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.operation, AuditOperation::Sanitize);
    assert_eq!(event.outcome, AuditOutcome::Ok);
    assert_eq!(event.session, "audit-scope");
    let email_count = event.actions.iter().find(|count| count.kind == "email");
    assert!(
        email_count
            .is_some_and(|count| { count.action == Action::Pseudonymize && count.count == 2 })
    );
    let secret_count = event
        .actions
        .iter()
        .find(|count| count.kind == "generic_secret");
    assert!(
        secret_count.is_some_and(|count| { count.action == Action::Redact && count.count == 1 })
    );
    let rendered = format!("{event:?}");
    assert!(!rendered.contains("alice@example.com"));
    assert!(!rendered.contains("s3cr3t-value-1234"));
    assert!(!rendered.contains("audit-fixture-purpose"));
    assert!(!rendered.contains(&first_placeholder(&result.text)));
}

#[test]
fn policy_block_is_recorded_before_the_error_returns() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut pipeline = audited_pipeline(&events);
    let mut enforcement = context();
    enforcement.recipient = do_context_shield_plugin_api::RecipientClass::Unknown;
    let error = match pipeline.sanitize(
        &ScopeId("test".to_owned()),
        "alice@example.com",
        &enforcement,
    ) {
        Ok(result) => panic!("expected policy block, got {result:?}"),
        Err(error) => error,
    };

    assert!(matches!(error, PipelineError::Policy(_)), "{error:?}");
    let events = recorded_events(&events);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].operation, AuditOperation::Sanitize);
    assert_eq!(events[0].outcome, AuditOutcome::Blocked);
    assert_eq!(events[0].session, "test");
}

#[test]
fn restore_and_forget_events_keep_scope_and_prior_history() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut pipeline = audited_pipeline(&events);
    let first_scope = ScopeId("audit-a".to_owned());
    let second_scope = ScopeId("audit-b".to_owned());
    let first = match pipeline.sanitize(&first_scope, "alice@example.com", &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected sanitize failure: {error}"),
    };
    let second = match pipeline.sanitize(&second_scope, "bob@example.com", &context()) {
        Ok(result) => result,
        Err(error) => panic!("unexpected sanitize failure: {error}"),
    };

    match pipeline.restore(&first_scope, &first.text) {
        Ok(restored) => assert_eq!(restored, "alice@example.com"),
        Err(error) => panic!("unexpected restore failure: {error}"),
    }
    match pipeline.restore(&second_scope, &first.text) {
        Ok(unresolved) => assert_eq!(unresolved, first.text),
        Err(error) => panic!("unexpected cross-scope restore failure: {error}"),
    }
    match pipeline.forget(&first_scope) {
        Ok(()) => {}
        Err(error) => panic!("unexpected forget failure: {error}"),
    }
    match pipeline.restore(&first_scope, &first.text) {
        Ok(unresolved) => assert_eq!(unresolved, first.text),
        Err(error) => panic!("unexpected post-forget restore failure: {error}"),
    }
    match pipeline.restore(&second_scope, &second.text) {
        Ok(restored) => assert_eq!(restored, "bob@example.com"),
        Err(error) => panic!("unexpected second-scope restore failure: {error}"),
    }

    let events = recorded_events(&events);
    assert_eq!(events.len(), 7);
    assert_eq!(events[0].operation, AuditOperation::Sanitize);
    assert_eq!(events[1].operation, AuditOperation::Sanitize);
    assert_eq!(events[2].operation, AuditOperation::Restore);
    assert_eq!(events[2].session, "audit-a");
    assert_eq!(events[2].resolved, Some(1));
    assert_eq!(events[3].operation, AuditOperation::Restore);
    assert_eq!(events[3].session, "audit-b");
    assert_eq!(events[3].resolved, Some(0));
    assert_eq!(events[4].operation, AuditOperation::Forget);
    assert_eq!(events[4].session, "audit-a");
    assert_eq!(events[5].operation, AuditOperation::Restore);
    assert_eq!(events[5].resolved, Some(0));
    assert_eq!(events[6].operation, AuditOperation::Restore);
    assert_eq!(events[6].session, "audit-b");
    assert_eq!(events[6].resolved, Some(1));
}

struct FailRestoreWithOriginal(String);

impl AuditSink for FailRestoreWithOriginal {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        if event.operation == AuditOperation::Restore {
            Err(AuditError::Message(format!(
                "restore audit failed while handling original {}",
                self.0
            )))
        } else {
            Ok(())
        }
    }
}

#[test]
fn restore_audit_error_scrubs_resolved_original_from_long_diagnostic() {
    let original = "alice@example.com";
    let mut pipeline =
        pipeline().with_audit_sink(Box::new(FailRestoreWithOriginal(original.to_owned())));
    let sanitized = sanitize_ok(&mut pipeline, original);
    let error = match pipeline.restore(&ScopeId("test".to_owned()), &sanitized.text) {
        Ok(restored) => panic!("expected audit refusal, got {restored}"),
        Err(error) => error,
    };

    assert!(matches!(error, PipelineError::Audit(_)), "{error:?}");
    assert!(!error.to_string().contains(original), "{error}");
    assert!(error.to_string().contains("[redacted]"), "{error}");
}

struct FailOnceSink {
    operation: AuditOperation,
    failed: bool,
}

impl AuditSink for FailOnceSink {
    fn record(&mut self, event: &AuditEvent) -> Result<(), AuditError> {
        if event.operation == self.operation && !self.failed {
            self.failed = true;
            Err(AuditError::Message("synthetic audit refusal".to_owned()))
        } else {
            Ok(())
        }
    }
}

struct CountingVault {
    inner: MemoryVault,
    insertions: Arc<AtomicUsize>,
}

impl Vault for CountingVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<do_context_shield_plugin_api::Mapping, VaultError> {
        let mapping = self.inner.get_or_insert(scope, kind, original)?;
        self.insertions.fetch_add(1, Ordering::Relaxed);
        Ok(mapping)
    }

    fn resolve(
        &self,
        scope: &ScopeId,
        token: &str,
    ) -> Result<Option<do_context_shield_plugin_api::Mapping>, VaultError> {
        self.inner.resolve(scope, token)
    }

    fn delete_scope(&mut self, scope: &ScopeId) -> Result<(), VaultError> {
        self.inner.delete_scope(scope)
    }
}

#[test]
fn audit_refusal_withholds_results_after_vault_side_effects() {
    let insertions = Arc::new(AtomicUsize::new(0));
    let mut sanitize_pipeline = PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(CountingVault {
            inner: MemoryVault::default(),
            insertions: Arc::clone(&insertions),
        }),
    )
    .with_audit_sink(Box::new(FailOnceSink {
        operation: AuditOperation::Sanitize,
        failed: false,
    }));
    let sanitize_error = match sanitize_pipeline.sanitize(
        &ScopeId("test".to_owned()),
        "alice@example.com",
        &context(),
    ) {
        Ok(result) => panic!("expected audit refusal, got {result:?}"),
        Err(error) => error,
    };
    assert!(matches!(sanitize_error, PipelineError::Audit(_)));
    assert!(insertions.load(Ordering::Relaxed) > 0);

    let mut restore_pipeline = pipeline().with_audit_sink(Box::new(FailOnceSink {
        operation: AuditOperation::Restore,
        failed: false,
    }));
    let sanitized = sanitize_ok(&mut restore_pipeline, "alice@example.com");
    let restore_error = match restore_pipeline.restore(&ScopeId("test".to_owned()), &sanitized.text)
    {
        Ok(restored) => panic!("expected audit refusal, got {restored}"),
        Err(error) => error,
    };
    assert!(matches!(restore_error, PipelineError::Audit(_)));
    match restore_pipeline.restore(&ScopeId("test".to_owned()), &sanitized.text) {
        Ok(restored) => assert_eq!(restored, "alice@example.com"),
        Err(error) => panic!("restore mapping was not retained: {error}"),
    }

    let mut forget_pipeline = pipeline().with_audit_sink(Box::new(FailOnceSink {
        operation: AuditOperation::Forget,
        failed: false,
    }));
    let forgotten = sanitize_ok(&mut forget_pipeline, "alice@example.com");
    let forget_error = match forget_pipeline.forget(&ScopeId("test".to_owned())) {
        Ok(()) => panic!("expected audit refusal after deletion"),
        Err(error) => error,
    };
    assert!(matches!(forget_error, PipelineError::Audit(_)));
    match forget_pipeline.restore(&ScopeId("test".to_owned()), &forgotten.text) {
        Ok(unresolved) => assert_eq!(unresolved, forgotten.text),
        Err(error) => panic!("unexpected restore failure after forget: {error}"),
    }
}
