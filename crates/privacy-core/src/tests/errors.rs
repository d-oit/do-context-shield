use super::*;

struct LeakingDetector;

impl Detector for LeakingDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        Err(DetectorError::Message(format!("cannot parse `{input}`")))
    }
}

#[test]
fn leaking_detector_error_is_scrubbed() {
    let mut pipeline = PrivacyPipeline::new(
        Box::new(LeakingDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let error = sanitize_err(&mut pipeline, "alice@example.com");
    let text = error.to_string();
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
}

struct LeakingJudge;

impl SemanticJudge for LeakingJudge {
    fn judge(&self, _input: &str, entities: &[Entity]) -> Result<Vec<Judgment>, JudgeError> {
        let value = entities
            .first()
            .map_or("nothing", |entity| entity.value.as_str());
        Err(JudgeError::Message(format!("cannot classify `{value}`")))
    }
}

#[test]
fn leaking_judge_error_is_scrubbed() {
    // The judge echoes a detected value, not the whole input, so only the
    // entity-value scrub can hide it.
    let mut pipeline = pipeline().with_judge(Box::new(LeakingJudge));
    let error = sanitize_err(&mut pipeline, "contact alice@example.com");
    let text = error.to_string();
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
}

struct LeakingVault;

impl Vault for LeakingVault {
    fn get_or_insert(
        &mut self,
        _scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        Err(VaultError::Message(format!(
            "cannot store `{original}` as {kind}"
        )))
    }

    fn resolve(&self, _scope: &ScopeId, _token: &str) -> Result<Option<Mapping>, VaultError> {
        Ok(None)
    }
}

#[test]
fn leaking_vault_error_is_scrubbed() {
    let mut pipeline = PrivacyPipeline::new(
        Box::new(FixedDetector(vec![entity(
            "email",
            8,
            25,
            "alice@example.com",
        )])),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(LeakingVault),
    );
    let error = sanitize_err(&mut pipeline, "contact alice@example.com");
    let text = error.to_string();
    assert!(!text.contains("alice@example.com"), "{text}");
    assert!(text.contains("[redacted]"), "{text}");
}
