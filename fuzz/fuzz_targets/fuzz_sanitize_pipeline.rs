#![no_main]

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{
    DataCategory, ProcessingContext, RecipientClass, ScopeId, is_secret_kind,
};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split first byte for context parameters selection
    let (head, rest) = data.split_at(1);
    let ctx_selector = head[0];

    let recipient = match ctx_selector & 0b11 {
        0 => RecipientClass::Local,
        1 => RecipientClass::Trusted,
        2 => RecipientClass::External,
        _ => RecipientClass::Unknown,
    };

    let category = match (ctx_selector >> 2) & 0b11 {
        0 => DataCategory::NonPersonal,
        1 => DataCategory::Personal,
        _ => DataCategory::SpecialCategory,
    };

    let lossy_input;
    let input: &str = match std::str::from_utf8(rest) {
        Ok(valid_utf8) => valid_utf8,
        Err(_) => {
            lossy_input = String::from_utf8_lossy(rest);
            &lossy_input
        }
    };

    let detector = Box::new(RegexDetector);
    let policy = Box::new(DefaultPolicy);
    let transformer = Box::new(PseudonymizingTransformer);
    let vault = Box::new(MemoryVault::default());

    let mut pipeline = PrivacyPipeline::new(detector, policy, transformer, vault);
    let scope = ScopeId("fuzz-session".to_owned());
    let mut context = ProcessingContext::default();
    context.recipient = recipient;
    context.data_category = category;
    context.jurisdiction = Some("US".to_owned());

    if let Ok(result) = pipeline.sanitize(&scope, input, &context) {
        // Redaction invariant: If a secret-kind entity was detected and pipeline succeeded (redact action),
        // the original secret value must NOT appear in the sanitized text.
        for summary in &result.entities {
            if is_secret_kind(&summary.kind) {
                let original_secret = &input[summary.start..summary.end];
                if !original_secret.is_empty() {
                    assert!(
                        !result.text.contains(original_secret),
                        "Sanitized output contains raw secret value `{}` of kind `{}`",
                        original_secret,
                        summary.kind
                    );
                }
            }
        }
    }
});
