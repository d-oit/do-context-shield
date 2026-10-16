#![no_main]

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_mcp_server::handle_request_for_fuzzing;
use do_context_shield_mcp_server::ToolSet;
use do_context_shield_plugin_api::ProcessingContext;
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_memory::MemoryVault;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let detector = Box::new(RegexDetector);
        let policy = Box::new(DefaultPolicy);
        let transformer = Box::new(PseudonymizingTransformer);
        let vault = Box::new(MemoryVault::default());
        let mut pipeline = PrivacyPipeline::new(detector, policy, transformer, vault);
        let tools = ToolSet::all();
        let default_context = ProcessingContext::default();

        let _ = handle_request_for_fuzzing(&mut pipeline, tools, &default_context, line);
    }
});
