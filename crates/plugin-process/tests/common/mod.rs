//! Helpers shared by the process plugin protocol tests.

use do_context_shield_plugin_process::ProcessCommand;

/// Structured command invoking the fixture in `mode`.
pub fn command(mode: &str) -> ProcessCommand {
    ProcessCommand::new(
        "sh",
        [
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plugin.sh"),
            mode,
        ],
    )
}
