//! Helpers shared by the process plugin protocol tests.

/// Command line invoking the fixture in `mode`.
pub fn command(mode: &str) -> String {
    format!(
        "sh {} {mode}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plugin.sh")
    )
}
