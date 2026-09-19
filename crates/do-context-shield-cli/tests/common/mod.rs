//! Helpers shared by the binary-level CLI integration tests.

use std::path::Path;

/// The compiled `do-context-shield` binary, started with a hermetic working
/// directory and `$HOME` so an ambient `do-context-shield.toml` or
/// `$HOME/.config/do-context-shield/config.toml` can never change a test.
pub fn cmd(dir: &Path) -> assert_cmd::Command {
    let mut command = match assert_cmd::Command::cargo_bin("do-context-shield") {
        Ok(command) => command,
        Err(error) => panic!("binary `do-context-shield` is not built: {error}"),
    };
    command.current_dir(dir).env("HOME", dir);
    command
}

/// Fresh temporary directory, removed when the returned handle is dropped.
pub fn temp_dir() -> tempfile::TempDir {
    match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    }
}
