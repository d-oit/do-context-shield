//! Black-box tests for `do-context-shield.toml` handling and CLI merges.

mod common;

use common::{cmd, temp_dir};
use std::ffi::OsString;
use std::path::Path;

/// `sanitize` with the given CLI arguments, `input` on stdin.
fn sanitize(dir: &Path, args: &[OsString], input: &str) -> String {
    let assert = cmd(dir)
        .arg("sanitize")
        .args(args)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// Write `content` to `path`, naming the path on failure.
fn write_config(path: &Path, content: &str) {
    if let Err(error) = std::fs::write(path, content) {
        panic!("cannot write {}: {error}", path.display());
    }
}

#[test]
fn config_file_selects_plugins() {
    let dir = temp_dir();
    let vault = dir.path().join("judged.json");
    let config = dir.path().join("config.toml");
    write_config(
        &config,
        &format!(
            "[plugins]\njudge = \"heuristics\"\n\n[vault]\nvault_file = \"{}\"\n",
            vault.display()
        ),
    );

    // `example.com` is a reserved documentation domain, so the heuristic judge
    // labels the address `Test` and the default policy keeps it.
    let configured = sanitize(
        dir.path(),
        &[OsString::from("--config"), config.into()],
        "test@example.com",
    );
    assert_eq!(configured, "test@example.com");

    // Control: without the configured judge the same address pseudonymizes, so
    // the keep above is the configuration file's doing.
    let control = sanitize(
        dir.path(),
        &[OsString::from("--vault-file"), vault.into()],
        "test@example.com",
    );
    assert_eq!(control, "__DO_PRIVATE_EMAIL_1__");
}

#[test]
fn config_unknown_field_exits_nonzero() {
    let dir = temp_dir();
    let config = dir.path().join("bad.toml");
    write_config(&config, "[plugins]\nunknown_field = \"x\"\n");

    cmd(dir.path())
        .arg("--config")
        .arg(&config)
        .arg("sanitize")
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("unknown field"));
}

#[test]
fn cli_flag_overrides_config() {
    let dir = temp_dir();
    let vault = dir.path().join("overridden.json");
    let config = dir.path().join("config.toml");
    write_config(&config, "[plugins]\ndetector = \"gliner2\"\n");

    // The config file alone would select the Gliner2 detector, which has no
    // local model here, so the run only reaches this output if `--detector`
    // regex won the merge over the file value.
    let sanitized = sanitize(
        dir.path(),
        &[
            OsString::from("--config"),
            config.into(),
            OsString::from("--detector"),
            OsString::from("regex"),
            OsString::from("--vault-file"),
            vault.into(),
        ],
        "alice@example.com",
    );
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");
}
