//! Black-box tests for `do-context-shield.toml` handling and CLI merges.

mod common;

use common::{cmd, temp_dir};
use std::ffi::OsString;
use std::path::Path;

/// `sanitize --session cfg-test` with the given CLI arguments, `input` on stdin.
fn sanitize(dir: &Path, args: &[OsString], input: &str) -> String {
    let assert = cmd(dir)
        .args(["sanitize", "--session", "cfg-test"])
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

/// `path` as a TOML basic-string literal: backslashes are escape characters,
/// so Windows paths must be doubled or TOML fails with a unicode-escape error.
fn toml_literal(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

#[test]
fn config_file_selects_plugins() {
    let dir = temp_dir();
    let vault = dir.path().join("judged.json");
    let config = dir.path().join("config.toml");
    write_config(
        &config,
        &format!(
            "[plugins]\njudge = \"heuristics\"\n\n[vault]\nvault_file = {}\n",
            toml_literal(&vault)
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
    common::assert_placeholder(&control, "EMAIL", 1);
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
        .args(["--session", "cfg-test"])
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
    common::assert_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn cwd_config_is_discovered_without_a_flag() {
    let dir = temp_dir();
    write_config(
        &dir.path().join("do-context-shield.toml"),
        "[context]\nrecipient = \"local\"\n",
    );

    // `--recipient local` keeps a personal value; observing the keep without
    // any flag proves the working-directory file was found and applied.
    let kept = sanitize(dir.path(), &[], "alice@example.com");
    assert_eq!(kept, "alice@example.com");
}

#[test]
fn home_config_is_discovered_when_the_working_directory_has_none() {
    let dir = temp_dir();
    let home = dir.path().join(".config/do-context-shield");
    if let Err(error) = std::fs::create_dir_all(&home) {
        panic!("cannot create {}: {error}", home.display());
    }
    write_config(
        &home.join("config.toml"),
        "[context]\nrecipient = \"local\"\n",
    );

    let kept = sanitize(dir.path(), &[], "alice@example.com");
    assert_eq!(kept, "alice@example.com");
}

#[test]
fn cwd_config_wins_over_the_home_config() {
    let dir = temp_dir();
    let home = dir.path().join(".config/do-context-shield");
    if let Err(error) = std::fs::create_dir_all(&home) {
        panic!("cannot create {}: {error}", home.display());
    }
    // The home file would block the call, so the keep below is the
    // working-directory file's value.
    write_config(
        &home.join("config.toml"),
        "[context]\nrecipient = \"unknown\"\n",
    );
    write_config(
        &dir.path().join("do-context-shield.toml"),
        "[context]\nrecipient = \"local\"\n",
    );

    let kept = sanitize(dir.path(), &[], "alice@example.com");
    assert_eq!(kept, "alice@example.com");
}
