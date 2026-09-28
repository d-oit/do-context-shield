//! Black-box tests for configuration-file discovery and its failure modes.
//!
//! Every test spawns the compiled binary with a hermetic working directory and
//! `$HOME`, so the documented search order (`--config`, then
//! `./do-context-shield.toml`, then `$HOME/.config/do-context-shield/config.toml`)
//! is exercised as a user would hit it.

mod common;

use common::{cmd, temp_dir};
use std::path::{Path, PathBuf};

const LOCAL_CONFIG: &str = "[context]\nrecipient = \"local\"\n";
const EXTERNAL_CONFIG: &str = "[context]\nrecipient = \"external\"\n";

/// Captured stdout as text.
fn stdout_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

/// `sanitize` reading the configuration discovered for `dir`/`home`.
fn sanitize_in(dir: &Path, home: &Path, session: &str) -> String {
    let assert = cmd(dir)
        .env("HOME", home)
        .args(["sanitize", "--session", session])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    stdout_of(&assert)
}

/// Write `content` to `path`, creating parent directories.
fn write_config(path: &Path, content: &[u8]) {
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("cannot create {}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(path, content) {
        panic!("cannot write {}: {error}", path.display());
    }
}

fn home_config(home: &Path) -> PathBuf {
    home.join(".config/do-context-shield/config.toml")
}

#[test]
fn cwd_config_is_discovered() {
    let dir = temp_dir();
    write_config(
        &dir.path().join("do-context-shield.toml"),
        LOCAL_CONFIG.as_bytes(),
    );
    // `recipient = "local"` keeps the address verbatim; the default `external`
    // would pseudonymize it, so the output proves the file was read.
    assert_eq!(
        sanitize_in(dir.path(), dir.path(), "a"),
        "alice@example.com"
    );
}

#[test]
fn home_config_is_discovered() {
    let dir = temp_dir();
    let home = temp_dir();
    write_config(&home_config(home.path()), LOCAL_CONFIG.as_bytes());
    assert_eq!(
        sanitize_in(dir.path(), home.path(), "b"),
        "alice@example.com"
    );
}

#[test]
fn cwd_config_shadows_the_home_config() {
    let dir = temp_dir();
    let home = temp_dir();
    write_config(
        &dir.path().join("do-context-shield.toml"),
        LOCAL_CONFIG.as_bytes(),
    );
    write_config(&home_config(home.path()), EXTERNAL_CONFIG.as_bytes());
    let kept = sanitize_in(dir.path(), home.path(), "c");
    assert_eq!(kept, "alice@example.com", "the cwd file must win");
}

#[test]
fn home_config_applies_when_the_cwd_has_none() {
    let dir = temp_dir();
    let home = temp_dir();
    write_config(&home_config(home.path()), EXTERNAL_CONFIG.as_bytes());
    let pseudonymized = sanitize_in(dir.path(), home.path(), "d");
    assert!(
        pseudonymized.starts_with("__DO_PRIVATE_EMAIL_"),
        "{pseudonymized}"
    );
}

/// A candidate that exists but is not a regular file is a broken setup, not an
/// absent one: it must fail instead of silently falling through to the next
/// candidate (here a valid `$HOME` file that would keep the value).
#[test]
fn directory_candidate_fails_instead_of_falling_through() {
    let dir = temp_dir();
    let home = temp_dir();
    write_config(&home_config(home.path()), LOCAL_CONFIG.as_bytes());
    if let Err(error) = std::fs::create_dir(dir.path().join("do-context-shield.toml")) {
        panic!("cannot create the directory candidate: {error}");
    }
    cmd(dir.path())
        .env("HOME", home.path())
        .args(["sanitize", "--session", "e"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("cannot read config"));
}

#[test]
fn explicit_config_must_exist() {
    let dir = temp_dir();
    cmd(dir.path())
        .args(["sanitize", "--session", "f", "--config"])
        .arg(dir.path().join("missing.toml"))
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("cannot read config"));
}

#[test]
fn unparsable_config_is_an_error() {
    let dir = temp_dir();
    let config = dir.path().join("broken.toml");
    write_config(&config, b"[plugins]\ndetector = \n");
    cmd(dir.path())
        .args(["sanitize", "--session", "g", "--config"])
        .arg(&config)
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("cannot parse config"));
}

#[test]
fn non_utf8_config_is_an_error() {
    let dir = temp_dir();
    let config = dir.path().join("binary.toml");
    write_config(&config, &[0x5b, 0x70, 0x6c, 0xff, 0xfe, 0x0a]);
    cmd(dir.path())
        .args(["sanitize", "--session", "h", "--config"])
        .arg(&config)
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("cannot read config"));
}

#[test]
fn jurisdiction_must_be_an_iso_alpha2_code() {
    let dir = temp_dir();
    for (value, expected) in [("DE", Some("alice@example.com")), ("Germany", None)] {
        write_config(
            &dir.path().join("do-context-shield.toml"),
            format!("[context]\nrecipient = \"local\"\njurisdiction = \"{value}\"\n").as_bytes(),
        );
        let assert = cmd(dir.path())
            .args(["sanitize", "--session", "i"])
            .write_stdin("alice@example.com")
            .assert();
        match expected {
            Some(text) => assert_eq!(stdout_of(&assert.success()), text),
            None => {
                assert
                    .code(1)
                    .stderr(predicates::str::contains("jurisdiction"));
            }
        }
    }
}
