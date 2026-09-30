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

#[test]
fn env_override_beats_the_file_value() {
    let dir = temp_dir();
    let vault = dir.path().join("env.json");
    write_config(
        &dir.path().join("do-context-shield.toml"),
        "[plugins]\ndetector = \"gliner2\"\n",
    );

    // Control: the file's `gliner2` has no local model and fails closed, so
    // the successful run below is the environment override's doing.
    cmd(dir.path())
        .args(["sanitize", "--session", "cfg-test", "--vault-file"])
        .arg(&vault)
        .write_stdin("alice@example.com")
        .assert()
        .failure();

    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_DETECTOR", "regex")
        .args(["sanitize", "--session", "cfg-test", "--vault-file"])
        .arg(&vault)
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn cli_flag_overrides_env_override() {
    let dir = temp_dir();
    let vault = dir.path().join("flag.json");

    // `gliner2` from the environment cannot run without a model, so this only
    // succeeds if `--detector regex` wins over the environment value.
    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_DETECTOR", "gliner2")
        .args([
            "sanitize",
            "--session",
            "cfg-test",
            "--detector",
            "regex",
            "--vault-file",
        ])
        .arg(&vault)
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn invalid_env_override_exits_nonzero() {
    let dir = temp_dir();
    cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_POLICY", "bogus")
        .args(["sanitize", "--session", "cfg-test"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("DO_CONTEXT_SHIELD_POLICY"));
}

#[test]
fn environment_context_precedence_changes_policy_outcome() {
    let dir = temp_dir();
    write_config(
        &dir.path().join("do-context-shield.toml"),
        "[context]\nrecipient = \"external\"\n",
    );

    // The environment value beats the file value; a kept value (not a token)
    // is the policy outcome only a `local` recipient produces.
    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_RECIPIENT", "local")
        .args(["sanitize", "--session", "cfg-test"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let kept = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert_eq!(kept, "alice@example.com");

    // The CLI flag still beats the environment: explicit `external` mints.
    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_RECIPIENT", "local")
        .args([
            "sanitize",
            "--session",
            "cfg-test",
            "--recipient",
            "external",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn invalid_context_environment_fails_closed() {
    let dir = temp_dir();
    // Each variable is checked before any plugin runs; the jurisdiction case
    // keeps the configuration diagnostic (the environment layer feeds the
    // same `[context]` validation the file uses).
    for (name, value, diagnostic) in [
        ("DO_CONTEXT_SHIELD_RECIPIENT", "nope", "recipient"),
        ("DO_CONTEXT_SHIELD_DATA_CATEGORY", "nope", "data_category"),
        (
            "DO_CONTEXT_SHIELD_JURISDICTION",
            "Germany",
            "ISO 3166-1 alpha-2",
        ),
    ] {
        let assert = cmd(dir.path())
            .env(name, value)
            .args(["sanitize", "--session", "cfg-test"])
            .write_stdin("alice@example.com")
            .assert()
            .code(1)
            .stderr(predicates::str::contains(diagnostic));
        let output = assert.get_output();
        assert!(
            output.stdout.is_empty(),
            "invalid {name} produced sanitized output"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("alice@example.com"),
            "stdin leaked for {name}"
        );
    }
}

#[test]
fn environment_data_category_reaches_policy() {
    let dir = temp_dir();
    // The default recipient is `external`, so a special-category environment
    // value blocks the call instead of pseudonymizing it.
    cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_DATA_CATEGORY", "special_category")
        .args(["sanitize", "--session", "cfg-test"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("blocked by policy"));

    // The flag override restores the documented pseudonymization.
    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_DATA_CATEGORY", "special_category")
        .args([
            "sanitize",
            "--session",
            "cfg-test",
            "--data-category",
            "personal",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_placeholder(&sanitized, "EMAIL", 1);
}

#[test]
fn environment_selects_non_reversible_transform_and_judge() {
    let dir = temp_dir();
    // `generalize` emits kind-only tokens; the bare placeholder proves the
    // transformer environment value was selected over the pseudonymizing
    // default.
    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_TRANSFORMER", "generalize")
        .args(["sanitize", "--session", "cfg-test"])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        "__DO_PRIVATE_EMAIL__"
    );

    // `heuristics` keeps the reserved-domain address; without a judge the
    // same address pseudonymizes.
    let assert = cmd(dir.path())
        .env("DO_CONTEXT_SHIELD_JUDGE", "heuristics")
        .args(["sanitize", "--session", "cfg-test"])
        .write_stdin("test@example.com")
        .assert()
        .success();
    assert_eq!(
        String::from_utf8_lossy(&assert.get_output().stdout),
        "test@example.com"
    );

    let assert = cmd(dir.path())
        .args(["sanitize", "--session", "cfg-test"])
        .write_stdin("test@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    common::assert_placeholder(&sanitized, "EMAIL", 1);
}
