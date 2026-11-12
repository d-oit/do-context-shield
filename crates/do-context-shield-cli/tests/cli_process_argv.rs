//! Black-box tests for structured process argv failure behavior.

mod common;

use common::{cmd, temp_dir};
#[test]
fn incomplete_process_argv_is_rejected_before_reading_input() {
    let dir = temp_dir();
    let output = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "incomplete",
            "--detector-arg",
            "SECRET-ARG",
        ])
        .write_stdin("SECRET-INPUT")
        .assert()
        .code(2)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--detector-program"), "{stderr}");
    assert!(!stderr.contains("SECRET-ARG"), "{stderr}");
    assert!(!stderr.contains("SECRET-INPUT"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn empty_process_program_is_rejected_without_echoing_input() {
    let dir = temp_dir();
    let output = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "empty-program",
            "--detector-program",
            "",
        ])
        .write_stdin("SECRET-INPUT")
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("`--detector-program` must not be empty"),
        "{stderr}"
    );
    assert!(!stderr.contains("SECRET-INPUT"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn removed_command_flag_has_a_precise_safe_migration_error() {
    let dir = temp_dir();
    let output = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "legacy-flag",
            "--detector-command",
            "SECRET-PLUGIN --token SECRET-ARG",
        ])
        .write_stdin("SECRET-INPUT")
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "`--detector-command` was removed; use `--detector-program` and repeat `--detector-arg`"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("SECRET-PLUGIN"), "{stderr}");
    assert!(!stderr.contains("SECRET-ARG"), "{stderr}");
    assert!(!stderr.contains("SECRET-INPUT"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn removed_config_command_has_a_precise_safe_migration_error() {
    let dir = temp_dir();
    common::write_config(
        &dir.path().join("legacy.toml"),
        "[plugins]\ndetector = \"process\"\ndetector_command = \"SECRET-PLUGIN --token SECRET-ARG\"\n",
    );
    let output = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "legacy-config",
            "--config",
            "legacy.toml",
        ])
        .write_stdin("SECRET-INPUT")
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "`plugins.detector_command` was removed; use `[process_plugins.detector]` with separate `program` and `args`"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("SECRET-PLUGIN"), "{stderr}");
    assert!(!stderr.contains("SECRET-ARG"), "{stderr}");
    assert!(!stderr.contains("SECRET-INPUT"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn missing_process_executable_fails_closed_without_echoing_input_or_path() {
    let dir = temp_dir();
    let program = dir.path().join("SECRET-MISSING-EXECUTABLE");
    let Some(program) = program.to_str() else {
        panic!("temp executable path is not valid UTF-8");
    };
    let output = cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "missing-program",
            "--detector",
            "process",
            "--detector-program",
            program,
        ])
        .write_stdin("SECRET-INPUT")
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("process detector failed to start"),
        "{stderr}"
    );
    assert!(!stderr.contains(program), "{stderr}");
    assert!(!stderr.contains("SECRET-INPUT"), "{stderr}");
    assert!(output.stdout.is_empty());
}
