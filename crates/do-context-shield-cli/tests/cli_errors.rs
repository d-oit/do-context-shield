//! Black-box tests for CLI error paths: argument parsing and vault selection.

mod common;

use common::{cmd, temp_dir};

#[test]
fn invalid_subcommand_exits_2() {
    let dir = temp_dir();
    cmd(dir.path())
        .arg("nonsense")
        .write_stdin("")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("unrecognized subcommand"));
}

#[test]
fn invalid_vault_combination_exits_1() {
    let dir = temp_dir();
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s",
            "--vault",
            "memory",
            "--vault-file",
        ])
        .arg(dir.path().join("vault.json"))
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "cannot be combined with a vault file",
        ));
}

#[test]
fn missing_vault_file_for_json_vault_exits_1() {
    let dir = temp_dir();
    cmd(dir.path())
        .args(["sanitize", "--session", "s", "--vault", "json"])
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("requires a vault file"));
}

#[test]
fn session_is_required_exits_2() {
    let dir = temp_dir();
    for command in ["sanitize", "restore", "forget"] {
        cmd(dir.path())
            .arg(command)
            .write_stdin("alice@example.com")
            .assert()
            .code(2)
            .stderr(predicates::str::contains("--session"));
    }
}
