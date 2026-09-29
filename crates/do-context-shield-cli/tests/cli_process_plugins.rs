//! Black-box tests for the documented process-plugin selections.
//!
//! `--<capability> process --<capability>-command <program>` must run the
//! configured local executable through the compiled binary: the child's answer
//! decides the output, and a child that is missing, unusable, or too slow fails
//! the call closed instead of silently falling back to a built-in plugin.

mod common;

use common::{cmd, process_command, temp_dir};
use std::path::Path;
use std::time::{Duration, Instant};

/// `sanitize --session <session> <extra…>`, `input` on stdin; stdout on success.
fn sanitize(dir: &Path, session: &str, extra: &[&str], input: &str) -> String {
    let assert = cmd(dir)
        .args(["sanitize", "--session", session])
        .args(extra)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

#[test]
fn detector_process_selection_drives_detection() {
    let dir = temp_dir();
    let command = process_command("detect-two");
    // `detect-two` reports `email` 0..5 plus `phone` 6..17, while the built-in
    // regex detector reports the whole address as one `email` span: only the
    // process child produces this pair of placeholders.
    let sanitized = sanitize(
        dir.path(),
        "proc",
        &[
            "--detector",
            "process",
            "--detector-command",
            command.as_str(),
        ],
        "alice@example.com",
    );
    let Some((local_part, domain_part)) = sanitized.split_once('@') else {
        panic!("no `@` separator in `{sanitized}`");
    };
    common::assert_placeholder(local_part, "EMAIL", 1);
    common::assert_placeholder(domain_part, "PHONE", 1);
}

#[test]
fn detector_process_failure_fails_closed() {
    let dir = temp_dir();
    let command = process_command("junk");
    // A built-in fallback would sanitize this address happily; the selected
    // child answered garbage, so the call must stop.
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "proc",
            "--detector",
            "process",
            "--detector-command",
        ])
        .arg(&command)
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "process detector returned invalid JSON",
        ));
}

#[test]
fn policy_process_selection_drives_the_plan() {
    let dir = temp_dir();
    let command = process_command("plan-two");
    // `plan-two` pseudonymizes the first entity and redacts the second; the
    // built-in policy would pseudonymize both.
    let sanitized = sanitize(
        dir.path(),
        "proc",
        &["--policy", "process", "--policy-command", command.as_str()],
        "alice@example.com bob@example.com",
    );
    let Some((kept, redacted)) = sanitized.split_once(' ') else {
        panic!("no space separator in `{sanitized}`");
    };
    common::assert_placeholder(kept, "EMAIL", 1);
    assert_eq!(redacted, "__DO_PRIVATE_REDACTED__");
}

#[test]
fn transformer_process_selection_drives_the_output() {
    let dir = temp_dir();
    let transformer = process_command("transform-wrapped");
    let vault = process_command("vault-ok");
    // The child wraps the token it minted; the built-in transformer would emit
    // the bare token, and the paired process vault is what resolves it.
    let sanitized = sanitize(
        dir.path(),
        "s1",
        &[
            "--transformer",
            "process",
            "--transformer-command",
            transformer.as_str(),
            "--vault",
            "process",
            "--vault-command",
            vault.as_str(),
        ],
        "alice@example.com",
    );
    assert_eq!(sanitized, "<<__DO_PRIVATE_EMAIL_1__>>");
}

#[test]
fn transformer_process_leftover_value_fails_closed() {
    let dir = temp_dir();
    let transformer = process_command("transform-leak");
    let vault = process_command("vault-ok");
    // A built-in transformer never leaves the planned value behind; the
    // selected child does, so the call must stop.
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "s1",
            "--transformer",
            "process",
            "--transformer-command",
        ])
        .arg(&transformer)
        .args(["--vault", "process", "--vault-command"])
        .arg(&vault)
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "still contains the value of kind",
        ));
}

#[test]
fn vault_process_selection_drives_token_minting() {
    let dir = temp_dir();
    let command = process_command("vault-ok");
    // `vault-ok` holds exactly `__DO_PRIVATE_EMAIL_1__` for scope `s1`; the
    // built-in vaults mint 16 hex characters of entropy per mapping.
    let sanitized = sanitize(
        dir.path(),
        "s1",
        &["--vault", "process", "--vault-command", command.as_str()],
        "alice@example.com",
    );
    assert_eq!(sanitized, "__DO_PRIVATE_EMAIL_1__");
}

#[test]
fn missing_process_command_fails_at_startup() {
    let dir = temp_dir();
    // Plain input keeps the policy, judge, and vault uninvoked, so a plugin
    // that only failed on its first call would still exit 0 here.
    for (flag, capability) in [
        ("--detector", "detector"),
        ("--judge", "judge"),
        ("--policy", "policy"),
        ("--transformer", "transformer"),
        ("--vault", "vault"),
    ] {
        cmd(dir.path())
            .args(["sanitize", "--session", "proc", flag, "process"])
            .write_stdin("hello world")
            .assert()
            .code(1)
            .stderr(predicates::str::contains(format!(
                "process {capability} unavailable (no command configured)"
            )));
    }
}

#[test]
fn process_timeout_flag_bounds_each_call() {
    let dir = temp_dir();
    // A plain `sleep` keeps the hanging child a single process: the fixture's
    // `hang` mode runs `sleep` under a shell, and on Windows the surviving
    // descendant delays the test harness's pipe drain, not the CLI.
    let started = Instant::now();
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "proc",
            "--policy",
            "process",
            "--policy-command",
            "sleep 30",
        ])
        .args(["--process-timeout-ms", "200"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "process policy timed out after 200 ms",
        ));
    // The default is 30 000 ms; honoring the flag is what keeps this bounded.
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}
