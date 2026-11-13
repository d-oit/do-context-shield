//! Black-box tests for the documented structured process-plugin selections.
//!
//! `--<capability>-program` and repeated `--<capability>-arg` flags are passed
//! literally to the selected local executable; a child failure never falls
//! back to a built-in plugin.

mod common;

use common::{cmd, temp_dir};
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};

/// `sanitize --session <session> <extra…>`, `input` on stdin; stdout on success.
fn sanitize<I, S>(dir: &Path, session: &str, extra: I, input: &str) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let assert = cmd(dir)
        .args(["sanitize", "--session", session])
        .args(extra)
        .write_stdin(input)
        .assert()
        .success();
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn process_selection(capability: &str, mode: &str) -> Vec<String> {
    let mut args = vec![format!("--{capability}"), "process".to_owned()];
    args.extend(common::process_plugin_args(capability, mode));
    args
}

#[test]
fn detector_process_selection_drives_detection() {
    let dir = temp_dir();
    // `detect-two` reports `email` 0..5 plus `phone` 6..17, while the built-in
    // regex detector reports the whole address as one `email` span: only the
    // process child produces this pair of placeholders.
    let sanitized = sanitize(
        dir.path(),
        "proc",
        process_selection("detector", "detect-two"),
        "alice@example.com",
    );
    let Some((local_part, domain_part)) = sanitized.split_once('@') else {
        panic!("no `@` separator in `{sanitized}`");
    };
    common::assert_placeholder(local_part, "EMAIL", 1);
    common::assert_placeholder(domain_part, "PHONE", 1);
}

#[test]
fn detector_process_zero_entities_without_text_signal_fails_closed() {
    let dir = temp_dir();
    cmd(dir.path())
        .args(["sanitize", "--session", "proc"])
        .args(process_selection("detector", "detect-zero"))
        .write_stdin("secret@example.com\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "process detector returned zero entities without completion text signal",
        ));
}

#[test]
fn detector_process_zero_entities_with_text_signal_succeeds() {
    let dir = temp_dir();
    let sanitized = sanitize(
        dir.path(),
        "proc",
        process_selection("detector", "detect-clean"),
        "hello world\n",
    );
    assert_eq!(sanitized, "hello world\n");
}

#[test]
fn detector_process_failure_fails_closed() {
    let dir = temp_dir();
    // A built-in fallback would sanitize this address happily; the selected
    // child answered garbage, so the call must stop.
    cmd(dir.path())
        .args(["sanitize", "--session", "proc"])
        .args(process_selection("detector", "junk"))
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
    // `plan-two` pseudonymizes the first entity and redacts the second; the
    // built-in policy would pseudonymize both.
    let sanitized = sanitize(
        dir.path(),
        "proc",
        process_selection("policy", "plan-two"),
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
    let mut args = process_selection("transformer", "transform-wrapped");
    args.extend(process_selection("vault", "vault-ok"));
    // The child wraps the token it minted; the built-in transformer would emit
    // the bare token, and the paired process vault is what resolves it.
    let sanitized = sanitize(dir.path(), "s1", args, "alice@example.com");
    assert_eq!(sanitized, "<<__DO_PRIVATE_EMAIL_1__>>");
}

#[test]
fn transformer_process_leftover_value_fails_closed() {
    let dir = temp_dir();
    let mut args = process_selection("transformer", "transform-leak");
    args.extend(process_selection("vault", "vault-ok"));
    // A built-in transformer never leaves the planned value behind; the
    // selected child does, so the call must stop.
    cmd(dir.path())
        .args(["sanitize", "--session", "s1"])
        .args(args)
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
    // `vault-ok` holds exactly `__DO_PRIVATE_EMAIL_1__` for scope `s1`; the
    // built-in vaults mint 16 hex characters of entropy per mapping.
    let sanitized = sanitize(
        dir.path(),
        "s1",
        process_selection("vault", "vault-ok"),
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
                "process {capability} unavailable (no executable configured)"
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
            "--policy-program",
            "sleep",
            "--policy-arg",
            "30",
            "--process-timeout-ms",
            "200",
        ])
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

#[test]
fn config_file_timeout_bounds_each_call() {
    let dir = temp_dir();
    common::write_config(
        &dir.path().join("do-context-shield.toml"),
        "[plugins]\npolicy = \"process\"\n\n\
         [process_plugins.policy]\nprogram = \"sleep\"\nargs = [\"30\"]\n\n\
         [process]\ntimeout_ms = 200\n",
    );
    let started = Instant::now();
    cmd(dir.path())
        .args([
            "sanitize",
            "--session",
            "proc",
            "--config",
            "do-context-shield.toml",
        ])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "process policy timed out after 200 ms",
        ));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn autodiscovered_config_process_selection_is_ignored() {
    let dir = temp_dir();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin-process/tests/fixtures/plugin.sh");
    let Some(fixture) = fixture.to_str() else {
        panic!("process fixture path is not valid UTF-8");
    };
    let config = format!(
        "[plugins]\ndetector = \"process\"\n\n\
         [process_plugins.detector]\nprogram = \"sh\"\nargs = [{fixture:?}, \"detect-two\"]\n"
    );
    common::write_config(&dir.path().join("do-context-shield.toml"), &config);

    // Auto-discovery without `--config` ignores process executables in
    // `do-context-shield.toml`, so the selected detector fails closed.
    cmd(dir.path())
        .args(["sanitize", "--session", "amb", "--vault", "memory"])
        .write_stdin("alice@example.com")
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "process detector unavailable (no executable configured)",
        ));

    // Explicit `--config` uses the configured process executable and argv.
    let sanitized = sanitize(
        dir.path(),
        "amb",
        ["--config", "do-context-shield.toml", "--vault", "memory"],
        "alice@example.com",
    );
    let Some((local_part, domain_part)) = sanitized.split_once('@') else {
        panic!("no `@` separator in `{sanitized}`");
    };
    common::assert_placeholder(local_part, "EMAIL", 1);
    common::assert_placeholder(domain_part, "PHONE", 1);
}

#[test]
fn structured_process_args_preserve_boundaries_and_shell_metacharacters() {
    let dir = temp_dir();
    let literal = "$(touch process-argv-sentinel)";
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin-process/tests/fixtures/plugin.sh");
    let Some(fixture) = fixture.to_str() else {
        panic!("process fixture path is not valid UTF-8");
    };

    let sanitized = cmd(dir.path())
        .env("EXPECTED_PROCESS_LITERAL_ARG", literal)
        .args([
            "sanitize",
            "--session",
            "argv",
            "--detector",
            "process",
            "--detector-program",
            "sh",
            "--detector-arg",
            fixture,
            "--detector-arg",
            "detect-argv",
            "--detector-arg",
            "with spaces",
            "--detector-arg",
            "λ",
            "--detector-arg",
            "",
            "--detector-arg",
            literal,
        ])
        .write_stdin("alice@example.com")
        .assert()
        .success();
    let sanitized = String::from_utf8_lossy(&sanitized.get_output().stdout);
    common::assert_placeholder(&sanitized, "EMAIL", 1);
    assert!(
        !dir.path().join("process-argv-sentinel").exists(),
        "shell syntax in an argument was executed"
    );
}

#[test]
fn structured_process_config_is_overridden_atomically_by_cli_argv() {
    let dir = temp_dir();
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin-process/tests/fixtures/plugin.sh");
    let Some(fixture) = fixture.to_str() else {
        panic!("process fixture path is not valid UTF-8");
    };
    let config = format!(
        "[plugins]\ndetector = \"process\"\n\n\
         [process_plugins.detector]\nprogram = \"sh\"\nargs = [{fixture:?}, \"detect-clean\"]\n"
    );
    common::write_config(&dir.path().join("do-context-shield.toml"), &config);

    let configured = sanitize(
        dir.path(),
        "argv-config",
        ["--config", "do-context-shield.toml"],
        "hello world",
    );
    assert_eq!(configured, "hello world");

    let overridden = sanitize(
        dir.path(),
        "argv-cli",
        [
            "--config",
            "do-context-shield.toml",
            "--detector-program",
            "sh",
            "--detector-arg",
            fixture,
            "--detector-arg",
            "detect-two",
        ],
        "alice@example.com",
    );
    let Some((local_part, domain_part)) = overridden.split_once('@') else {
        panic!("CLI process argv did not override the configured detector");
    };
    common::assert_placeholder(local_part, "EMAIL", 1);
    common::assert_placeholder(domain_part, "PHONE", 1);
}
