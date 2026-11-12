//! Structured process commands preserve executable paths and argument boundaries.

use std::ffi::OsString;
use std::fs;
use std::process::Command;

use do_context_shield_plugin_api::Detector;
use do_context_shield_plugin_process::{ProcessCommand, ProcessConfig, ProcessDetector};

#[test]
fn executable_path_and_arguments_are_spawned_without_shell_splitting() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create temporary directory: {error}"),
    };
    let capture = dir.path().join("captured argv.txt");
    let mut program = dir.path().join("local plugin λ with spaces");
    if !std::env::consts::EXE_SUFFIX.is_empty() {
        program.set_extension("exe");
    }
    let source_path = dir.path().join("argv-fixture.rs");
    let source = r#"
use std::io::{Read, Write};
const CAPTURE: &str = __CAPTURE__;
fn main() {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("\0");
    if std::fs::write(CAPTURE, args).is_err() {
        std::process::exit(2);
    }
    let mut request = String::new();
    if std::io::stdin().read_to_string(&mut request).is_err() {
        std::process::exit(3);
    }
    if std::io::stdout()
        .lock()
        .write_all(b"{\"entities\":[],\"text\":\"\"}\n")
        .is_err()
    {
        std::process::exit(4);
    }
}
"#
    .replace(
        "__CAPTURE__",
        &format!("{:?}", capture.to_string_lossy().as_ref()),
    );
    if let Err(error) = fs::write(&source_path, source) {
        panic!("cannot write process fixture source: {error}");
    }
    let compiled = Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source_path)
        .arg("-o")
        .arg(&program)
        .output();
    let compiled = match compiled {
        Ok(output) => output,
        Err(error) => panic!("cannot run rustc for the process fixture: {error}"),
    };
    assert!(compiled.status.success(), "process fixture did not compile");

    let literal = "$(touch process-argv-sentinel)";
    let args = ["first", "value with spaces", "λ", "", literal]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let detector = ProcessDetector::new(ProcessConfig::with_command(ProcessCommand::new(
        program.as_os_str(),
        args,
    )));
    let entities = match detector.detect("synthetic@example.invalid") {
        Ok(entities) => entities,
        Err(error) => panic!("structured process invocation failed: {error}"),
    };
    assert!(entities.is_empty());

    let captured = match fs::read_to_string(&capture) {
        Ok(captured) => captured,
        Err(error) => panic!("process fixture did not record its arguments: {error}"),
    };
    assert_eq!(
        captured.split('\0').collect::<Vec<_>>(),
        ["first", "value with spaces", "λ", "", literal]
    );
    assert!(!dir.path().join("process-argv-sentinel").exists());
}
