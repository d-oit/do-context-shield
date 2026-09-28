//! Black-box tests for configuration-driven `mcp-stdio` behavior.

use serde_json::{Value, json};
use std::process::Command;

mod common;

use common::{McpSession, content_text, temp_dir, tool_call, tool_names, write_config};

#[test]
fn configured_tool_surface_narrows_the_server() {
    let home = temp_dir();
    write_config(
        &home.path().join("do-context-shield.toml"),
        "[plugins]\ntools = \"sanitize\"\n",
    );
    let mut session = McpSession::start_configured(home, &[], &[]);
    let listed = session.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(tool_names(&listed), ["context.sanitize"]);

    // A tool the configured surface hides is rejected before it could run.
    let denied = session.send(&tool_call(
        "context.inspect",
        &json!({"text": "alice@example.com"}),
    ));
    let message = denied
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(message.contains("not enabled"), "{denied}");
    session.close();
}

#[test]
fn tools_env_and_flag_override_the_configured_surface() {
    // The environment override beats the file value.
    let home = temp_dir();
    write_config(
        &home.path().join("do-context-shield.toml"),
        "[plugins]\ntools = \"sanitize\"\n",
    );
    let mut session = McpSession::start_configured(
        home,
        &[],
        &[("DO_CONTEXT_SHIELD_TOOLS", "sanitize,inspect")],
    );
    let listed = session.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(tool_names(&listed), ["context.sanitize", "context.inspect"]);
    session.close();

    // The CLI flag beats the environment.
    let home = temp_dir();
    write_config(
        &home.path().join("do-context-shield.toml"),
        "[plugins]\ntools = \"sanitize\"\n",
    );
    let mut session = McpSession::start_configured(
        home,
        &["--tools", "all"],
        &[("DO_CONTEXT_SHIELD_TOOLS", "sanitize")],
    );
    let listed = session.send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
    assert_eq!(tool_names(&listed).len(), 4);
    session.close();
}

#[test]
fn config_file_context_supplies_server_defaults() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let config = dir.path().join("do-context-shield.toml");
    if let Err(error) = std::fs::write(&config, "[context]\nrecipient = \"local\"\n") {
        panic!("cannot write the config file: {error}");
    }
    let Some(config_path) = config.to_str() else {
        panic!("config path is not valid UTF-8");
    };
    let mut session = McpSession::start_with(&["--config", config_path, "--tools", "all"]);

    // The file's `[context] recipient = "local"` is the server default, so a
    // personal value is kept instead of pseudonymized.
    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "cfg"}),
    )));
    assert_eq!(sanitized, "alice@example.com");

    // A per-call argument still overrides the file value.
    let overridden = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "bob@example.com", "session": "cfg", "recipient": "external"}),
    )));
    assert!(
        overridden.starts_with("__DO_PRIVATE_EMAIL_"),
        "{overridden}"
    );
    session.close();
}

#[test]
fn vault_ttl_expires_mappings_inside_one_server() {
    let mut session = McpSession::start_with(&["--tools", "all", "--vault-ttl-seconds", "1"]);
    let sanitized = content_text(&session.send(&tool_call(
        "context.sanitize",
        &json!({"text": "alice@example.com", "session": "ttl"}),
    )));
    common::assert_placeholder(&sanitized, "EMAIL", 1);

    // The server drops expired mappings before the next sanitize, and resolve
    // never resurrects one: the placeholder comes back unchanged.
    std::thread::sleep(std::time::Duration::from_millis(1_200));
    let restored = content_text(&session.send(&tool_call(
        "context.restore",
        &json!({"text": &sanitized, "session": "ttl"}),
    )));
    assert_eq!(restored, sanitized);
    session.close();
}

/// Spawn `mcp-stdio` with `extra` and return its exit code and stderr.
fn mcp_startup_failure(extra: &[&str]) -> (i32, String) {
    let home = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let output = match Command::new(env!("CARGO_BIN_EXE_do-context-shield"))
        .arg("mcp-stdio")
        .args(extra)
        .current_dir(home.path())
        .env("HOME", home.path())
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("cannot spawn `do-context-shield mcp-stdio`: {error}"),
    };
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn vault_ttl_with_a_non_memory_vault_fails_at_startup() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("cannot create a temp directory: {error}"),
    };
    let vault = dir.path().join("vault.json");
    let Some(vault_path) = vault.to_str() else {
        panic!("vault path is not valid UTF-8");
    };
    let (code, stderr) = mcp_startup_failure(&[
        "--vault",
        "json",
        "--vault-file",
        vault_path,
        "--vault-ttl-seconds",
        "5",
    ]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("--vault-ttl-seconds"), "stderr: {stderr}");
}

#[test]
fn vault_file_with_an_explicit_memory_vault_fails_at_startup() {
    let (code, stderr) = mcp_startup_failure(&["--vault", "memory", "--vault-file", "v.json"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("--vault-file"), "stderr: {stderr}");
}
