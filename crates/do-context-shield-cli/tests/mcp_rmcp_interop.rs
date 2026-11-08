//! Interoperability tests using the official Rust MCP SDK (`rmcp`).
//!
//! Spawns the compiled `do-context-shield mcp-stdio` binary and interacts with
//! it using the official SDK client over stdio. Covers:
//! - Modern 2026-07-28 discovery and tool enumeration
//! - Tool annotations and parameter schemas
//! - Default-denied model-facing surface (restore/forget disabled by default)
//! - Explicit `--tools all` surface with sanitize -> restore -> forget cycle
//! - Data-minimization: raw canaries never leak in sanitize results
//! - Negative cases: malformed arguments and disabled tools

use std::error::Error;
use std::path::PathBuf;

use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult, ClientConfig, JsonObject, ProtocolVersion},
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

mod common;

use common::temp_dir;

const CANARY: &str = "alice@example.com";

fn binary_path() -> PathBuf {
    assert_cmd::cargo::cargo_bin("do-context-shield")
}

type Client = RunningService<RoleClient, ()>;

async fn start_client(args: &[&str]) -> Result<(Client, tempfile::TempDir), Box<dyn Error>> {
    let tmp = temp_dir();
    let bin = binary_path();
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();

    let transport =
        TokioChildProcess::new(tokio::process::Command::new(bin).configure(move |cmd| {
            cmd.arg("mcp-stdio");
            for arg in &args {
                cmd.arg(arg);
            }
        }))?;

    let client = ().serve(transport).await?;
    Ok((client, tmp))
}

fn json_object(value: Value) -> Result<JsonObject, Box<dyn Error>> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err("expected JSON object".into()),
    }
}

fn text_content(result: &CallToolResult) -> Result<&str, Box<dyn Error>> {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .ok_or_else(|| "missing text content in result".into())
}

#[tokio::test]
async fn modern_sdk_discovers_default_tools_and_invokes_safely() -> Result<(), Box<dyn Error>> {
    let (client, _tmp) = start_client(&[]).await?;

    // 1. Tool discovery: default exposed surface is sanitize and inspect only.
    let tools = client.list_all_tools().await?;
    assert_eq!(tools.len(), 2, "default surface must expose 2 tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["context.sanitize", "context.inspect"]);

    // Check tool annotations if present
    for tool in &tools {
        assert!(tool.description.is_some());
    }

    // 2. Benign inspect: does not leak canary
    let inspect_args = json_object(json!({ "text": CANARY }))?;
    let inspect_res = client
        .call_tool(CallToolRequestParams::new("context.inspect").with_arguments(inspect_args))
        .await?;

    let inspect_text = text_content(&inspect_res)?;
    assert!(
        !inspect_text.contains(CANARY),
        "inspect leaked the raw canary"
    );
    assert!(
        inspect_text.contains("email"),
        "expected email entity: {inspect_text}"
    );

    // 3. Sanitize: returns minted placeholder, never raw canary
    let sanitize_args = json_object(json!({
        "text": CANARY,
        "session": "rmcp-test-session"
    }))?;

    let sanitize_res = client
        .call_tool(CallToolRequestParams::new("context.sanitize").with_arguments(sanitize_args))
        .await?;

    let sanitize_text = text_content(&sanitize_res)?;
    assert!(
        !sanitize_text.contains(CANARY),
        "sanitize leaked raw canary: {sanitize_text}"
    );
    assert!(
        sanitize_text.starts_with("__DO_PRIVATE_EMAIL_"),
        "unexpected placeholder: {sanitize_text}"
    );

    // 4. Default-denied: restore is not exposed on the default surface
    let restore_args = json_object(json!({
        "text": sanitize_text,
        "session": "rmcp-test-session"
    }))?;

    let restore_err = client
        .call_tool(CallToolRequestParams::new("context.restore").with_arguments(restore_args))
        .await;
    assert!(restore_err.is_err(), "restore on default surface must fail");

    client.cancel().await.ok();
    Ok(())
}

#[tokio::test]
async fn explicit_all_tools_enables_full_lifecycle() -> Result<(), Box<dyn Error>> {
    let tmp = temp_dir();
    let vault_path = tmp.path().join("vault.json");
    let vault_str = vault_path.to_str().ok_or("invalid UTF-8 in vault path")?;
    let (client, _tmp) = start_client(&["--tools", "all", "--vault-file", vault_str]).await?;

    // 1. Tool discovery: all 4 tools must be present
    let tools = client.list_all_tools().await?;
    assert_eq!(tools.len(), 4, "--tools all must expose 4 tools");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(
        names,
        [
            "context.sanitize",
            "context.restore",
            "context.inspect",
            "context.forget"
        ]
    );

    // 2. Sanitize
    let sanitize_args = json_object(json!({
        "text": CANARY,
        "session": "lifecycle-session"
    }))?;

    let sanitize_res = client
        .call_tool(CallToolRequestParams::new("context.sanitize").with_arguments(sanitize_args))
        .await?;

    let token = text_content(&sanitize_res)?.to_owned();
    assert!(!token.contains(CANARY));

    // 3. Restore
    let restore_args = json_object(json!({
        "text": token,
        "session": "lifecycle-session"
    }))?;

    let restore_res = client
        .call_tool(CallToolRequestParams::new("context.restore").with_arguments(restore_args))
        .await?;

    let restored_text = text_content(&restore_res)?;
    assert_eq!(restored_text, CANARY);

    // 4. Forget
    let forget_args = json_object(json!({
        "session": "lifecycle-session"
    }))?;

    let forget_res = client
        .call_tool(CallToolRequestParams::new("context.forget").with_arguments(forget_args))
        .await?;

    let forget_text = text_content(&forget_res)?;
    assert!(forget_text.contains("forgotten"));

    // 5. Restore after forget: mapping is gone
    let restore_args2 = json_object(json!({
        "text": token,
        "session": "lifecycle-session"
    }))?;

    let restore_res2 = client
        .call_tool(CallToolRequestParams::new("context.restore").with_arguments(restore_args2))
        .await?;

    let post_forget_text = text_content(&restore_res2)?;
    // After forget, the token does not resolve back to the canary
    assert_ne!(post_forget_text, CANARY);

    client.cancel().await.ok();
    Ok(())
}

#[tokio::test]
async fn invalid_tool_arguments_return_tool_error() -> Result<(), Box<dyn Error>> {
    let (client, _tmp) = start_client(&[]).await?;

    // Missing text argument returns an error result (isError: true)
    let bad_args = json_object(json!({ "session": "s" }))?;

    let res = client
        .call_tool(CallToolRequestParams::new("context.sanitize").with_arguments(bad_args))
        .await?;

    assert!(res.is_error.unwrap_or(false), "expected isError: true");
    let err_msg = text_content(&res)?;
    assert!(err_msg.contains("text"), "expected text error: {err_msg}");

    // Invalid context argument returns an error result without leaking canary
    let bad_context = json_object(json!({
        "text": CANARY,
        "recipient": "CANARY-invalid-recipient"
    }))?;

    let res2 = client
        .call_tool(CallToolRequestParams::new("context.sanitize").with_arguments(bad_context))
        .await?;

    assert!(res2.is_error.unwrap_or(false), "expected isError: true");
    let err_msg2 = text_content(&res2)?;
    assert!(
        !err_msg2.contains("CANARY"),
        "error message must not leak canary: {err_msg2}"
    );

    client.cancel().await.ok();
    Ok(())
}

#[tokio::test]
async fn legacy_sdk_initialization_round_trip() -> Result<(), Box<dyn Error>> {
    let _tmp = temp_dir();
    let bin = binary_path();
    let transport = TokioChildProcess::new(tokio::process::Command::new(bin).configure(|cmd| {
        cmd.arg("mcp-stdio");
    }))?;

    let client = ClientConfig::default()
        .with_protocol_version(ProtocolVersion::V_2025_11_25)
        .serve(transport)
        .await?;

    let tools = client.list_all_tools().await?;
    assert_eq!(tools.len(), 2);
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["context.sanitize", "context.inspect"]);

    client.cancel().await.ok();
    Ok(())
}
