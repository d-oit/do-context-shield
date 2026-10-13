use super::*;
use do_context_shield_plugin_api::is_secret_kind;

/// Runs the detector and returns its single entity; any other count fails.
fn detect_one(input: &str) -> Entity {
    let entities = match RegexDetector.detect(input) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    match entities.as_slice() {
        [entity] => entity.clone(),
        other => panic!("expected one entity for {input:?}, got {other:?}"),
    }
}

// Synthetic fixtures are built programmatically so no credential literal is committed.

#[test]
fn detects_anthropic_key_as_its_own_kind() {
    let key = format!("sk-ant-api03-{}", "0123456789abcdefABCDEFghij".repeat(4));
    let entity = detect_one(&format!("Use {key}."));
    assert_eq!(entity.kind, "anthropic_key");
    assert_eq!(entity.value, key, "trailing period must not be swallowed");
    assert!(is_secret_kind(&entity.kind));
}

#[test]
fn anthropic_key_below_floor_falls_back_to_api_key() {
    let short = "sk-ant-api03-0123456789abcdefABCDEF".to_owned();
    assert_eq!(detect_one(&short).kind, "api_key");
}

#[test]
fn detects_openai_project_and_service_account_keys() {
    let tail = "0123456789abcdefABCDEFghijKLMNOP".repeat(2);
    for prefix in ["sk-proj-", "sk-svcacct-"] {
        let key = format!("{prefix}{tail}");
        let entity = detect_one(&key);
        assert_eq!(entity.kind, "openai_project_key", "{key}");
        assert_eq!(entity.value, key);
    }
}

#[test]
fn detects_azure_storage_connection_string_including_padding() {
    // 64-character base64 key ending in `==` padding: the padding is part of the secret.
    let account_key = format!("{}ab==", "ab12".repeat(15));
    let connection = format!(
        "DefaultEndpointsProtocol=https;AccountName=devstoreacct1;AccountKey={account_key};EndpointSuffix=core.windows.net"
    );
    let entity = detect_one(&format!("conn={connection} end"));
    assert_eq!(entity.kind, "azure_storage_credential");
    assert_eq!(entity.value, connection);
    assert!(is_secret_kind(&entity.kind));
}
