//! Tests for the configuration loader, validation, and CLI merge.

use super::{
    CliSelection, Config, ContextConfig, Plugins, ProcessConfig, VaultConfig, resolve, validate,
};
use crate::cli::DetectorSelection;
use do_context_shield_plugin_process::DEFAULT_TIMEOUT_MS;
use std::path::PathBuf;

#[test]
fn empty_config_is_default() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = toml::from_str("")?;
    assert_eq!(config, Config::default());
    Ok(())
}

#[test]
fn full_config_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let text = r#"
[plugins]
detector = "gliner2"
policy = "process"
transformer = "process"
judge = "heuristics"
model_dir = "/models/gliner2"
detector_command = "detect-detector"
policy_command = "detect-policy"
transformer_command = "detect-transformer"
judge_command = "detect-judge"

[vault]
vault = "json"
vault_file = "vault.json"
vault_command = "detect-vault"

[context]
recipient = "trusted"
data_category = "special_category"
purpose = "code assistance"
jurisdiction = "DE"

[process]
timeout_ms = 1500
"#;
    let config: Config = toml::from_str(text)?;
    let expected = Config {
        plugins: Plugins {
            detector: Some("gliner2".to_owned()),
            policy: Some("process".to_owned()),
            transformer: Some("process".to_owned()),
            judge: Some("heuristics".to_owned()),
            model_dir: Some(PathBuf::from("/models/gliner2")),
            detector_command: Some("detect-detector".to_owned()),
            policy_command: Some("detect-policy".to_owned()),
            transformer_command: Some("detect-transformer".to_owned()),
            judge_command: Some("detect-judge".to_owned()),
        },
        vault: VaultConfig {
            vault: Some("json".to_owned()),
            vault_file: Some(PathBuf::from("vault.json")),
            vault_command: Some("detect-vault".to_owned()),
            vault_ttl_seconds: None,
        },
        context: ContextConfig {
            recipient: Some("trusted".to_owned()),
            data_category: Some("special_category".to_owned()),
            purpose: Some("code assistance".to_owned()),
            jurisdiction: Some("DE".to_owned()),
        },
        process: ProcessConfig {
            timeout_ms: Some(1500),
        },
    };
    assert_eq!(config, expected);
    Ok(())
}

#[test]
fn memory_vault_ttl_parses() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = toml::from_str("[vault]\nvault_ttl_seconds = 3600\n")?;
    assert_eq!(config.vault.vault_ttl_seconds, Some(3600));
    assert!(validate(&config).is_ok());
    Ok(())
}

#[test]
fn unknown_field_rejected() {
    assert!(toml::from_str::<Config>("[plugins]\nbogus = 1").is_err());
}

#[test]
fn invalid_value_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let detector: Config = toml::from_str("[plugins]\ndetector = \"bogus\"")?;
    assert!(validate(&detector).is_err());
    let recipient: Config = toml::from_str("[context]\nrecipient = \"nope\"")?;
    assert!(validate(&recipient).is_err());
    Ok(())
}

#[test]
fn hybrid_detector_name_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = toml::from_str("[plugins]\ndetector = \"hybrid\"\n")?;
    assert!(validate(&config).is_ok());
    Ok(())
}

#[test]
fn vault_combinations_checked() -> Result<(), Box<dyn std::error::Error>> {
    for text in [
        "[vault]\nvault = \"json\"\n",
        "[vault]\nvault = \"json\"\nvault_file = \"v.json\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault = \"process\"\nvault_file = \"v.json\"\n",
        "[vault]\nvault = \"process\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault = \"memory\"\nvault_file = \"v.json\"\n",
        "[vault]\nvault_file = \"v.json\"\nvault_ttl_seconds = 60\n",
    ] {
        let config: Config = toml::from_str(text)?;
        assert!(validate(&config).is_err(), "expected rejection: {text}");
    }
    for text in [
        "[vault]\nvault = \"json\"\nvault_file = \"v.json\"\n",
        "[vault]\nvault = \"memory\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault_file = \"v.json\"\n",
        "[vault]\nvault = \"process\"\nvault_command = \"vault-cmd\"\n",
    ] {
        let config: Config = toml::from_str(text)?;
        assert!(validate(&config).is_ok(), "expected acceptance: {text}");
    }
    Ok(())
}

#[test]
fn cli_overrides_config_and_defaults_fill_gaps() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config =
        toml::from_str("[plugins]\npolicy = \"process\"\n\n[context]\nrecipient = \"local\"\n")?;
    let cli = CliSelection {
        detector: DetectorSelection {
            detector: Some("gliner2".to_owned()),
            ..DetectorSelection::default()
        },
        ..CliSelection::default()
    };
    let resolved = resolve(cli, &config);
    assert_eq!(resolved.detector, "gliner2");
    assert_eq!(resolved.policy, "process");
    assert_eq!(resolved.transformer, "pseudonymize");
    assert_eq!(resolved.recipient, "local");
    assert_eq!(resolved.data_category, "personal");
    assert_eq!(resolved.process_timeout_ms, DEFAULT_TIMEOUT_MS);
    Ok(())
}
