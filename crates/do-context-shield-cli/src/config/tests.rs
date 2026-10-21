//! Tests for the configuration loader, validation, and CLI merge.

use super::{CliSelection, Config, resolve, resolve_tools, validate};
use crate::cli::DetectorSelection;
use do_context_shield_mcp_server::ToolSet;
use do_context_shield_plugin_process::DEFAULT_TIMEOUT_MS;

#[test]
fn empty_config_is_default() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = toml::from_str("")?;
    assert_eq!(config, Config::default());
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
fn tools_value_is_validated() -> Result<(), Box<dyn std::error::Error>> {
    let bogus: Config = toml::from_str("[plugins]\ntools = \"sanitize,bogus\"")?;
    assert!(validate(&bogus).is_err());
    let empty: Config = toml::from_str("[plugins]\ntools = \"\"")?;
    assert!(validate(&empty).is_err());
    let accepted: Config = toml::from_str("[plugins]\ntools = \"sanitize,inspect\"")?;
    assert!(validate(&accepted).is_ok());
    let all: Config = toml::from_str("[plugins]\ntools = \"all\"")?;
    assert!(validate(&all).is_ok());
    Ok(())
}

#[test]
fn tools_resolution_prefers_flag_then_file_then_default() -> Result<(), Box<dyn std::error::Error>>
{
    let configured: Config = toml::from_str("[plugins]\ntools = \"sanitize\"")?;
    assert_eq!(
        resolve_tools(None, &configured)?,
        ToolSet::parse("sanitize")?
    );
    assert_eq!(
        resolve_tools(Some(ToolSet::all()), &configured)?,
        ToolSet::all()
    );
    assert_eq!(
        resolve_tools(None, &Config::default())?,
        ToolSet::model_facing()
    );
    Ok(())
}

#[test]
fn hybrid_detector_name_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let config: Config = toml::from_str("[plugins]\ndetector = \"hybrid\"\n")?;
    assert!(validate(&config).is_ok());
    Ok(())
}

#[test]
fn non_reversible_transformer_names_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
    for name in ["generalize", "mask"] {
        let config: Config = toml::from_str(&format!("[plugins]\ntransformer = \"{name}\"\n"))?;
        assert!(validate(&config).is_ok(), "{name}");
    }
    Ok(())
}

#[test]
fn vault_combinations_checked() -> Result<(), Box<dyn std::error::Error>> {
    for text in [
        "[vault]\nvault = \"json\"\n",
        "[vault]\nvault = \"process\"\nvault_file = \"v.json\"\n",
        "[vault]\nvault = \"process\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault = \"memory\"\nvault_file = \"v.json\"\n",
        // A key encrypts only the JSON vault, which needs a file.
        "[vault]\nvault_key_file = \"k.key\"\n",
        "[vault]\nvault = \"memory\"\nvault_key_file = \"k.key\"\n",
        "[vault]\nvault = \"process\"\nvault_key_file = \"k.key\"\n",
    ] {
        let config: Config = toml::from_str(text)?;
        assert!(validate(&config).is_err(), "expected rejection: {text}");
    }
    for text in [
        "[vault]\nvault = \"json\"\nvault_file = \"v.json\"\n",
        "[vault]\nvault = \"memory\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault = \"json\"\nvault_file = \"v.json\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault_file = \"v.json\"\nvault_ttl_seconds = 60\n",
        "[vault]\nvault_file = \"v.json\"\n",
        "[vault]\nvault = \"process\"\nvault_command = \"vault-cmd\"\n",
        "[vault]\nvault = \"json\"\nvault_file = \"v.json\"\nvault_key_file = \"k.key\"\n",
        "[vault]\nvault_file = \"v.json\"\nvault_key_file = \"k.key\"\n",
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
    let resolved = resolve(&cli, &config);
    assert_eq!(resolved.detector, "gliner2");
    assert_eq!(resolved.policy, "process");
    assert_eq!(resolved.transformer, "pseudonymize");
    assert_eq!(resolved.recipient, "local");
    assert_eq!(resolved.data_category, "personal");
    assert_eq!(resolved.process_timeout_ms, DEFAULT_TIMEOUT_MS);
    Ok(())
}
