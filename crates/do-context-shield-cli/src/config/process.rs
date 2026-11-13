use do_context_shield_plugin_process::ProcessCommand;
use serde::Deserialize;

/// Separate process-plugin executables and argument lists.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessPlugins {
    pub(crate) detector: Option<ProcessPluginConfig>,
    pub(crate) judge: Option<ProcessPluginConfig>,
    pub(crate) policy: Option<ProcessPluginConfig>,
    pub(crate) transformer: Option<ProcessPluginConfig>,
    pub(crate) vault: Option<ProcessPluginConfig>,
}

/// One process-plugin executable and its ordered literal arguments.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessPluginConfig {
    pub(crate) program: Option<String>,
    #[serde(default)]
    pub(crate) args: Vec<String>,
}

impl ProcessPluginConfig {
    fn command(&self) -> Option<ProcessCommand> {
        self.program
            .as_ref()
            .map(|program| ProcessCommand::new(program.clone(), self.args.clone()))
    }
}

/// Reject the old combined process-command fields with a safe migration hint.
///
/// # Errors
///
/// Returns a safe migration error if a removed combined command field is present.
pub(super) fn reject_legacy_process_commands(
    value: &toml::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    for (section, field, capability) in [
        ("plugins", "detector_command", "detector"),
        ("plugins", "judge_command", "judge"),
        ("plugins", "policy_command", "policy"),
        ("plugins", "transformer_command", "transformer"),
        ("vault", "vault_command", "vault"),
    ] {
        if value
            .get(section)
            .and_then(|table| table.get(field))
            .is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config: `{section}.{field}` was removed; use `[process_plugins.{capability}]` with separate `program` and `args`"
                ),
            )
            .into());
        }
    }
    Ok(())
}

/// CLI program and argv replace the file selection as one command tuple.
pub(super) fn resolve_process_command(
    program: Option<String>,
    args: Vec<String>,
    configured: Option<&ProcessPluginConfig>,
    use_config: bool,
) -> Option<ProcessCommand> {
    if let Some(program) = program {
        Some(ProcessCommand::new(program, args))
    } else if use_config {
        configured.and_then(ProcessPluginConfig::command)
    } else {
        None
    }
}
