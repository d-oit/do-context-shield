use clap::Args;

/// Timeout and executable/argument selections shared by process plugins.
#[derive(Args, Default, Clone)]
pub(crate) struct ProcessArgs {
    /// Milliseconds to wait for one process-plugin response; defaults to the
    /// config file value or the built-in timeout.
    #[arg(long)]
    pub(crate) process_timeout_ms: Option<u64>,
    /// Local detector executable path or PATH-resolved name.
    #[arg(long, value_name = "PROGRAM")]
    pub(crate) detector_program: Option<String>,
    /// One detector argument, repeatable and passed literally.
    #[arg(long = "detector-arg", action = clap::ArgAction::Append, value_name = "ARG", requires = "detector_program")]
    pub(crate) detector_args: Vec<String>,
    /// Local judge executable path or PATH-resolved name.
    #[arg(long, value_name = "PROGRAM")]
    pub(crate) judge_program: Option<String>,
    /// One judge argument, repeatable and passed literally.
    #[arg(long = "judge-arg", action = clap::ArgAction::Append, value_name = "ARG", requires = "judge_program")]
    pub(crate) judge_args: Vec<String>,
    /// Local policy executable path or PATH-resolved name.
    #[arg(long, value_name = "PROGRAM")]
    pub(crate) policy_program: Option<String>,
    /// One policy argument, repeatable and passed literally.
    #[arg(long = "policy-arg", action = clap::ArgAction::Append, value_name = "ARG", requires = "policy_program")]
    pub(crate) policy_args: Vec<String>,
    /// Local transformer executable path or PATH-resolved name.
    #[arg(long, value_name = "PROGRAM")]
    pub(crate) transformer_program: Option<String>,
    /// One transformer argument, repeatable and passed literally.
    #[arg(long = "transformer-arg", action = clap::ArgAction::Append, value_name = "ARG", requires = "transformer_program")]
    pub(crate) transformer_args: Vec<String>,
    /// Local vault executable path or PATH-resolved name.
    #[arg(long, value_name = "PROGRAM")]
    pub(crate) vault_program: Option<String>,
    /// One vault argument, repeatable and passed literally.
    #[arg(long = "vault-arg", action = clap::ArgAction::Append, value_name = "ARG", requires = "vault_program")]
    pub(crate) vault_args: Vec<String>,
    #[arg(long = "detector-command", hide = true)]
    legacy_detector_command: Option<String>,
    #[arg(long = "judge-command", hide = true)]
    legacy_judge_command: Option<String>,
    #[arg(long = "policy-command", hide = true)]
    legacy_policy_command: Option<String>,
    #[arg(long = "transformer-command", hide = true)]
    legacy_transformer_command: Option<String>,
    #[arg(long = "vault-command", hide = true)]
    legacy_vault_command: Option<String>,
}

impl ProcessArgs {
    /// Reject the removed single-string command flags without echoing values.
    ///
    /// # Errors
    ///
    /// Returns a fixed migration message when a legacy option was supplied.
    pub(crate) fn reject_legacy_flags(&self) -> Result<(), std::io::Error> {
        let legacy = [
            ("detector", self.legacy_detector_command.is_some()),
            ("judge", self.legacy_judge_command.is_some()),
            ("policy", self.legacy_policy_command.is_some()),
            ("transformer", self.legacy_transformer_command.is_some()),
            ("vault", self.legacy_vault_command.is_some()),
        ];
        if let Some((capability, _)) = legacy.iter().find(|(_, supplied)| *supplied) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "`--{capability}-command` was removed; use `--{capability}-program` and repeat `--{capability}-arg`"
                ),
            ));
        }
        Ok(())
    }
    /// Validate process-plugin selections before configuration or stdin use.
    ///
    /// # Errors
    ///
    /// Returns a fixed error for a legacy flag, an empty executable, or
    /// arguments without their executable.
    pub(crate) fn validate(&self) -> Result<(), std::io::Error> {
        self.reject_legacy_flags()?;
        let selections = [
            (
                "detector",
                self.detector_program.as_deref(),
                !self.detector_args.is_empty(),
            ),
            (
                "judge",
                self.judge_program.as_deref(),
                !self.judge_args.is_empty(),
            ),
            (
                "policy",
                self.policy_program.as_deref(),
                !self.policy_args.is_empty(),
            ),
            (
                "transformer",
                self.transformer_program.as_deref(),
                !self.transformer_args.is_empty(),
            ),
            (
                "vault",
                self.vault_program.as_deref(),
                !self.vault_args.is_empty(),
            ),
        ];
        for (capability, program, has_args) in selections {
            if program.is_some_and(str::is_empty) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("`--{capability}-program` must not be empty"),
                ));
            }
            if program.is_none() && has_args {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("`--{capability}-arg` requires `--{capability}-program`"),
                ));
            }
        }
        Ok(())
    }
}
