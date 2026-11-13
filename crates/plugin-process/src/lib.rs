//! Process plugins: local executables over a newline-delimited JSON protocol.
//!
//! A configured local program (Python, `Presidio`, a cross-language rules
//! engine, a service-backed store, or any other executable) replaces a
//! compiled-in detector, policy, transformer, or vault without touching
//! `do-context-shield-core`. One child process is started per operation: the
//! request is written as a single JSON line to stdin, exactly one response line
//! is read from stdout, and the child is terminated as soon as its answer has
//! been read. A long-lived server mode is not part of this version.
//!
//! Methods:
//!
//! - `detect` — [`ProcessDetector`]: input text to entities.
//! - `judge` — [`ProcessJudge`]: input plus entities to per-candidate labels.
//! - `plan` — [`ProcessPolicy`]: entities to per-entity actions.
//! - `transform` — [`ProcessTransformer`]: input plus plan to sanitized text.
//! - `vault_get_or_insert` / `vault_resolve` — [`ProcessVault`]: scope-keyed
//!   reversible mappings.
//!
//! `docs/process-plugin.md` carries the authoritative wire contract, including
//! the exact request and response shapes.
//!
//! Every method shares the same driver guarantees: one request line in, one
//! response line out (8 MiB cap), a configurable timeout ([`DEFAULT_TIMEOUT_MS`]
//! by default) with kill and reap, a non-zero exit that fails even when a
//! response line was printed, stderr discarded and never logged, and error
//! messages that never echo input values.
//!
//! Validation is fail-closed and stricter than a model backend's: a process
//! plugin is a programming contract, so violations are reported instead of
//! silently dropped. The detector rejects bad spans, value mismatches, and
//! out-of-range confidence; the policy requires exactly one decision per entity;
//! the transformer checks that its text keeps `keep` values, drops every other
//! planned value, and that each emitted placeholder resolves through the
//! pipeline's vault back to the claimed kind and value; the vault must return
//! placeholders the pipeline's `restore` can resolve.
//!
//! `ProcessVault` keeps no state in Rust: the child owns the mapping store, so
//! token stability across calls is whatever that store provides. A stateless
//! child re-issues tokens per call.
//!
//! Configure each process plugin with a separate executable and argument list:
//! `--detector-program <path>` plus repeated `--detector-arg <arg>` (and the
//! equivalent `--judge-*`, `--policy-*`, `--transformer-*`, and `--vault-*`
//! flags). Configuration files use `[process_plugins.detector]` with `program`
//! and `args`; see `docs/process-plugin.md`. Arguments are passed directly to
//! the child, without shell parsing or expansion.

mod detector;
mod judge;
mod policy;
mod protocol;
mod transformer;
mod vault;
mod wire;

pub use detector::ProcessDetector;
pub use judge::ProcessJudge;
pub use policy::ProcessPolicy;
pub use transformer::ProcessTransformer;
pub use vault::ProcessVault;

use std::time::Duration;

/// Default process-plugin timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Executable and ordered arguments for a local process plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessCommand {
    /// Executable path or name resolved through the current `PATH`.
    pub program: std::ffi::OsString,
    /// Arguments passed after the executable, preserving empty values and order.
    pub args: Vec<std::ffi::OsString>,
}

impl ProcessCommand {
    /// Build a process command without shell interpretation.
    #[must_use]
    pub fn new<P, I, A>(program: P, args: I) -> Self
    where
        P: Into<std::ffi::OsString>,
        I: IntoIterator<Item = A>,
        A: Into<std::ffi::OsString>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

/// Configuration shared by every process plugin.
#[derive(Clone, Debug)]
pub struct ProcessConfig {
    /// Local executable and its independent arguments. `None` means unconfigured.
    pub command: Option<ProcessCommand>,
    /// Maximum time to wait for one response.
    pub timeout: Duration,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            command: None,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl ProcessConfig {
    /// Build a config from a structured process command and the default timeout.
    #[must_use]
    pub fn with_command(command: ProcessCommand) -> Self {
        Self {
            command: Some(command),
            ..Self::default()
        }
    }

    /// Set the response timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}
