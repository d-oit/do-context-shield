//! Explicit opt-in JSON-file vault for CLI-to-CLI workflows.

use do_context_shield_plugin_api::{Mapping, ScopeId, Vault, VaultError};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter};
use std::path::PathBuf;

#[derive(Default, Serialize, Deserialize)]
struct State {
    mappings: Vec<MappingRecord>,
    counters: Vec<CounterRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MappingRecord {
    scope: String,
    mapping: Mapping,
}

#[derive(Clone, Serialize, Deserialize)]
struct CounterRecord {
    scope: String,
    kind: String,
    value: usize,
}

/// File-backed local vault. Use only with an access-controlled local path.
pub struct JsonVault {
    path: PathBuf,
    state: State,
}

impl JsonVault {
    /// Open or create a JSON vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError`] when the vault file cannot be read, parsed, or created.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let path = path.into();
        let state = if path.exists() {
            let file = File::open(&path).map_err(|error| io_error(&error))?;
            serde_json::from_reader(BufReader::new(file)).map_err(|error| json_error(&error))?
        } else {
            State::default()
        };
        Ok(Self { path, state })
    }

    fn persist(&self) -> Result<(), VaultError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| io_error(&error))?;
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let file = File::create(&tmp).map_err(|error| io_error(&error))?;
            serde_json::to_writer(BufWriter::new(file), &self.state)
                .map_err(|error| json_error(&error))?;
        }
        fs::rename(&tmp, &self.path).map_err(|error| io_error(&error))?;
        Ok(())
    }
}

impl Vault for JsonVault {
    fn get_or_insert(
        &mut self,
        scope: &ScopeId,
        kind: &str,
        original: &str,
    ) -> Result<Mapping, VaultError> {
        if let Some(existing) = self
            .state
            .mappings
            .iter()
            .find(|record| record.scope == scope.0 && record.mapping.original == original)
        {
            return Ok(existing.mapping.clone());
        }

        let counter = self
            .state
            .counters
            .iter_mut()
            .find(|record| record.scope == scope.0 && record.kind == kind);
        let next = if let Some(record) = counter {
            record.value += 1;
            record.value
        } else {
            self.state.counters.push(CounterRecord {
                scope: scope.0.clone(),
                kind: kind.to_owned(),
                value: 1,
            });
            1
        };

        let mapping = Mapping {
            kind: kind.to_owned(),
            original: original.to_owned(),
            token: format!("__DO_PRIVATE_{}_{}__", kind.to_ascii_uppercase(), next),
        };
        self.state.mappings.push(MappingRecord {
            scope: scope.0.clone(),
            mapping: mapping.clone(),
        });
        self.persist()?;
        Ok(mapping)
    }

    fn resolve(&self, scope: &ScopeId, token: &str) -> Result<Option<Mapping>, VaultError> {
        Ok(self
            .state
            .mappings
            .iter()
            .find(|record| record.scope == scope.0 && record.mapping.token == token)
            .map(|record| record.mapping.clone()))
    }
}

fn io_error(error: &io::Error) -> VaultError {
    VaultError::Message(error.to_string())
}

fn json_error(error: &serde_json::Error) -> VaultError {
    VaultError::Message(error.to_string())
}
