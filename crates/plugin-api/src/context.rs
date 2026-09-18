//! Enforcement context threaded through the pipeline.

use serde::{Deserialize, Serialize};

/// Recipient trust classification for policy decisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecipientClass {
    /// Local or trusted process on the same device.
    Local,
    /// Known, contractually bound external provider.
    Trusted,
    /// External provider without a data-processing agreement.
    #[default]
    External,
    /// Recipient identity is unknown; fail closed to the most restrictive rules.
    Unknown,
}

impl RecipientClass {
    /// Lowercase name used by the process protocol.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Trusted => "trusted",
            Self::External => "external",
            Self::Unknown => "unknown",
        }
    }

    /// Parse a process-protocol name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "local" => Some(Self::Local),
            "trusted" => Some(Self::Trusted),
            "external" => Some(Self::External),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

/// Data category for jurisdiction-aware policy decisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataCategory {
    /// Non-personal or already anonymised data.
    NonPersonal,
    /// Standard personal data (name, email, phone, IP).
    #[default]
    Personal,
    /// Special-category data (health, biometric, political opinion, etc.).
    SpecialCategory,
}

impl DataCategory {
    /// Lowercase name used by the process protocol.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NonPersonal => "non_personal",
            Self::Personal => "personal",
            Self::SpecialCategory => "special_category",
        }
    }

    /// Parse a process-protocol name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "non_personal" => Some(Self::NonPersonal),
            "personal" => Some(Self::Personal),
            "special_category" => Some(Self::SpecialCategory),
            _ => None,
        }
    }
}

/// Enforcement context threaded through the pipeline.
///
/// Every field defaults to the most restrictive interpretation so an
/// uninitialized context is safe by construction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessingContext {
    /// Purpose of the processing operation (free-form, policy-matched).
    pub purpose: Option<String>,
    /// Trust classification of the data recipient.
    pub recipient: RecipientClass,
    /// Jurisdiction code (ISO 3166-1 alpha-2), if known.
    pub jurisdiction: Option<String>,
    /// Highest data category present in the input.
    pub data_category: DataCategory,
}
