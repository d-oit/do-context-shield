//! Hybrid detector: runs two detectors over the same input and merges their
//! entities with the primary's spans taking precedence.
//!
//! The documented detector stack pairs the deterministic `detector-regex`
//! (structured identifiers: cards, SSNs, keys) with a local model
//! (`detector-gliner2`, linguistic PII: names, addresses, demographics).
//! Selecting `--detector hybrid` composes the two: the primary runs first, the
//! secondary second, and any secondary entity overlapping a primary entity is
//! dropped before the pipeline's own longest-span-wins pass. Without that
//! precedence, a noisy secondary fragment (a model splitting an SSN into
//! `tax_id` + `ssn` pieces) would displace the primary's authoritative span
//! and leave the uncovered middle digits passing through.
//!
//! Either detector failing fails the call closed. A hybrid that silently
//! degraded to the surviving detector would shrink coverage below what the
//! caller selected — "not checked" must surface as an error, never as a
//! smaller entity list.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};

/// A detector pair evaluated in order, with overlapping secondary entities
/// filtered out.
pub struct HybridDetector {
    primary: Box<dyn Detector>,
    secondary: Box<dyn Detector>,
}

impl HybridDetector {
    /// Compose two detectors; `primary` runs first and keeps its spans when
    /// the two detectors disagree (overlaps, exact ties included).
    #[must_use]
    pub fn new(primary: Box<dyn Detector>, secondary: Box<dyn Detector>) -> Self {
        Self { primary, secondary }
    }
}

impl Detector for HybridDetector {
    fn detect(&self, input: &str) -> Result<Vec<Entity>, DetectorError> {
        let mut entities = self.primary.detect(input)?;
        for entity in self.secondary.detect(input)? {
            if !entities
                .iter()
                .any(|kept| kept.start < entity.end && entity.start < kept.end)
            {
                entities.push(entity);
            }
        }
        Ok(entities)
    }
}

#[cfg(test)]
mod tests;
