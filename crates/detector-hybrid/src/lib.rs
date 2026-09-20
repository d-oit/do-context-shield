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
//! Secondary entities that overlap each other are resolved longest-span-wins:
//! a secondary displaces the kept secondaries it overlaps only when it is
//! strictly longer, and equal-length overlaps keep the earlier-returned span.
//! The merged list therefore carries no overlapping secondary spans, so the
//! merge is stable before the pipeline's own dedup pass.
//!
//! Either detector failing fails the call closed. A hybrid that silently
//! degraded to the surviving detector would shrink coverage below what the
//! caller selected — "not checked" must surface as an error, never as a
//! smaller entity list.

use do_context_shield_plugin_api::{Detector, DetectorError, Entity};

/// A detector pair evaluated in order: primary spans take precedence, and
/// overlapping secondary spans are resolved longest-span-wins (ties keep the
/// earlier-returned span).
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
        let primary_len = entities.len();
        for entity in self.secondary.detect(input)? {
            let overlaps = |kept: &Entity| kept.start < entity.end && entity.start < kept.end;
            if entities[..primary_len].iter().any(overlaps) {
                // Primary spans keep their precedence: a secondary entity
                // touching a primary authority is dropped whole.
                continue;
            }
            // Spans are half-open (`start..end`); zero-length spans are not
            // special-cased. Downstream validation owns span hygiene.
            let longest_kept = entities[primary_len..]
                .iter()
                .filter(|kept| overlaps(kept))
                .map(|kept| kept.end - kept.start)
                .max();
            match longest_kept {
                None => entities.push(entity),
                Some(longest) if entity.end - entity.start > longest => {
                    // Longest-span-wins among secondaries: the candidate
                    // displaces every shorter kept secondary it overlaps; an
                    // equal-length overlap keeps the earlier-returned span.
                    entities.retain(|kept| !overlaps(kept));
                    entities.push(entity);
                }
                Some(_) => {}
            }
        }
        Ok(entities)
    }
}

#[cfg(test)]
mod tests;
