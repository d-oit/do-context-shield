//! Span hygiene shared by detectors and the pipeline.

use crate::Entity;

/// Resolve overlapping detector spans longest-span-wins.
///
/// Detectors may report overlapping candidates for the same text (a nested
/// kind, a loose shape swallowed by a wider one). The widest span wins: it is
/// kept and every span it overlaps is dropped, so a later span displaces a
/// shorter one it covers. Spans of equal length keep the order the detector
/// returned them in (the sort is stable and compares length only), which is
/// what lets a detector's specificity order decide equal-span ties — including
/// equal-length spans at different positions, which overlap each other.
/// The result is sorted by start and end and carries no overlapping spans.
///
/// A span whose `end` precedes its `start` counts as empty rather than
/// panicking; bounds and character-boundary validation stay with the caller.
#[must_use]
pub fn resolve_overlaps(mut entities: Vec<Entity>) -> Vec<Entity> {
    entities.sort_by_key(|entity| std::cmp::Reverse(entity.end.saturating_sub(entity.start)));
    let mut kept: Vec<Entity> = Vec::with_capacity(entities.len());
    for entity in entities {
        let overlaps = kept
            .iter()
            .any(|saved| entity.start < saved.end && saved.start < entity.end);
        if !overlaps {
            kept.push(entity);
        }
    }
    kept.sort_by_key(|entity| (entity.start, entity.end));
    kept
}

#[cfg(test)]
mod tests {
    use super::resolve_overlaps;
    use crate::Entity;

    fn entity(kind: &str, start: usize, end: usize) -> Entity {
        Entity {
            kind: kind.to_owned(),
            start,
            end,
            value: String::new(),
            confidence: 1.0,
        }
    }

    fn kinds(entities: &[Entity]) -> Vec<&str> {
        entities.iter().map(|entity| entity.kind.as_str()).collect()
    }

    #[test]
    fn a_later_span_displaces_a_shorter_one_it_covers() {
        let entities = resolve_overlaps(vec![entity("person", 0, 2), entity("api_key", 1, 12)]);
        assert_eq!(kinds(&entities), ["api_key"]);
    }

    #[test]
    fn a_nested_span_is_dropped() {
        let entities = resolve_overlaps(vec![entity("api_key", 0, 25), entity("phone", 9, 19)]);
        assert_eq!(kinds(&entities), ["api_key"]);
    }

    #[test]
    fn equal_length_ties_keep_the_reported_order() {
        let email_first = resolve_overlaps(vec![entity("email", 0, 17), entity("phone", 0, 17)]);
        assert_eq!(kinds(&email_first), ["email"]);
        let phone_first = resolve_overlaps(vec![entity("phone", 0, 17), entity("email", 0, 17)]);
        assert_eq!(kinds(&phone_first), ["phone"]);
    }

    #[test]
    fn equal_length_overlaps_keep_the_reported_order_not_the_leftmost() {
        // Same length, different positions, overlapping each other: the
        // detector's order decides (detector-regex relies on it for its SPECS
        // precedence, privacy-core and plugin-process for theirs), so the
        // reported-first span wins even when the other starts earlier.
        let later_first = resolve_overlaps(vec![entity("phone", 3, 8), entity("email", 0, 5)]);
        assert_eq!(kinds(&later_first), ["phone"]);
        let earlier_first = resolve_overlaps(vec![entity("email", 0, 5), entity("phone", 3, 8)]);
        assert_eq!(kinds(&earlier_first), ["email"]);
    }

    #[test]
    fn disjoint_spans_survive_sorted_by_start() {
        let entities = resolve_overlaps(vec![entity("city", 10, 12), entity("name", 0, 2)]);
        assert_eq!(kinds(&entities), ["name", "city"]);
        assert_eq!((entities[0].start, entities[1].start), (0, 10));
    }
}
