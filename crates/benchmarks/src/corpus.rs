//! Deterministic, synthetic-only benchmark inputs.

use do_context_shield_plugin_api::{Action, Entity, PlannedEntity};

/// Revision of the generated benchmark corpus, incremented when its content changes.
pub const CORPUS_REVISION: &str = "synthetic-v1";

/// A bounded synthetic input case with corresponding non-secret test entities.
#[derive(Clone, Debug)]
pub struct Case {
    /// Case label used in Criterion reports.
    pub name: &'static str,
    /// Synthetic prose and generated test addresses.
    pub text: String,
    /// Entity spans corresponding to the generated addresses.
    pub entities: Vec<Entity>,
}

/// Generate a deterministic case with approximately `target_bytes` bytes.
///
/// The target size is a lower bound; the final record may exceed it by one record.
#[must_use]
pub fn make_case(name: &'static str, target_bytes: usize) -> Case {
    let mut text = String::with_capacity(target_bytes.saturating_add(128));
    let mut entities = Vec::new();
    let mut index = 0_usize;
    while text.len() < target_bytes {
        text.push_str("Synthetic support record ");
        text.push_str(&index.to_string());
        text.push_str(" contact ");
        let address = format!("user{index}@example.test");
        let start = text.len();
        text.push_str(&address);
        let end = text.len();
        entities.push(Entity {
            kind: "email".to_owned(),
            start,
            end,
            value: address,
            confidence: 0.99,
        });
        text.push_str("; status=sample; no customer data.\n");
        index = index.saturating_add(1);
    }
    Case {
        name,
        text,
        entities,
    }
}

/// Build standard small, medium, large, and bounded adversarial-size cases.
#[must_use]
pub fn standard_cases() -> Vec<Case> {
    let mut cases = vec![
        make_case("small", 4 * 1024),
        make_case("medium", 64 * 1024),
        make_case("large", 512 * 1024),
    ];
    let mut adversarial = make_case("adversarial", 8 * 1024);
    for _ in 0..512 {
        adversarial.text.push_str("sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA! 999.999.999.999 4111111111111112 ");
    }
    cases.push(adversarial);
    cases
}

/// Convert a case's valid test entities into pseudonymization plans.
#[must_use]
pub fn pseudonymization_plan(entities: &[Entity]) -> Vec<PlannedEntity> {
    entities
        .iter()
        .cloned()
        .map(|entity| PlannedEntity {
            entity,
            action: Action::Pseudonymize,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{CORPUS_REVISION, make_case, standard_cases};

    #[test]
    fn generated_cases_are_deterministic_and_synthetic() {
        let first = standard_cases();
        let second = standard_cases();
        assert_eq!(CORPUS_REVISION, "synthetic-v1");
        assert_eq!(
            first
                .iter()
                .map(|case| (&case.name, &case.text))
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|case| (&case.name, &case.text))
                .collect::<Vec<_>>()
        );
        assert!(
            first
                .iter()
                .all(|case| case.name == "adversarial" || case.text.contains("example.test"))
        );
        assert!(first.iter().all(|case| !case.text.contains("example.com")));
        assert!(make_case("repeat", 1024).text.len() >= 1024);
    }
}
