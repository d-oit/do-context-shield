//! Deterministic regression assertions over the committed fuzz seed corpora.
//!
//! The fuzz targets probe arbitrary input; this test pins the *committed*
//! seeds. Every CHANGELOG regression in
//! `corpus/fuzz_detector_regex/changelog_regressions.txt` must still be
//! detected at its exact kind and byte span, every detected credential must
//! carry the `SYNTHETIC` marker (the allowlist contract in `.gitleaks.toml`),
//! and sanitizing `corpus/fuzz_sanitize_pipeline/changelog_regressions.txt`
//! must remove every detected secret. A seed that loses its regression value,
//! its span, or its marker fails here instead of silently shrinking fuzz
//! coverage; a crash reproduced by the fuzzer is preserved by minimizing the
//! reproducer into a corpus file and adding its row to the table below.

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{
    DataCategory, Detector, ProcessingContext, RecipientClass, ScopeId, Vault, is_secret_kind,
};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_json::JsonVault;
use do_context_shield_vault_memory::MemoryVault;
use std::error::Error;

/// Marker word every committed fake credential carries (see `.gitleaks.toml`);
/// the gitleaks allowlist ignores marked values only, so an unmarked fixture
/// fails the secret scan instead of passing silently.
const MARKER: &str = "SYNTHETIC";

/// Kinds the sanitize seeds must still exercise.
const SANITIZE_SEED_KINDS: [&str; 4] = [
    "anthropic_key",
    "generic_secret",
    "gitlab_token",
    "google_api_key",
];

/// `(exact detected value, expected kind)` for every seeded regression.
const DETECTOR_REGRESSIONS: &[(&str, &str)] = &[
    // exact-width key, 35-char tail ending in `_`
    ("AIzaSYNTHETIC0123456789012345678901234_", "google_api_key"),
    // routable PAT with a `.routing` suffix
    ("glpat-SYNTHETICabcdef1234567890.v1.route", "gitlab_token"),
    // versioned routable PAT
    (
        "glpat-SYNTHETICabcdef1234567890.01.us01abcd123",
        "gitlab_token",
    ),
    // 19-char payload with the trailing-hyphen tail
    ("glpat-SYNTHETIC1234567890-", "gitlab_token"),
    (
        "sk-ant-api03-SYNTHETICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "anthropic_key",
    ),
    (
        "sk-proj-SYNTHETICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "openai_project_key",
    ),
    (
        "github_pat_SYNTHETICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "github_token",
    ),
    ("ghp_SYNTHETIC0123456789012", "github_token"),
    (
        "DefaultEndpointsProtocol=https;AccountName=syntheticacct;AccountKey=SYNTHETICBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==;EndpointSuffix=core.windows.net",
        "azure_storage_credential",
    ),
    (
        "postgres://user:SYNTHETICpw@localhost:5432/appdb",
        "db_credential",
    ),
    // double-quoted assignment: the span covers keyword, `=`, and the quoted
    // literal (spaces preserved)
    (
        "password=\"SYNTHETIC passphrase with spaces\"",
        "generic_secret",
    ),
    // underscore-prefixed assignment: the span starts at the `_` before
    // `SECRET` and keeps the punctuation inside the quotes
    ("_SECRET='SYNTHETIC-pass;!'", "generic_secret"),
    // multibyte line: the non-secret identifier beside the marked key
    ("user@domain.com", "email"),
];

fn corpus_text(relative: &str) -> Result<String, Box<dyn Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(relative);
    Ok(std::fs::read_to_string(path)?)
}

#[test]
fn detector_seeds_pin_every_regression_at_its_exact_span() -> Result<(), Box<dyn Error>> {
    let text = corpus_text("fuzz_detector_regex/changelog_regressions.txt")?;
    for (value, kind) in DETECTOR_REGRESSIONS {
        let hits: Vec<&str> = text.lines().filter(|line| line.contains(*value)).collect();
        if hits.is_empty() {
            return Err(format!("detector seeds: no line contains `{value}`").into());
        }
        for line in hits {
            let offset = line
                .find(*value)
                .ok_or_else(|| format!("detector seeds: offset of `{value}`"))?;
            let entities = RegexDetector.detect(line)?;
            let mut matching = entities
                .iter()
                .filter(|entity| entity.start == offset && entity.end == offset + value.len());
            let entity = matching
                .next()
                .ok_or_else(|| format!("detector seeds: `{value}` was not detected at its span"))?;
            if entity.kind != *kind {
                return Err(format!(
                    "detector seeds: `{value}` detected as `{}`, expected `{kind}`",
                    entity.kind
                )
                .into());
            }
            if entity.value != *value {
                return Err(format!(
                    "detector seeds: span {}..{} carries a value other than the seeded `{value}`",
                    entity.start, entity.end
                )
                .into());
            }
            if matching.next().is_some() {
                return Err(format!("detector seeds: `{value}` matched more than once").into());
            }
        }
    }

    // Marker contract: every secret-kind entity a seed produces must carry the
    // marker, so no real credential can hide in a committed fixture.
    for (number, line) in text.lines().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        for entity in RegexDetector.detect(line)? {
            if is_secret_kind(&entity.kind) && !entity.value.contains(MARKER) {
                return Err(format!(
                    "detector seeds: `{}` on line {} is not SYNTHETIC-marked",
                    entity.kind,
                    number + 1
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn sanitize_seeds_redact_every_detected_secret() -> Result<(), Box<dyn Error>> {
    let text = corpus_text("fuzz_sanitize_pipeline/changelog_regressions.txt")?;
    let mut pipeline = PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let scope = ScopeId("seed-corpus".to_owned());
    let context = ProcessingContext {
        recipient: RecipientClass::External,
        data_category: DataCategory::Personal,
        ..ProcessingContext::default()
    };
    let result = pipeline.sanitize(&scope, &text, &context)?;

    for expected in SANITIZE_SEED_KINDS {
        if !result.entities.iter().any(|entity| entity.kind == expected) {
            return Err(
                format!("sanitize seeds: expected kind `{expected}` was not detected").into(),
            );
        }
    }

    let detected = RegexDetector.detect(&text)?;
    let secrets: Vec<_> = detected
        .iter()
        .filter(|entity| is_secret_kind(&entity.kind))
        .collect();
    if secrets.len() < SANITIZE_SEED_KINDS.len() {
        return Err(format!(
            "sanitize seeds: expected at least {} secrets, detected {}",
            SANITIZE_SEED_KINDS.len(),
            secrets.len()
        )
        .into());
    }
    for secret in secrets {
        // The message names the kind only: never echo a detected value.
        if result.text.contains(&secret.value) {
            return Err(format!(
                "sanitize seeds: a `{}` value survived sanitization",
                secret.kind
            )
            .into());
        }
    }
    Ok(())
}

/// The pipeline fails closed when a removed value survives in an undetected
/// copy. The seed pairs a detected google-shaped key with a copy glued to word
/// characters, which the detector's boundary rules cannot see; redacting only
/// the detected span would emit the raw key.
#[test]
fn sanitize_seed_fails_closed_when_a_copy_survives() -> Result<(), Box<dyn Error>> {
    let text = corpus_text("fuzz_sanitize_pipeline/glued_duplicate.txt")?;
    let mut pipeline = PrivacyPipeline::new(
        Box::new(RegexDetector),
        Box::new(DefaultPolicy),
        Box::new(PseudonymizingTransformer),
        Box::new(MemoryVault::default()),
    );
    let scope = ScopeId("seed-corpus".to_owned());
    let context = ProcessingContext {
        recipient: RecipientClass::External,
        data_category: DataCategory::Personal,
        ..ProcessingContext::default()
    };
    match pipeline.sanitize(&scope, &text, &context) {
        Ok(result) => Err(format!(
            "sanitize seeds: expected a fail-closed error, got {} entities",
            result.entities.len()
        )
        .into()),
        Err(error) => {
            // The refusal names the kind only: never echo a detected value.
            if error.to_string().contains(MARKER) {
                return Err(format!("sanitize seeds: error echoed the value: {error}").into());
            }
            Ok(())
        }
    }
}

/// The vault seeds pin both halves of the persisted-state contract: malformed
/// bytes are refused with a typed error and left alone, and a valid state opens
/// and round-trips an insert through the same file.
#[test]
fn vault_seeds_pin_parse_errors_and_round_trips() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;

    let malformed = corpus_text("fuzz_vault_json/malformed_vault.json")?;
    let malformed_path = dir.path().join("malformed.json");
    std::fs::write(&malformed_path, &malformed)?;
    if JsonVault::open(&malformed_path).is_ok() {
        return Err("a malformed vault seed opened as a valid vault".into());
    }
    if std::fs::read(&malformed_path)?.as_slice() != malformed.as_bytes() {
        return Err("a refused vault file was rewritten".into());
    }

    let sample = corpus_text("fuzz_vault_json/sample_vault.json")?;
    let sample_path = dir.path().join("sample.json");
    std::fs::write(&sample_path, &sample)?;
    let mut vault = JsonVault::open(&sample_path)?;
    let scope = ScopeId("seed-corpus".to_owned());
    let mapping = vault.get_or_insert(&scope, "email", "round-trip@example.com")?;
    match vault.resolve(&scope, &mapping.token)? {
        Some(resolved) if resolved.original == "round-trip@example.com" => {}
        other => {
            // Name the shape only: never echo a mapping.
            return Err(format!(
                "vault seed round-trip failed (a mapping came back: {})",
                other.is_some()
            )
            .into());
        }
    }
    Ok(())
}
