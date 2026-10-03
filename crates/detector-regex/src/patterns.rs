//! Static pattern table for the regex detector.

use do_context_shield_plugin_api::DetectorError;
use regex::Regex;
use std::sync::LazyLock;

/// IPv6 matcher: full, `::`-compressed, and v4-mapped forms.
///
/// Alternatives are ordered so the longest valid form wins at one start
/// position (`2001:db8::1.2.3.4` before `2001:db8::1`). Zone IDs (`%eth0`)
/// and a bare `::` are out of scope.
pub(crate) const IPV6: &str = concat!(
    r"(?i)",
    r"\b(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}:){0,5}(?:\d{1,3}\.){3}\d{1,3}\b",
    r"|\b(?:[0-9a-f]{1,4}:){1,7}(?:\d{1,3}\.){3}\d{1,3}\b",
    r"|::(?:[0-9a-f]{1,4}:){0,6}(?:\d{1,3}\.){3}\d{1,3}\b",
    r"|\b(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*\b",
    r"|\b(?:[0-9a-f]{1,4}:){1,7}:",
    r"|\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b",
    r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})\b",
);

/// Pattern specs: entity kind, regex source, and detector confidence.
///
/// The order is part of the contract: for one identical span the overlap pass
/// keeps the first entity pushed, so `db_credential` precedes `email`, and
/// `ssn`, `credit_card`, and `us_bank_routing` precede the looser `phone` shape
/// that also matches their text.
pub(crate) const SPECS: [(&str, &str, f32); 24] = [
    (
        "db_credential",
        r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|snowflake):\/\/[^\s/@:]*:[^\s/@]+@[^\s"'`<>,;)]*[A-Za-z0-9/]"#,
        0.99,
    ),
    (
        "email",
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        0.99,
    ),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", 0.95),
    (
        "date_of_birth",
        r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b",
        0.85,
    ),
    ("passport", r"\b[A-Z]{1,2}\d{6,9}\b", 0.70),
    ("us_drivers_license", r"\b[A-Z]\d{4}-\d{5}-\d{5}\b", 0.90),
    ("credit_card", r"\b(?:\d[ -]*?){13,19}\b", 0.95),
    ("us_bank_routing", r"\b[0-3]\d{8}\b", 0.70),
    ("phone", r"\b(?:\+?\d[\d ()-]{7,}\d)\b", 0.99),
    ("iban", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", 0.99),
    ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.99),
    (
        "api_key",
        r"\b(?:sk|pk|rk)-(?:[A-Za-z0-9_-]{16,}|[A-Za-z0-9]{15}-)",
        0.99,
    ),
    (
        "github_token",
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{60,})\b",
        0.99,
    ),
    (
        "slack_token",
        r"\bxox[bpras]-(?:[A-Za-z0-9-]{10,}|[A-Za-z0-9]{9}-)",
        0.99,
    ),
    (
        "private_key",
        r"(?s)(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        0.99,
    ),
    ("ipv6", IPV6, 0.99),
    (
        "aws_access_key",
        r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        0.99,
    ),
    (
        "google_api_key",
        r"\bAIza(?:[0-9A-Za-z_-]{34}[0-9A-Za-z_]\b|[0-9A-Za-z_-]{34}-)",
        0.99,
    ),
    (
        "stripe_key",
        r"\b(?:(?:sk|pk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}|whsec_[0-9a-zA-Z]{32,})\b",
        0.99,
    ),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{34,}\b", 0.99),
    (
        "pypi_token",
        r"\bpypi-AgEIcHlwaS5vcmcCJ(?:[A-Za-z0-9_-]{50,}|[A-Za-z0-9]{49}-)",
        0.99,
    ),
    (
        "gitlab_token",
        r"\bglpat-(?:[0-9a-zA-Z_\-]{20,}(?:\.[0-9a-zA-Z]{2,})*|[0-9a-zA-Z]{19}-)",
        0.99,
    ),
    (
        "generic_secret",
        r"(?i)(?:(?:\b|_)(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S{8,}\b|\bbearer\s+\S{8,}\b)",
        0.80,
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.(?:[A-Za-z0-9_-]{10,}|[A-Za-z0-9]{9}-)",
        0.95,
    ),
];

/// One compiled pattern with its entity kind and confidence.
pub(crate) struct Compiled {
    pub(crate) kind: String,
    pub(crate) regex: Regex,
    pub(crate) confidence: f32,
}

/// Compiled once per process; patterns are constants, so a build failure
/// here means a programming error surfaced as [`DetectorError`].
static COMPILED: LazyLock<Result<Vec<Compiled>, String>> = LazyLock::new(|| {
    let mut specs = Vec::with_capacity(SPECS.len());
    for (kind, pattern, confidence) in SPECS {
        let regex = Regex::new(pattern).map_err(|error| error.to_string())?;
        specs.push(Compiled {
            kind: kind.to_owned(),
            regex,
            confidence,
        });
    }
    Ok(specs)
});

/// Returns the process-wide compiled pattern table.
///
/// # Errors
///
/// Returns [`DetectorError::Message`] when a constant pattern fails to compile.
pub(crate) fn compiled() -> Result<&'static [Compiled], DetectorError> {
    match &*COMPILED {
        Ok(specs) => Ok(specs.as_slice()),
        Err(message) => Err(DetectorError::Message(message.clone())),
    }
}
