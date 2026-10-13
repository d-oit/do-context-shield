//! Boundary fixtures shared by the quality benchmark: values whose
//! generated tails end in an admitted separator (`-`, `_`) or base64 padding
//! (`=`). The exact-span contract extends to these endings; keep them in one
//! place so `corpus.rs` stays under the 500-LOC ceiling.

use super::Rng;

/// The base64url alphabet the shared generators draw from.
const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SLACK: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";

/// One generated value for `kind` whose tail ends in the given separator
/// (`-` or `_`) at the pattern's floor length — the floor counts every tail
/// character, including the separator itself. The prefix matches each
/// generator in `corpus::value_for`; `None` for kinds without a
/// separator-tail fixture.
pub(super) fn separator_tail_value_for(kind: &str, tail: char, rng: &mut Rng) -> Option<String> {
    let mut tailled = |len: usize, alphabet: &str| -> String {
        let head = rng.chars_from(len.saturating_sub(1), alphabet);
        format!("{head}{tail}")
    };
    Some(match (kind, tail) {
        ("api_key", '-') => format!("sk-{}", tailled(16, BASE64URL)),
        ("slack_token", '-') => format!("xoxb-{}", tailled(10, SLACK)),
        ("google_api_key", '-' | '_') => format!("AIza{}", tailled(35, BASE64URL)),
        ("pypi_token", '-') => format!("pypi-AgEIcHlwaS5vcmcCJ{}", tailled(50, BASE64URL)),
        ("gitlab_token", '-') => format!("glpat-{}", tailled(20, ALNUM)),
        ("anthropic_key", '-' | '_') => format!("sk-ant-api03-{}", tailled(86, BASE64URL)),
        ("openai_project_key", '-' | '_') => format!("sk-proj-{}", tailled(48, BASE64URL)),
        _ => return None,
    })
}

/// All boundary cases: separator-tail credentials, both newer prefix variants,
/// and an Azure key ending in standard base64 `==` padding.
pub(super) fn boundary_cases(rng: &mut Rng) -> Vec<(&'static str, String)> {
    let mut cases = Vec::new();
    for (kind, tail) in [
        ("api_key", '-'),
        ("slack_token", '-'),
        ("google_api_key", '-'),
        ("pypi_token", '-'),
        ("gitlab_token", '-'),
        ("google_api_key", '_'),
        ("anthropic_key", '-'),
        ("anthropic_key", '_'),
        ("openai_project_key", '-'),
        ("openai_project_key", '_'),
    ] {
        let Some(value) = separator_tail_value_for(kind, tail, rng) else {
            continue;
        };
        cases.push((kind, value));
    }

    for tail in ['-', '_'] {
        let admin_tail = format!("{}{}", rng.chars_from(85, BASE64URL), tail);
        cases.push(("anthropic_key", format!("sk-ant-admin01-{admin_tail}")));
        let service_tail = format!("{}{}", rng.chars_from(47, BASE64URL), tail);
        cases.push(("openai_project_key", format!("sk-svcacct-{service_tail}")));
    }

    cases.push((
        "azure_storage_credential",
        format!(
            "DefaultEndpointsProtocol=https;AccountName=acct1234;AccountKey={}==",
            "A".repeat(64)
        ),
    ));
    cases
}
