//! Boundary-tail fixtures shared by the quality benchmark: values whose
//! generated tail ends in a separator the declared alphabet admits (`-` or
//! `_`). The exact-span contract extends to these endings; keep them in one
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
        ("google_api_key", '-' | '_') => {
            format!("AIza{}", tailled(35, BASE64URL))
        }
        ("pypi_token", '-') => format!("pypi-AgEIcHlwaS5vcmcCJ{}", tailled(50, BASE64URL)),
        ("gitlab_token", '-') => format!("glpat-{}", tailled(20, ALNUM)),
        _ => return None,
    })
}

/// All separator-tail boundary cases: every existing hyphen-tail fixture plus
/// the underscore-tail `google_api_key` case whose ending the exact-width
/// pattern used to reject.
pub(super) fn boundary_cases(rng: &mut Rng) -> Vec<(&'static str, String)> {
    let mut cases = Vec::new();
    for (kind, tail) in [
        ("api_key", '-'),
        ("slack_token", '-'),
        ("google_api_key", '-'),
        ("pypi_token", '-'),
        ("gitlab_token", '-'),
        ("google_api_key", '_'),
    ] {
        let Some(value) = separator_tail_value_for(kind, tail, rng) else {
            continue;
        };
        cases.push((kind, value));
    }
    cases
}
