//! Corpus generation for the quality benchmark: deterministic RNG, checksum
//! helpers, and the generated/adversarial/benign corpora.

/// Values generated per declared kind.
const SAMPLES_PER_KIND: usize = 25;
/// Kind names declared in `crates/detector-regex/src/patterns.rs`, read from
/// the source so a new spec cannot silently miss the benchmark.
///
/// Spec entries are either one line (`("kind", r"…", 0.9),`) or a `(` line
/// followed by `"kind",`; nothing else in the file opens with a quoted name.
pub(super) fn declared_kinds() -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let mut lines = include_str!("../../src/patterns.rs").lines().map(str::trim);
    while let Some(line) = lines.next() {
        let literal = if let Some(rest) = line.strip_prefix("(\"") {
            rest
        } else if line == "(" {
            let Some(rest) = lines.next().and_then(|next| next.strip_prefix('"')) else {
                continue;
            };
            rest
        } else {
            continue;
        };
        let Some(kind) = literal.split('"').next() else {
            continue;
        };
        let named = kind
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase());
        let shaped = kind
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
        if named && shaped {
            kinds.push(kind);
        }
    }
    kinds
}

/// xorshift64* — deterministic and dependency-free.
pub(super) struct Rng(u64);

impl Rng {
    pub(super) fn seeded() -> Self {
        Self(0x5eed_1234_5678_9abc)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u32) -> u32 {
        u32::try_from(self.next() % u64::from(bound)).unwrap_or_default()
    }

    fn digits(&mut self, len: usize) -> String {
        (0..len)
            .map(|_| char::from_digit(self.below(10), 10).unwrap_or('0'))
            .collect()
    }

    fn chars_from(&mut self, len: usize, alphabet: &str) -> String {
        let chars: Vec<char> = alphabet.chars().collect();
        let bound = u32::try_from(chars.len()).unwrap_or_default();
        (0..len)
            .map(|_| {
                let index = usize::try_from(self.below(bound)).unwrap_or_default();
                chars.get(index).copied().unwrap_or('x')
            })
            .collect()
    }

    /// `len` characters from `alphabet` with an alphanumeric tail.
    ///
    /// Generated values end on a word character to pin the exact span for
    /// the default generated corpus; hyphen-terminated tails are covered
    /// separately by [`Self::chars_with_hyphen_tail`], whose values the
    /// patterns must also match across the full span.
    fn chars_with_alnum_tail(&mut self, len: usize, alphabet: &str) -> String {
        let head = self.chars_from(len.saturating_sub(1), alphabet);
        format!("{head}{}", self.chars_from(1, ALNUM))
    }

    /// `len` characters from `alphabet` ending in `-`: inside the declared
    /// alphabet of the hyphen-admitting token kinds, so the detector must
    /// report the full value including the trailing character.
    fn chars_with_hyphen_tail(&mut self, len: usize, alphabet: &str) -> String {
        let head = self.chars_from(len.saturating_sub(1), alphabet);
        format!("{head}-")
    }
}

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_DIGITS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
/// Slack token alphabet: the pattern admits hyphens but not underscores.
const SLACK: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
const HEX: &str = "0123456789abcdef";

/// Standard Luhn checksum over all digits.
fn luhn_valid(number: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in number.chars().rev() {
        let Some(mut digit) = ch.to_digit(10) else {
            return false;
        };
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        double = !double;
    }
    sum % 10 == 0
}

/// Check digit that makes `prefix` (15 digits) Luhn-valid.
fn luhn_check_digit(prefix: &str) -> char {
    let mut sum = 0u32;
    let mut double = true;
    for ch in prefix.chars().rev() {
        let Some(digit) = ch.to_digit(10) else {
            return '0';
        };
        let mut value = digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    char::from_digit((10 - sum % 10) % 10, 10).unwrap_or('0')
}

/// ABA routing checksum (3-7-1 weights).
fn aba_valid(number: &str) -> bool {
    let weights = [3u32, 7, 1, 3, 7, 1, 3, 7, 1];
    let mut sum = 0u32;
    for (ch, weight) in number.chars().zip(weights) {
        let Some(digit) = ch.to_digit(10) else {
            return false;
        };
        sum += digit * weight;
    }
    number.len() == 9 && sum % 10 == 0
}

/// IBAN mod-97 validation (spaces ignored).
fn iban_valid(iban: &str) -> bool {
    let compact: String = iban.chars().filter(char::is_ascii_alphanumeric).collect();
    let (Some(rest), Some(country), Some(check)) =
        (compact.get(4..), compact.get(..2), compact.get(2..4))
    else {
        return false;
    };
    let mut digits = String::new();
    for ch in rest.chars().chain(country.chars()).chain(check.chars()) {
        match ch.to_digit(36) {
            Some(_) if ch.is_ascii_digit() => digits.push(ch),
            Some(value) => digits.push_str(&value.to_string()),
            None => return false,
        }
    }
    let mut remainder = 0u32;
    for ch in digits.chars() {
        let Some(digit) = ch.to_digit(10) else {
            return false;
        };
        remainder = (remainder * 10 + digit) % 97;
    }
    remainder == 1
}

/// Check digits that make `country` + `bban` mod-97 valid.
fn iban_check_digits(country: &str, bban: &str) -> String {
    let mut digits = String::from(bban);
    for ch in country.chars() {
        match ch.to_digit(36) {
            Some(value) => digits.push_str(&value.to_string()),
            None => return String::from("00"),
        }
    }
    digits.push_str("00");
    let mut remainder = 0u32;
    for ch in digits.chars() {
        let Some(digit) = ch.to_digit(10) else {
            return String::from("00");
        };
        remainder = (remainder * 10 + digit) % 97;
    }
    format!("{:02}", 98 - remainder)
}

/// Generated values for the credential-shaped kinds.
fn credential_value_for(kind: &str, rng: &mut Rng) -> Option<String> {
    Some(match kind {
        "api_key" => format!("sk-{}", rng.chars_with_alnum_tail(24, BASE64URL)),
        "github_token" => {
            if rng.below(2) == 0 {
                format!("ghp_{}", rng.chars_from(30, ALNUM))
            } else {
                format!(
                    "github_pat_{}_{}",
                    rng.chars_from(22, ALNUM),
                    rng.chars_from(59, ALNUM)
                )
            }
        }
        "slack_token" => format!("xoxb-{}", rng.chars_with_alnum_tail(12, SLACK)),
        "private_key" => format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            rng.chars_from(64, BASE64URL)
        ),
        "aws_access_key" => format!("AKIA{}", rng.chars_from(16, UPPER_DIGITS)),
        "google_api_key" => format!("AIza{}", rng.chars_with_alnum_tail(35, BASE64URL)),
        "generic_secret" => format!("password={}", rng.chars_from(16, ALNUM)),
        "jwt" => format!(
            "eyJ{}.eyJ{}.{}",
            rng.chars_from(16, BASE64URL),
            rng.chars_from(16, BASE64URL),
            rng.chars_with_alnum_tail(20, BASE64URL)
        ),
        "db_credential" => {
            let scheme = match rng.below(4) {
                0 => "postgres",
                1 => "mysql",
                2 => "mongodb+srv",
                _ => "redis",
            };
            format!(
                "{scheme}://{}:{}@host{}.example.com:{}/db",
                rng.chars_from(6, ALNUM),
                rng.chars_from(10, ALNUM),
                rng.digits(2),
                1000 + rng.below(8000)
            )
        }
        "stripe_key" => match rng.below(2) {
            0 => format!("sk_live_{}", rng.chars_from(24, ALNUM)),
            _ => format!("whsec_{}", rng.chars_from(32, ALNUM)),
        },
        "huggingface_token" => format!("hf_{}", rng.chars_from(34, ALNUM)),
        "pypi_token" => format!(
            "pypi-AgEIcHlwaS5vcmcCJ{}",
            rng.chars_with_alnum_tail(50, BASE64URL)
        ),
        "gitlab_token" => format!("glpat-{}", rng.chars_from(20, ALNUM)),
        _ => return None,
    })
}

/// One generated value for `kind` with the shape and checksum the pattern
/// table declares.
fn value_for(kind: &str, rng: &mut Rng) -> String {
    if let Some(value) = credential_value_for(kind, rng) {
        return value;
    }
    match kind {
        "email" => format!("user{}@example-domain{}.com", rng.digits(4), rng.digits(1)),
        "ssn" => {
            let mut area = rng.below(800) + 100;
            if area == 666 {
                area = 667;
            }
            format!("{area}-{:02}-{:04}", rng.below(99) + 1, rng.below(9999) + 1)
        }
        "date_of_birth" => format!(
            "{:02}/{:02}/{}",
            rng.below(12) + 1,
            rng.below(28) + 1,
            1950 + rng.below(56)
        ),
        "passport" => format!("{}{}", rng.chars_from(1, UPPER), rng.digits(8)),
        "us_drivers_license" => format!(
            "{}{}-{}-{}",
            rng.chars_from(1, UPPER),
            rng.digits(4),
            rng.digits(5),
            rng.digits(5)
        ),
        "credit_card" => {
            let mut digits = rng.digits(15);
            digits.push(luhn_check_digit(&digits));
            if rng.below(2) == 0 {
                digits
            } else {
                digits
                    .as_bytes()
                    .chunks(4)
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect::<Vec<String>>()
                    .join(" ")
            }
        }
        "us_bank_routing" => {
            let prefix = format!("{}{}", rng.below(4), rng.digits(7));
            format!("{prefix}{}", aba_check_digit(&prefix))
        }
        "phone" => {
            // The match starts at the first digit (`\b` before `+` does not
            // hold at a string start), so the corpus uses digit-leading forms
            // to pin the exact span.
            if rng.below(2) == 0 {
                format!("{}-{}-{}", rng.digits(3), rng.digits(3), rng.digits(4))
            } else {
                format!("{} {} {}", rng.digits(3), rng.digits(3), rng.digits(4))
            }
        }
        "iban" => {
            let bban = rng.digits(18);
            let iban = format!("DE{}{bban}", iban_check_digits("DE", &bban));
            if rng.below(2) == 0 {
                iban
            } else {
                iban.as_bytes()
                    .chunks(4)
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect::<Vec<String>>()
                    .join(" ")
            }
        }
        "ipv4" => format!(
            "{}.{}.{}.{}",
            rng.below(256),
            rng.below(256),
            rng.below(256),
            rng.below(256)
        ),
        "ipv6" => {
            if rng.below(2) == 0 {
                format!(
                    "2001:db8:{}:{}:{}:{}:{}:{}",
                    rng.chars_from(4, HEX),
                    rng.chars_from(4, HEX),
                    rng.chars_from(4, HEX),
                    rng.chars_from(4, HEX),
                    rng.chars_from(4, HEX),
                    rng.chars_from(4, HEX)
                )
            } else {
                format!("2001:db8::{}", rng.chars_from(4, HEX))
            }
        }
        other => panic!("no generator for declared kind `{other}`"),
    }
}

/// Check digit that makes an 8-digit ABA prefix a valid 9-digit routing number.
fn aba_check_digit(prefix: &str) -> char {
    let weights = [3u32, 7, 1, 3, 7, 1, 3, 7];
    let mut sum = 0u32;
    for (ch, weight) in prefix.chars().zip(weights) {
        let Some(digit) = ch.to_digit(10) else {
            return '0';
        };
        sum += digit * weight;
    }
    char::from_digit((10 - sum % 10) % 10, 10).unwrap_or('0')
}

/// All generated cases, with each checksum-bearing value self-validated.
pub(super) fn generated_cases(rng: &mut Rng) -> Vec<(&'static str, String)> {
    let kinds = declared_kinds();
    assert!(
        kinds.len() >= 24,
        "pattern-table parser found only {} kinds: {kinds:?}",
        kinds.len()
    );
    let mut cases = Vec::with_capacity(kinds.len() * SAMPLES_PER_KIND);
    for kind in &kinds {
        for _ in 0..SAMPLES_PER_KIND {
            let value = value_for(kind, rng);
            match *kind {
                "credit_card" => assert!(luhn_valid(&value.replace(' ', ""))),
                "us_bank_routing" => assert!(aba_valid(&value)),
                "iban" => assert!(iban_valid(&value)),
                _ => {}
            }
            cases.push((*kind, value));
        }
    }
    // A trailing `-` stays inside the declared alphabet of these kinds, so
    // the full value must be one exact-span match (a floor-satisfying value
    // ending in `-` used to be trimmed or missed entirely below the floor).
    // The tail length equals the pattern's floor; the prefix matches each
    // generator in `value_for`.
    cases.extend([
        (
            "api_key",
            format!("sk-{}", rng.chars_with_hyphen_tail(16, BASE64URL)),
        ),
        (
            "slack_token",
            format!("xoxb-{}", rng.chars_with_hyphen_tail(10, SLACK)),
        ),
        (
            "google_api_key",
            format!("AIza{}", rng.chars_with_hyphen_tail(35, BASE64URL)),
        ),
        (
            "pypi_token",
            format!(
                "pypi-AgEIcHlwaS5vcmcCJ{}",
                rng.chars_with_hyphen_tail(50, BASE64URL)
            ),
        ),
        (
            "gitlab_token",
            format!("glpat-{}", rng.chars_with_hyphen_tail(20, ALNUM)),
        ),
    ]);
    cases
}

/// Values shaped like their kind but invalid by that kind's own rule.
pub(super) fn adversarial_cases(rng: &mut Rng) -> Vec<(&'static str, String)> {
    let mut card = rng.digits(16);
    while luhn_valid(&card) {
        card = rng.digits(16);
    }
    let mut routing = format!("1{}", rng.digits(8));
    while aba_valid(&routing) {
        routing = format!("1{}", rng.digits(8));
    }
    let bban = rng.digits(18);
    let broken_iban: String = {
        let iban = format!("DE{}{bban}", iban_check_digits("DE", &bban));
        let mut chars: Vec<char> = iban.chars().collect();
        let last = chars.len().saturating_sub(1);
        if let Some(ch) = chars.get_mut(last) {
            let digit = ch.to_digit(10).unwrap_or(0);
            *ch = char::from_digit((digit + 1) % 10, 10).unwrap_or('0');
        }
        chars.into_iter().collect()
    };
    vec![
        ("credit_card", card),
        ("us_bank_routing", routing),
        ("iban", broken_iban),
        ("ipv4", String::from("999.999.999.999")),
        ("email", String::from("user@localhost")),
        (
            "aws_access_key",
            format!("AKIA{}", rng.chars_from(15, UPPER_DIGITS)),
        ),
        (
            "jwt",
            format!(
                "eyJ{}.eyJ{}x.short",
                rng.chars_from(6, BASE64URL),
                rng.chars_from(6, BASE64URL)
            ),
        ),
        ("passport", String::from("ABCD123456")),
        ("slack_token", String::from("xoxb-short")),
        ("github_token", String::from("github_pat_short")),
        (
            "db_credential",
            String::from("postgres://localhost:5432/app"),
        ),
        ("stripe_key", String::from("sk_dev_short")),
        ("huggingface_token", String::from("hf_short")),
        ("pypi_token", String::from("pypi-short")),
        ("gitlab_token", String::from("glpat-short")),
    ]
}

/// Prose, code, and numbers that must produce no entities.
pub(super) fn benign_corpus() -> Vec<&'static str> {
    vec![
        "The quick brown fox jumps over the lazy dog.",
        "fn main() { let answer = 42; println!(\"{answer}\"); }",
        "Release v1.2.3 shipped on 30 September 2026; see the changelog.",
        "Cache hit ratio improved from 0.81 to 0.94.",
        "See RFC 2119 for the keyword definitions.",
        "Order #10045 left the warehouse; carrier tracking is pending.",
        "sha256: 3f9a1c7e5b2d48f0a6c1e9b4d7f2a8c5e1b3d6f9a2c4e7b0d3f6a9c2e5b8d1f4",
        "The function returns Option<&str> when the key is absent.",
        "add --force-with-lease to the push command before rebasing.",
    ]
}
