use super::*;

#[test]
fn detects_slack_token() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let token = format!("xoxb-{}", "0123456789abcdef");
    let entities = match detector.detect(&token) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "slack_token");
    assert_eq!(entities[0].value, token);
}

#[test]
fn detects_private_key() {
    let detector = RegexDetector;
    // Synthetic fixtures built programmatically so no key literal is committed.
    let header = format!("-----BEGIN {}PRIVATE KEY-----", "RSA ");
    let body = "MIIEowIBAAKCAQEAx7Vv";
    let block = format!("{header}\n{body}\n-----END {}PRIVATE KEY-----", "RSA ");
    let encrypted_flavor = "ENCRYPTED ";
    let encrypted = format!(
        "-----BEGIN {encrypted_flavor}PRIVATE KEY-----\n{body}\n-----END {encrypted_flavor}PRIVATE KEY-----"
    );
    // Headers without a matching END marker still detect the header alone.
    let pgp_header = format!("-----BEGIN {}PRIVATE KEY BLOCK-----", "PGP ");
    let encrypted_header = format!("-----BEGIN {encrypted_flavor}PRIVATE KEY-----");
    let entities = match detector.detect(&format!(
        "{block} then {encrypted} then {pgp_header} then {encrypted_header}"
    )) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 4);
    assert_eq!(entities[0].kind, "private_key");
    assert_eq!(entities[0].value, block);
    assert_eq!(entities[1].kind, "private_key");
    assert_eq!(entities[1].value, encrypted);
    assert_eq!(entities[2].kind, "private_key");
    assert_eq!(entities[2].value, pgp_header);
    assert_eq!(entities[3].kind, "private_key");
    assert_eq!(entities[3].value, encrypted_header);
}

#[test]
fn detects_google_api_key() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let key = format!("AIza{}", "0123456789abcdefghijKLMNOPQRSTUVWXY");
    let entities = match detector.detect(&key) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "google_api_key");
    assert_eq!(entities[0].value, key);
}

/// Google keys are exact-width: `AIza` plus exactly 35 tail characters from
/// the declared alphabet. The tail may end in any allowed word character or
/// in the alphabet's `-`, so all three endings must produce one full-span
/// entity with exact byte offsets, bare or inside multibyte surroundings.
/// The `_` ending was missing from the final word-character class; these
/// assertions pin every ending next to the width controls.
#[test]
fn google_api_key_matches_every_allowed_tail_ending() {
    let detector = RegexDetector;
    // 34 head characters from the declared alphabet (digits, letters, and
    // the `-`/`_` separators) plus one final character: the total tail is
    // exactly the declared width. Built programmatically so no credential
    // literal is committed.
    let head = "0123456789abcdefghij-k_lmnopqrstuv";
    assert_eq!(head.len(), 34);
    let surroundings = [("", "", 0usize), ("配置 ", "。", "配置 ".len())];
    for (final_char, label) in [('w', "alphanumeric"), ('_', "underscore"), ('-', "hyphen")] {
        let key = format!("AIza{head}{final_char}");
        assert_eq!(key.len(), 39);
        for (before, after, start) in surroundings {
            let text = format!("{before}{key}{after}");
            let entities = match detector.detect(&text) {
                Ok(value) => value,
                Err(error) => panic!("unexpected error: {error}"),
            };
            assert_eq!(
                entities.len(),
                1,
                "expected one google_api_key entity for the {label}-ending key in {text:?}, got {entities:?}"
            );
            assert_eq!(entities[0].kind, "google_api_key", "{label} ending");
            assert_eq!(
                entities[0].value, key,
                "{label} ending must match the full value"
            );
            assert_eq!(
                entities[0].start, start,
                "{label} ending must start at the key's first byte"
            );
            assert_eq!(
                entities[0].end,
                start + key.len(),
                "{label} ending must end after the key's last byte"
            );
        }
    }

    // Width controls: all-word tails one below and one above the declared
    // width are not Google keys. All-word so the hyphen branch cannot
    // recover them; only the exact width matches.
    let word36 = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (label, tail) in [("34", &word36[..34]), ("36", word36)] {
        let text = format!("AIza{tail}");
        let entities = match detector.detect(&text) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(
            !entities
                .iter()
                .any(|entity| entity.kind == "google_api_key"),
            "{label}-character all-word tail must not be a google_api_key: {entities:?}"
        );
    }
}

#[test]
fn detects_generic_secret_assignments() {
    let detector = RegexDetector;
    let assignment = format!("password={}", "hunter2hunter2");
    let entities = match detector.detect(&assignment) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "generic_secret");
    assert_eq!(entities[0].value, assignment);

    // Env-style keys are underscore-prefixed; the separator is consumed
    // into the span, so the assignment value is still redacted whole.
    let underscored = format!("DB_PASSWORD={}", "hunter2hunter2");
    let entities = match detector.detect(&underscored) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "generic_secret");
    assert_eq!(entities[0].value, underscored[2..]);

    let bearer = format!("Authorization: Bearer {}", "abcdef12345678");
    let entities = match detector.detect(&bearer) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "generic_secret");
    assert_eq!(entities[0].value, "Bearer abcdef12345678");

    // A bare keyword without an assignment or value is not a secret.
    let bare = match detector.detect("password") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(bare.is_empty(), "{bare:?}");
}

#[test]
fn detects_quoted_generic_secret_assignments() {
    let detector = RegexDetector;

    // 1. Quoted secret with spaces (multi-word passphrase)
    let with_spaces = r#"password="my secret passphrase with spaces""#;
    let entities = match detector.detect(with_spaces) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "failed for {with_spaces}");
    assert_eq!(entities[0].kind, "generic_secret");
    assert_eq!(
        entities[0].value, with_spaces,
        "must capture full quoted assignment including closing quote"
    );

    // 2. Single-quoted secret with trailing punctuation
    let single_quoted = "secret='s3cr3t#pass;123!'";
    let entities = match detector.detect(single_quoted) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "failed for {single_quoted}");
    assert_eq!(entities[0].kind, "generic_secret");
    assert_eq!(
        entities[0].value, single_quoted,
        "must capture full single-quoted assignment"
    );

    // 3. Env-style quoted key (consumes leading underscore)
    let env_quoted = "API_SECRET='s3cr3t#pass;123!'";
    let entities = match detector.detect(env_quoted) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].value, env_quoted[3..]);
    // 4. Colon assignment with quotes (e.g. JSON / YAML / config)
    let yaml_style = r#"api_secret: "custom-token-value!""#;
    let entities = match detector.detect(yaml_style) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "failed for {yaml_style}");
    assert_eq!(entities[0].kind, "generic_secret");
    assert_eq!(entities[0].value, yaml_style[3..]);
}

#[test]
fn detects_db_credential_and_prevents_email_collision() {
    let detector = RegexDetector;
    let postgres = "postgres://app:s3cr3tpass@db.example.com:5432/production";
    let entities = match detector.detect(postgres) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(
        entities.len(),
        1,
        "expected db_credential, got {entities:?}"
    );
    assert_eq!(entities[0].kind, "db_credential");
    assert_eq!(entities[0].value, postgres);

    // Redis connection string with empty username (`:password@`)
    let redis = "redis://:foobared@redis.example.com:6379/0";
    let entities = match detector.detect(redis) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "db_credential");
    assert_eq!(entities[0].value, redis);

    // MongoDB connection string with query params
    let mongo = "mongodb+srv://admin:pass12345@cluster.mongodb.net/app?retryWrites=true";
    let entities = match detector.detect(mongo) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "db_credential");
    assert_eq!(entities[0].value, mongo);

    // Non-credential URLs must not be reported as db_credential
    for non_secret in [
        "postgres://localhost:5432/production",
        "postgres://app@localhost:5432/production",
        "mysql://127.0.0.1/db",
    ] {
        let entities = match detector.detect(non_secret) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(
            !entities.iter().any(|e| e.kind == "db_credential"),
            "non-credential URL unexpectedly produced db_credential"
        );
    }
}

#[test]
fn detects_github_fine_grained_pat() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let pat = format!(
        "github_pat_{}_{}",
        "11A2B3C4D5E6F7G8H9I0J1",
        "1234567890123456789012345678901234567890123456789012345678901234567890123456789012"
    );
    let entities = match detector.detect(&pat) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "github_token");
    assert_eq!(entities[0].value, pat);
}

#[test]
fn detects_stripe_keys_and_webhook_secrets() {
    let detector = RegexDetector;
    // Synthetic fixtures built programmatically so no credential literal is committed.
    let sk = format!(
        "sk_live_{}",
        "51NzABCDEFG1234567890abcdefghijklmnopqrstuvwxyz12345678"
    );
    let rk = format!(
        "rk_test_{}",
        "51NzABCDEFG1234567890abcdefghijklmnopqrstuvwxyz12345678"
    );
    let wh = format!("whsec_{}", "abcdefghijklmnopqrstuvwxyz0123456789");
    for key in [&sk, &rk, &wh] {
        let entities = match detector.detect(key) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1, "failed for {key}");
        assert_eq!(entities[0].kind, "stripe_key");
        assert_eq!(entities[0].value, *key);
    }
}

#[test]
fn detects_huggingface_token() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let token = format!("hf_{}", "abcdefghijklmnopqrstuvwxyz01234567");
    let entities = match detector.detect(&token) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "huggingface_token");
    assert_eq!(entities[0].value, token);
}

#[test]
fn detects_pypi_token() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let token = format!(
        "pypi-{}",
        "AgEIcHlwaS5vcmcCJDEyMzQ1Njc4LTlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5egACKlszLCJteS1wcm9qZWN0Il0AAAYg1234567890abcdefghijklmnopqrstuvwxyz12"
    );
    let entities = match detector.detect(&token) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "pypi_token");
    assert_eq!(entities[0].value, token);
}

#[test]
fn detects_gitlab_token() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let token = format!("glpat-{}", "0123456789abcdefghij");
    let entities = match detector.detect(&token) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "gitlab_token");
    assert_eq!(entities[0].value, token);
}

/// Routable GitLab personal access tokens (GitLab 16.9+) append routing
/// and CRC information in dot-separated lowercase-alphanumeric segments
/// (`.us01abcd123` or `.01.us01abcd123`). The detector must match the full
/// routable token without truncating at the dot, while cleanly excluding
/// trailing sentence periods in prose.
#[test]
fn detects_routable_gitlab_tokens() {
    let detector = RegexDetector;
    let payload = "0123456789abcdefghij_klmnopqrstuv";

    // 1. Standard routable PAT
    let routable = format!("glpat-{payload}.us01abcd123");
    let entities = match detector.detect(&routable) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "failed for {routable}");
    assert_eq!(entities[0].kind, "gitlab_token");
    assert_eq!(
        entities[0].value, routable,
        "must capture full routable token"
    );

    // 2. Versioned routable PAT
    let versioned = format!("glpat-{payload}.01.us01abcd123");
    let entities = match detector.detect(&versioned) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "failed for {versioned}");
    assert_eq!(entities[0].kind, "gitlab_token");
    assert_eq!(
        entities[0].value, versioned,
        "must capture full versioned routable token"
    );

    // 3. Prose safety: trailing sentence period must NOT be swallowed
    let prose_routable = format!("Token is {routable}.");
    let entities = match detector.detect(&prose_routable) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(
        entities[0].value, routable,
        "must not swallow trailing sentence period"
    );

    let classic = format!("glpat-{payload}");
    let prose_classic = format!("Token is {classic}.");
    let entities = match detector.detect(&prose_classic) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(
        entities[0].value, classic,
        "must not swallow trailing sentence period on classic token"
    );
}

/// A floor-satisfying value ending in `-` is inside the declared alphabet,
/// so the full value including the trailing `-` must be one secret span.
/// The old right anchor (`\b`) dropped the whole match one character below
/// the floor and trimmed one character above it; the recovery alternation
/// restores exactly one trailing `-` at the floor. The floor counts every
/// tail character, including the final `-` itself.
#[test]
fn hyphen_terminated_token_values_keep_the_full_span() {
    let detector = RegexDetector;
    // (prefix, tail, kind): tail length == the pattern's floor, so the
    // trailing `-` makes the value exactly one character past the old
    // `\b`-trimmed match and exactly one short of the old full match.
    for (prefix, tail, kind) in [
        ("glpat-", "0123456789abcdefghij", "gitlab_token"),
        ("sk-", "0123456789abcdef", "api_key"),
        ("xoxb-", "0123456789", "slack_token"),
        (
            "AIza",
            "0123456789abcdefghijklmnopqrstuvwx",
            "google_api_key",
        ),
        (
            "pypi-AgEIcHlwaS5vcmcCJ",
            "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "pypi_token",
        ),
    ] {
        let token = format!("{prefix}{tail}-");
        let entities = match detector.detect(&token) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(
            entities.len(),
            1,
            "expected one {kind} entity for {token:?}, got {entities:?}"
        );
        assert_eq!(entities[0].kind, kind, "for {token:?}");
        assert_eq!(entities[0].value, token, "for {token:?}");
    }
}

/// A JWT whose signature segment ends with `-` (base64url alphabet) is one
/// full-span entity including the trailing `-`, via the recovery
/// alternation; the `eyJ` header prefix stays required.
#[test]
fn hyphen_terminated_jwt_keeps_the_full_span() {
    let detector = RegexDetector;
    // Each segment sits exactly at the pattern's ten-character floor, and
    // the value carries the `eyJ` header prefix the pattern requires.
    let token = format!(
        "eyJ{}.eyJ{}.{}-",
        "hbGciOiJIUz", "zdWIiOiIxMj", "c2lnbmF0dXJ"
    );
    let entities = match detector.detect(&token) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "{entities:?}");
    assert_eq!(entities[0].kind, "jwt");
    assert_eq!(entities[0].value, token);
}
