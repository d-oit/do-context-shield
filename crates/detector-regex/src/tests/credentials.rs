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
            "non-credential URL {non_secret} produced db_credential: {entities:?}"
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
