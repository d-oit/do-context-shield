mod credentials;

use super::*;

#[test]
fn detects_email_and_key() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no secret-like literal is committed.
    let api_key = format!("sk-test-{}", "0123456789abcdef");
    let input = format!("alice@example.com {api_key}");
    let entities = match detector.detect(&input) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 2);
    assert_eq!(entities[0].kind, "email");
    assert_eq!(entities[1].kind, "api_key");
}

#[test]
fn api_key_is_not_double_counted_as_phone() {
    let detector = RegexDetector;
    let api_key = format!("sk-test-{}", "0123456789abcdef");
    let entities = match detector.detect(&api_key) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    // Longest-span-wins: the api_key match suppresses any phone overlap.
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "api_key");
}

#[test]
fn repeated_detection_reuses_compiled_patterns() {
    let detector = RegexDetector;
    for _ in 0..3 {
        match detector.detect("call +1 555 010 1234 today") {
            Ok(_) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}

#[test]
fn detects_credit_card_with_luhn() {
    let detector = RegexDetector;
    let entities = match detector.detect("card 4111 1111 1111 1111 on file") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "credit_card");
    assert_eq!(entities[0].value, "4111 1111 1111 1111");
}

#[test]
fn rejects_invalid_luhn() {
    let detector = RegexDetector;
    let entities = match detector.detect("4111 1111 1111 1112") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(
        !entities.iter().any(|entity| entity.kind == "credit_card"),
        "{entities:?}"
    );
}

#[test]
fn detects_ssn() {
    let detector = RegexDetector;
    let entities = match detector.detect("SSN is 123-45-6789") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "ssn");
}

#[test]
fn detects_ipv6() {
    let detector = RegexDetector;
    let entities = match detector.detect("host 2001:0db8:85a3::8a2e:0370:7334 up") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "ipv6");
    assert_eq!(entities[0].value, "2001:0db8:85a3::8a2e:0370:7334");
}

#[test]
fn detects_ipv4() {
    let detector = RegexDetector;
    let entities = match detector.detect("host 192.168.1.1 up") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1, "{entities:?}");
    assert_eq!(entities[0].kind, "ipv4");
    assert_eq!(entities[0].value, "192.168.1.1");
    assert_eq!((entities[0].start, entities[0].end), (5, 16));
}

#[test]
fn detects_iban() {
    let detector = RegexDetector;
    let entities = match detector.detect("IBAN DE89 3704 0044 0532 0130 00 today") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    // Longest-span-wins: the IBAN beats the looser `phone` shape that also
    // matches its digit groups.
    assert_eq!(entities.len(), 1, "{entities:?}");
    assert_eq!(entities[0].kind, "iban");
    assert_eq!(entities[0].value, "DE89 3704 0044 0532 0130 00");
    assert_eq!((entities[0].start, entities[0].end), (5, 32));
}

#[test]
fn rejects_out_of_range_ipv4_octets() {
    let detector = RegexDetector;
    for input in ["host 999.999.999.999 up", "host 256.100.100.100 up"] {
        let entities = match detector.detect(input) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert!(
            !entities.iter().any(|entity| entity.kind == "ipv4"),
            "{input}: {entities:?}"
        );
    }
}

#[test]
fn accepts_boundary_ipv4_octets() {
    let detector = RegexDetector;
    for input in ["0.0.0.0", "255.255.255.255"] {
        let entities = match detector.detect(input) {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error}"),
        };
        assert_eq!(entities.len(), 1, "{input}: {entities:?}");
        assert_eq!(entities[0].kind, "ipv4");
        assert_eq!(entities[0].value, input);
    }
}

#[test]
fn rejects_iban_with_a_bad_checksum() {
    let detector = RegexDetector;
    let entities = match detector.detect("IBAN DE89 3704 0044 0532 0130 01 today") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    // The digit groups may still surface as the looser `phone` shape, but the
    // invalid account number must not be reported as an IBAN.
    assert!(
        !entities.iter().any(|entity| entity.kind == "iban"),
        "{entities:?}"
    );
}

#[test]
fn detects_aws_key() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no credential literal is committed.
    let aws_key = format!("AKIA{}", "0123456789ABCDEF");
    let entities = match detector.detect(&aws_key) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "aws_access_key");
}

#[test]
fn detects_jwt() {
    let detector = RegexDetector;
    // Synthetic fixture built programmatically so no token literal is committed.
    let jwt = format!(
        "eyJ{}.eyJ{}.{}",
        "hbGciOiJIUzI1NiJ9", "zdWIiOiIxIn0", "signature0123456789"
    );
    let entities = match detector.detect(&jwt) {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "jwt");
}

#[test]
fn credit_card_vs_phone_overlap() {
    let detector = RegexDetector;
    // The loose phone shape matches this span too; the more specific kind
    // wins the equal-span tie in the overlap pass.
    let entities = match detector.detect("pay 4111 1111 1111 1111 now") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "credit_card");
}

#[test]
fn luhn_gate_rejects_invalid_card_numbers() {
    // The gate, not the pattern, is what makes "regex owns cards" true: the
    // digit run is accepted only when the checksum passes.
    assert!(luhn_valid("4111111111111111"), "valid Visa test number");
    assert!(luhn_valid("4111 1111 1111 1111"), "spaces are ignored");
    assert!(luhn_valid("4111-1111-1111-1111"), "hyphens are ignored");
    assert!(!luhn_valid("4111111111111112"), "wrong check digit");
    assert!(!luhn_valid("1234567890123456"), "digit run that fails Luhn");
    assert!(!luhn_valid("4111x11111111111"), "non-digit is not a card");
}

#[test]
fn aba_gate_rejects_invalid_routing_numbers() {
    assert!(aba_valid("111000025"), "ABA checksum passes");
    assert!(
        !aba_valid("123456789"),
        "digits whose weighted sum is not 0 mod 10"
    );
    assert!(!aba_valid("11100002"), "eight digits");
    assert!(!aba_valid("1110000255"), "ten digits");
    assert!(!aba_valid("11100A025"), "non-digit is not a routing number");
}

#[test]
fn detects_date_of_birth() {
    let detector = RegexDetector;
    let entities = match detector.detect("DOB 01/15/1990 recorded") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "date_of_birth");
    assert_eq!(entities[0].value, "01/15/1990");

    // Out-of-range months and out-of-window years are not dates.
    let invalid = match detector.detect("on 13/15/1990 and 01/15/1890") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(invalid.is_empty(), "{invalid:?}");
}

#[test]
fn date_of_birth_and_ssn_coexist() {
    let detector = RegexDetector;
    let entities = match detector.detect("DOB 01/15/1990 SSN 123-45-6789") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 2);
    assert_eq!(entities[0].kind, "date_of_birth");
    assert_eq!(entities[1].kind, "ssn");
}

#[test]
fn detects_passport() {
    let detector = RegexDetector;
    let entities = match detector.detect("passport AB1234567 expires 2030") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "passport");
    assert_eq!(entities[0].value, "AB1234567");

    // Passport numbers are uppercase-only.
    let lowercase = match detector.detect("passport ab1234567 expires") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(lowercase.is_empty(), "{lowercase:?}");
}

#[test]
fn detects_us_drivers_license() {
    let detector = RegexDetector;
    let entities = match detector.detect("license W1234-56789-01234 on file") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "us_drivers_license");
    assert_eq!(entities[0].value, "W1234-56789-01234");
}

#[test]
fn detects_us_bank_routing_with_aba_checksum() {
    let detector = RegexDetector;
    let entities = match detector.detect("routing 021000021 on file") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].kind, "us_bank_routing");
    assert_eq!(entities[0].value, "021000021");
}

#[test]
fn rejects_invalid_aba_checksum() {
    let detector = RegexDetector;
    let entities = match detector.detect("routing 021000022 on file") {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error}"),
    };
    assert!(
        !entities
            .iter()
            .any(|entity| entity.kind == "us_bank_routing"),
        "{entities:?}"
    );
}
