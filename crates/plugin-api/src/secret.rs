//! Credential-kind taxonomy behind the fail-closed redaction rule.

/// Whether `kind` names a credential that must be redacted, never pseudonymized.
#[must_use]
pub fn is_secret_kind(kind: &str) -> bool {
    kind.contains("key")
        || kind.contains("secret")
        || kind.contains("token")
        || kind.contains("password")
        || kind.contains("credential")
        || kind == "card_cvv"
        || kind == "recovery_code"
        || kind == "jwt"
}

#[cfg(test)]
mod tests {
    use super::is_secret_kind;

    #[test]
    fn credential_kinds_are_secrets() {
        for kind in [
            "access_token",
            "api_key",
            "aws_access_key",
            "card_cvv",
            "db_credential",
            "generic_secret",
            "github_token",
            "google_api_key",
            "huggingface_token",
            "jwt",
            "password",
            "private_key",
            "pypi_token",
            "recovery_code",
            "slack_token",
            "stripe_key",
            "user_password",
        ] {
            assert!(is_secret_kind(kind), "{kind}");
        }
    }

    #[test]
    fn personal_kinds_are_not_secrets() {
        for kind in [
            "account_number",
            "card_expiry",
            "date_of_birth",
            "email",
            "iban",
            "ip_address",
            "passport",
            "phone",
            "transaction_date",
            "us_bank_routing",
            "us_drivers_license",
        ] {
            assert!(!is_secret_kind(kind), "{kind}");
        }
    }
}
