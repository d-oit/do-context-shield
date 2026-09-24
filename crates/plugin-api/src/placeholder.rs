use crate::VaultError;

/// Whether `token` has the `__DO_PRIVATE_<INNER>__` placeholder shape that
/// the pipeline's `restore` resolves through a vault.
///
/// `<INNER>` must start and end with an ASCII alphanumeric character and may
/// contain only ASCII alphanumerics and single underscores. This excludes
/// nested delimiters that the restore scanner would otherwise split early.
#[must_use]
pub fn is_placeholder_token(token: &str) -> bool {
    let Some(inner) = token
        .strip_prefix("__DO_PRIVATE_")
        .and_then(|rest| rest.strip_suffix("__"))
    else {
        return false;
    };
    let bytes = inner.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && !inner.contains("__")
}

/// Whether `token` has the current built-in vault format:
/// `__DO_PRIVATE_<KIND>_<COUNTER>_<16_HEX>__`.
///
/// Legacy tokens without the entropy suffix deliberately do not qualify.
#[must_use]
pub fn is_minted_placeholder_token(token: &str) -> bool {
    if !is_placeholder_token(token) {
        return false;
    }
    let Some(inner) = token
        .strip_prefix("__DO_PRIVATE_")
        .and_then(|rest| rest.strip_suffix("__"))
    else {
        return false;
    };
    let Some((kind_and_counter, entropy)) = inner.rsplit_once('_') else {
        return false;
    };
    if entropy.len() != 16 || !entropy.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    let Some((kind, counter)) = kind_and_counter.rsplit_once('_') else {
        return false;
    };
    is_valid_placeholder_kind(kind)
        && !counter.is_empty()
        && counter.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `kind` can be embedded in a token and parsed by `restore`.
fn is_valid_placeholder_kind(kind: &str) -> bool {
    let bytes = kind.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && !kind.contains("__")
}

/// Mint a fresh placeholder token for one mapping.
///
/// The token carries an unguessable 64-bit suffix, so tokens cannot be
/// enumerated from other tokens of the same scope and a fabricated
/// `__DO_PRIVATE_*__` string — in a model reply, say — does not resolve to a
/// stored value. Stability is the vault's job: the same `(scope, kind,
/// original)` mapping keeps returning the token minted on its first insert.
///
/// # Errors
///
/// Returns [`VaultError`] when `kind` cannot be represented in a restorable
/// token or the system entropy source is unavailable. The vault must fail the
/// insert rather than emit an unrestorable or predictable token.
pub fn mint_placeholder(kind: &str, counter: u64) -> Result<String, VaultError> {
    if !is_valid_placeholder_kind(kind) {
        return Err(VaultError::Message(
            "cannot mint a placeholder for an invalid entity kind".to_owned(),
        ));
    }
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|error| {
        VaultError::Message(format!(
            "cannot obtain entropy for a placeholder token ({error})"
        ))
    })?;
    let entropy = u64::from_be_bytes(suffix);
    Ok(format!(
        "__DO_PRIVATE_{}_{counter}_{entropy:016X}__",
        kind.to_ascii_uppercase()
    ))
}
