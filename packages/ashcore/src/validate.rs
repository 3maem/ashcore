//! Standalone validators for ashcore inputs.
//!
//! These functions extract validation logic that was previously inline
//! in other functions, making it testable and reusable without changing
//! any behavioral rules.

use crate::errors::{AshError, AshErrorCode, InternalReason};

/// Minimum hex characters for a valid nonce (128 bits entropy).
/// Extracted from `ash_derive_client_secret` — same value, same rule.
const MIN_NONCE_HEX_CHARS: usize = 32;

/// Maximum nonce length in characters.
/// Extracted from `ash_derive_client_secret` — same value, same rule.
const MAX_NONCE_LENGTH: usize = 512;

/// Validate a nonce string (format and length only, not uniqueness).
///
/// This extracts the exact validation rules from `ash_derive_client_secret`
/// into a standalone function. No rules have been changed.
///
/// # Rules
///
/// - Minimum 32 hex characters (128 bits entropy) — SEC-014
/// - Maximum 512 characters — SEC-NONCE-001
/// - All characters must be ASCII hexadecimal (0-9, a-f, A-F) — BUG-004
///
/// # Returns
///
/// `Ok(())` if the nonce is valid, `Err` with `ASH_VALIDATION_ERROR` (485) otherwise.
/// The `InternalReason` distinguishes between `NonceTooShort`, `NonceTooLong`,
/// and `NonceInvalidChars` for diagnostic purposes.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_validate_nonce;
///
/// // Valid nonce (32 hex chars)
/// assert!(ash_validate_nonce("0123456789abcdef0123456789abcdef").is_ok());
///
/// // Too short
/// assert!(ash_validate_nonce("abcdef").is_err());
///
/// // Invalid characters
/// assert!(ash_validate_nonce("0123456789abcdef0123456789abcdXY").is_err());
/// ```
pub fn ash_validate_nonce(nonce: &str) -> Result<(), AshError> {
    // SEC-014: Validate nonce has sufficient entropy
    if nonce.len() < MIN_NONCE_HEX_CHARS {
        return Err(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::NonceTooShort,
            format!(
                "Nonce must be at least {} hex characters ({} bytes) for adequate entropy",
                MIN_NONCE_HEX_CHARS,
                MIN_NONCE_HEX_CHARS / 2
            ),
        ));
    }

    // SEC-NONCE-001: Validate nonce doesn't exceed maximum length
    if nonce.len() > MAX_NONCE_LENGTH {
        return Err(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::NonceTooLong,
            format!("Nonce exceeds maximum length of {} characters", MAX_NONCE_LENGTH),
        ));
    }

    // BUG-004: Validate nonce is valid hexadecimal
    if !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::NonceInvalidChars,
            "Nonce must contain only hexadecimal characters (0-9, a-f, A-F)",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_valid_32_chars() {
        assert!(ash_validate_nonce("0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn test_nonce_valid_64_chars() {
        let nonce = "a".repeat(64);
        assert!(ash_validate_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_nonce_valid_512_chars() {
        let nonce = "f".repeat(512);
        assert!(ash_validate_nonce(&nonce).is_ok());
    }

    #[test]
    fn test_nonce_too_short() {
        let err = ash_validate_nonce("abcdef").unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.http_status(), 485);
        assert_eq!(err.reason(), InternalReason::NonceTooShort);
    }

    #[test]
    fn test_nonce_empty() {
        let err = ash_validate_nonce("").unwrap_err();
        assert_eq!(err.reason(), InternalReason::NonceTooShort);
    }

    #[test]
    fn test_nonce_too_long() {
        let nonce = "a".repeat(513);
        let err = ash_validate_nonce(&nonce).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.http_status(), 485);
        assert_eq!(err.reason(), InternalReason::NonceTooLong);
    }

    #[test]
    fn test_nonce_invalid_chars() {
        let err = ash_validate_nonce("0123456789abcdef0123456789abcdXY").unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.http_status(), 485);
        assert_eq!(err.reason(), InternalReason::NonceInvalidChars);
    }

    #[test]
    fn test_nonce_uppercase_hex_valid() {
        assert!(ash_validate_nonce("0123456789ABCDEF0123456789ABCDEF").is_ok());
    }

    #[test]
    fn test_nonce_boundary_31_chars() {
        let nonce = "a".repeat(31);
        assert!(ash_validate_nonce(&nonce).is_err());
    }

    #[test]
    fn test_nonce_boundary_32_chars() {
        let nonce = "a".repeat(32);
        assert!(ash_validate_nonce(&nonce).is_ok());
    }
}
