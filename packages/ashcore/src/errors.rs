//! Error types for ashcore.
//!
//! This module provides structured error types with:
//! - Stable error codes for programmatic handling
//! - HTTP status code mappings for API responses
//! - Human-readable error messages
//!
//! ## Error Codes (Unique HTTP Status Codes)
//!
//! ASH uses unique HTTP status codes in the 450-499 range for precise error identification.
//! Every error code maps to a unique HTTP status code for unambiguous monitoring and retry logic.
//!
//! | Code | HTTP Status | Meaning |
//! |------|-------------|---------|
//! | `CTX_NOT_FOUND` | 450 | Context ID not found in store |
//! | `CTX_EXPIRED` | 451 | Context has expired |
//! | `CTX_ALREADY_USED` | 452 | Context was already consumed (replay) |
//! | `PROOF_INVALID` | 460 | Proof verification failed |
//! | `BINDING_MISMATCH` | 461 | Request endpoint doesn't match context |
//! | `SCOPE_MISMATCH` | 473 | Scope hash mismatch |
//! | `CHAIN_BROKEN` | 474 | Chain verification failed |
//! | `SCOPED_FIELD_MISSING` | 475 | Required scoped field missing |
//! | `TIMESTAMP_INVALID` | 482 | Invalid timestamp format |
//! | `PROOF_MISSING` | 483 | Required X-ASH-Proof header missing |
//! | `CANONICALIZATION_ERROR` | 484 | Payload cannot be canonicalized |
//! | `VALIDATION_ERROR` | 485 | Input validation failure |
//! | `MODE_VIOLATION` | 486 | Security mode requirements not met |
//! | `UNSUPPORTED_CONTENT_TYPE` | 415 | Content type not supported |
//! | `INTERNAL_ERROR` | 500 | Internal server error |
//!
//! ## Example
//!
//! ```rust
//! use ashcore::{AshError, AshErrorCode};
//!
//! fn verify_request() -> Result<(), AshError> {
//!     // Return an error with code and message
//!     Err(AshError::new(
//!         AshErrorCode::ProofInvalid,
//!         "Proof does not match expected value"
//!     ))
//! }
//!
//! match verify_request() {
//!     Ok(_) => println!("Valid!"),
//!     Err(e) => {
//!         println!("Error: {} (HTTP {})", e.message(), e.code().http_status());
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Error codes for ashcore.
///
/// These codes are stable and should not change between versions.
///
/// ## Standard Error Codes
///
/// | Error Code | HTTP Status | Description |
/// |------------|-------------|-------------|
/// | `ASH_CTX_NOT_FOUND` | 450 | Context ID not found in store |
/// | `ASH_CTX_EXPIRED` | 451 | Context has expired |
/// | `ASH_CTX_ALREADY_USED` | 452 | Context was already consumed (replay) |
/// | `ASH_PROOF_INVALID` | 460 | Proof verification failed |
/// | `ASH_BINDING_MISMATCH` | 461 | Request endpoint doesn't match context |
/// | `ASH_SCOPE_MISMATCH` | 473 | Scope hash mismatch |
/// | `ASH_CHAIN_BROKEN` | 474 | Chain verification failed |
/// | `ASH_TIMESTAMP_INVALID` | 482 | Invalid timestamp format |
/// | `ASH_PROOF_MISSING` | 483 | Required X-ASH-Proof header missing |
/// | `ASH_SCOPED_FIELD_MISSING` | 475 | Required scoped field missing |
/// | `ASH_CANONICALIZATION_ERROR` | 484 | Payload cannot be canonicalized |
/// | `ASH_VALIDATION_ERROR` | 485 | Input validation failure |
/// | `ASH_MODE_VIOLATION` | 486 | Security mode requirements not met |
/// | `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Content type not supported |
/// | `ASH_INTERNAL_ERROR` | 500 | Internal server error |
///
/// Every error code has a unique HTTP status code for unambiguous identification.
///
/// ## Serde Serialization (CR-001)
///
/// Error codes serialize with the `ASH_` prefix per the ASH specification:
/// `CtxNotFound` serializes as `"ASH_CTX_NOT_FOUND"`, not `"CTX_NOT_FOUND"`.
/// This ensures cross-SDK interoperability when error codes are transmitted as JSON.
// TODO: Add `#[non_exhaustive]` to AshErrorCode. This would allow adding new
// error variants without a semver-breaking change, but adding it now would break
// existing exhaustive `match` statements in downstream crates (semver-breaking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AshErrorCode {
    /// Context not found in store
    CtxNotFound,
    /// Context has expired
    CtxExpired,
    /// Context was already consumed (replay detected).
    ///
    /// **Distributed systems note**: In distributed deployments with multiple
    /// verification nodes, `CtxAlreadyUsed` may be returned due to replication
    /// lag rather than an actual replay attack. Consider allowing a short retry
    /// window or using a distributed lock if your architecture produces false
    /// positives for this error code.
    CtxAlreadyUsed,
    /// Binding does not match expected endpoint
    BindingMismatch,
    /// Required proof not provided
    ProofMissing,
    /// Proof does not match expected value
    ProofInvalid,
    /// Payload cannot be canonicalized
    CanonicalizationError,
    /// General validation error (input validation failures)
    /// Spec: ASH_VALIDATION_ERROR (HTTP 485)
    ValidationError,
    /// Mode requirements not met
    ModeViolation,
    /// Content type not supported
    UnsupportedContentType,
    /// Scope hash mismatch
    ScopeMismatch,
    /// Chain verification failed
    ChainBroken,
    /// Internal server error (RNG failure, etc.)
    InternalError,
    /// Timestamp validation failed (SEC-005)
    TimestampInvalid,
    /// Required scoped field missing (SEC-006)
    ScopedFieldMissing,
}

/// CR-001: Custom Serialize implementation to produce spec-compliant ASH_ prefixed strings.
/// `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` would produce `CTX_NOT_FOUND` without
/// the required `ASH_` prefix, causing cross-SDK deserialization failures.
impl Serialize for AshErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AshErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "ASH_CTX_NOT_FOUND" => Ok(AshErrorCode::CtxNotFound),
            "ASH_CTX_EXPIRED" => Ok(AshErrorCode::CtxExpired),
            "ASH_CTX_ALREADY_USED" => Ok(AshErrorCode::CtxAlreadyUsed),
            "ASH_BINDING_MISMATCH" => Ok(AshErrorCode::BindingMismatch),
            "ASH_PROOF_MISSING" => Ok(AshErrorCode::ProofMissing),
            "ASH_PROOF_INVALID" => Ok(AshErrorCode::ProofInvalid),
            "ASH_CANONICALIZATION_ERROR" => Ok(AshErrorCode::CanonicalizationError),
            "ASH_VALIDATION_ERROR" => Ok(AshErrorCode::ValidationError),
            "ASH_MODE_VIOLATION" => Ok(AshErrorCode::ModeViolation),
            "ASH_UNSUPPORTED_CONTENT_TYPE" => Ok(AshErrorCode::UnsupportedContentType),
            "ASH_SCOPE_MISMATCH" => Ok(AshErrorCode::ScopeMismatch),
            "ASH_CHAIN_BROKEN" => Ok(AshErrorCode::ChainBroken),
            "ASH_INTERNAL_ERROR" => Ok(AshErrorCode::InternalError),
            "ASH_TIMESTAMP_INVALID" => Ok(AshErrorCode::TimestampInvalid),
            "ASH_SCOPED_FIELD_MISSING" => Ok(AshErrorCode::ScopedFieldMissing),
            _ => Err(serde::de::Error::unknown_variant(
                &s,
                &[
                    "ASH_CTX_NOT_FOUND", "ASH_CTX_EXPIRED", "ASH_CTX_ALREADY_USED",
                    "ASH_BINDING_MISMATCH", "ASH_PROOF_MISSING", "ASH_PROOF_INVALID",
                    "ASH_CANONICALIZATION_ERROR", "ASH_VALIDATION_ERROR", "ASH_MODE_VIOLATION",
                    "ASH_UNSUPPORTED_CONTENT_TYPE", "ASH_SCOPE_MISMATCH", "ASH_CHAIN_BROKEN",
                    "ASH_INTERNAL_ERROR", "ASH_TIMESTAMP_INVALID", "ASH_SCOPED_FIELD_MISSING",
                ],
            )),
        }
    }
}

impl AshErrorCode {
    /// Get the recommended HTTP status code for this error.
    ///
    /// Every error code has a unique HTTP status code for unambiguous identification.
    /// ASH-specific errors use the 450-486 range. Standard HTTP codes (415, 500) are used
    /// only where a single ASH error maps to a well-known HTTP semantic.
    pub fn http_status(&self) -> u16 {
        match self {
            // Context errors (450-452)
            AshErrorCode::CtxNotFound => 450,
            AshErrorCode::CtxExpired => 451,
            AshErrorCode::CtxAlreadyUsed => 452,
            // Proof & Binding errors (460-461)
            AshErrorCode::ProofInvalid => 460,
            AshErrorCode::BindingMismatch => 461,
            // Verification errors (473-479)
            AshErrorCode::ScopeMismatch => 473,
            AshErrorCode::ChainBroken => 474,
            AshErrorCode::ScopedFieldMissing => 475,
            // Format/Protocol errors (480-489)
            AshErrorCode::TimestampInvalid => 482,
            AshErrorCode::ProofMissing => 483,
            AshErrorCode::CanonicalizationError => 484,
            AshErrorCode::ValidationError => 485,
            AshErrorCode::ModeViolation => 486,
            // Standard HTTP codes (unique, 1:1 mapping)
            AshErrorCode::UnsupportedContentType => 415,
            AshErrorCode::InternalError => 500,
        }
    }

    /// Whether this error code is retryable.
    ///
    /// Retryable errors are transient conditions that may resolve on retry:
    /// - `TimestampInvalid` — clock skew may resolve after sync
    /// - `InternalError` — transient server failure
    /// - `CtxAlreadyUsed` — in distributed deployments, replication lag may cause
    ///   false positives (see doc comment on the variant). A short retry with a
    ///   fresh context can succeed.
    ///
    /// All other errors are permanent (wrong proof, missing fields, etc.)
    /// and retrying with the same inputs will always produce the same error.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            AshErrorCode::TimestampInvalid
                | AshErrorCode::InternalError
                | AshErrorCode::CtxAlreadyUsed
        )
    }

    /// Get the error code as a string.
    ///
    /// Returns the error code string per ASH specification.
    pub fn as_str(&self) -> &'static str {
        match self {
            AshErrorCode::CtxNotFound => "ASH_CTX_NOT_FOUND",
            AshErrorCode::CtxExpired => "ASH_CTX_EXPIRED",
            AshErrorCode::CtxAlreadyUsed => "ASH_CTX_ALREADY_USED",
            AshErrorCode::BindingMismatch => "ASH_BINDING_MISMATCH",
            AshErrorCode::ProofMissing => "ASH_PROOF_MISSING",
            AshErrorCode::ProofInvalid => "ASH_PROOF_INVALID",
            AshErrorCode::CanonicalizationError => "ASH_CANONICALIZATION_ERROR",
            AshErrorCode::ValidationError => "ASH_VALIDATION_ERROR",
            AshErrorCode::ModeViolation => "ASH_MODE_VIOLATION",
            AshErrorCode::UnsupportedContentType => "ASH_UNSUPPORTED_CONTENT_TYPE",
            AshErrorCode::ScopeMismatch => "ASH_SCOPE_MISMATCH",
            AshErrorCode::ChainBroken => "ASH_CHAIN_BROKEN",
            AshErrorCode::InternalError => "ASH_INTERNAL_ERROR",
            AshErrorCode::TimestampInvalid => "ASH_TIMESTAMP_INVALID",
            AshErrorCode::ScopedFieldMissing => "ASH_SCOPED_FIELD_MISSING",
        }
    }
}

impl fmt::Display for AshErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Internal diagnostic reason for errors.
///
/// This provides granular error classification for debugging and observability
/// without changing wire-level behavior. The wire code (`AshErrorCode`) and
/// HTTP status remain conformance-locked; `InternalReason` adds precision
/// for logs and diagnostics only.
///
/// ## Reconciliation
///
/// | InternalReason | WireCode | http_status |
/// |----------------|----------|-------------|
/// | `HdrMissing` | `ASH_VALIDATION_ERROR` | 485 |
/// | `HdrMultiValue` | `ASH_VALIDATION_ERROR` | 485 |
/// | `HdrInvalidChars` | `ASH_VALIDATION_ERROR` | 485 |
/// | `TsParse` | `ASH_TIMESTAMP_INVALID` | 482 |
/// | `TsSkew` | `ASH_TIMESTAMP_INVALID` | 482 |
/// | `TsLeadingZeros` | `ASH_TIMESTAMP_INVALID` | 482 |
/// | `TsOverflow` | `ASH_TIMESTAMP_INVALID` | 482 |
/// | `NonceTooShort` | `ASH_VALIDATION_ERROR` | 485 |
/// | `NonceTooLong` | `ASH_VALIDATION_ERROR` | 485 |
/// | `NonceInvalidChars` | `ASH_VALIDATION_ERROR` | 485 |
/// | `General` | (varies) | (varies) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InternalReason {
    // Header extraction
    /// Required header is missing
    HdrMissing,
    /// Header has multiple values where single is required
    HdrMultiValue,
    /// Header contains control characters or newlines
    HdrInvalidChars,

    // Timestamp validation
    /// Timestamp could not be parsed as integer
    TsParse,
    /// Timestamp outside allowed clock skew
    TsSkew,
    /// Timestamp has leading zeros
    TsLeadingZeros,
    /// Timestamp exceeds maximum bounds
    TsOverflow,

    // Nonce validation
    /// Nonce is shorter than minimum required length
    NonceTooShort,
    /// Nonce exceeds maximum allowed length
    NonceTooLong,
    /// Nonce contains non-hexadecimal characters
    NonceInvalidChars,

    /// General/unspecified reason (backward compat for existing error paths)
    General,
}

impl fmt::Display for InternalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalReason::HdrMissing => write!(f, "HDR_MISSING"),
            InternalReason::HdrMultiValue => write!(f, "HDR_MULTI_VALUE"),
            InternalReason::HdrInvalidChars => write!(f, "HDR_INVALID_CHARS"),
            InternalReason::TsParse => write!(f, "TS_PARSE"),
            InternalReason::TsSkew => write!(f, "TS_SKEW"),
            InternalReason::TsLeadingZeros => write!(f, "TS_LEADING_ZEROS"),
            InternalReason::TsOverflow => write!(f, "TS_OVERFLOW"),
            InternalReason::NonceTooShort => write!(f, "NONCE_TOO_SHORT"),
            InternalReason::NonceTooLong => write!(f, "NONCE_TOO_LONG"),
            InternalReason::NonceInvalidChars => write!(f, "NONCE_INVALID_CHARS"),
            InternalReason::General => write!(f, "GENERAL"),
        }
    }
}

/// Main error type for ASH operations.
///
/// Error messages are designed to be safe for logging and client responses.
/// They never contain sensitive data like payloads, proofs, or canonical strings.
///
/// ## Two-Layer Error Model
///
/// - **Wire layer** (`code` / `http_status` / `message`): Conformance-locked.
///   These values are tested by the 134-vector conformance suite and must not change.
/// - **Diagnostic layer** (`reason` / `details`): Internal only.
///   Provides granular classification for logging and debugging without affecting
///   wire behavior.
#[derive(Debug, Clone)]
pub struct AshError {
    /// Error code (wire-level, conformance-locked)
    code: AshErrorCode,
    /// Human-readable message (safe for logging)
    message: String,
    /// Internal diagnostic reason (not exposed on wire)
    reason: InternalReason,
    /// Optional diagnostic details (not exposed on wire, must not contain secrets)
    details: Option<BTreeMap<&'static str, String>>,
}

impl AshError {
    /// Create a new AshError with General reason (backward compatible).
    pub fn new(code: AshErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            reason: InternalReason::General,
            details: None,
        }
    }

    /// Create a new AshError with a specific internal reason.
    pub fn with_reason(code: AshErrorCode, reason: InternalReason, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            reason,
            details: None,
        }
    }

    /// Add a diagnostic detail (builder pattern). Must not contain secrets.
    pub fn with_detail(mut self, key: &'static str, value: impl Into<String>) -> Self {
        let map = self.details.get_or_insert_with(BTreeMap::new);
        map.insert(key, value.into());
        self
    }

    /// Get the error code.
    pub fn code(&self) -> AshErrorCode {
        self.code
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the recommended HTTP status code.
    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    /// Get the internal diagnostic reason.
    pub fn reason(&self) -> InternalReason {
        self.reason
    }

    /// Get the diagnostic details (if any).
    pub fn details(&self) -> Option<&BTreeMap<&'static str, String>> {
        self.details.as_ref()
    }

    /// Whether this error is retryable.
    ///
    /// Delegates to `AshErrorCode::retryable()`. SDKs can pass this
    /// through to clients without implementing their own retry logic.
    pub fn retryable(&self) -> bool {
        self.code.retryable()
    }
}

impl fmt::Display for AshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AshError {}

/// Convenience functions for creating common errors.
impl AshError {
    /// Context not found.
    pub fn ctx_not_found() -> Self {
        Self::new(AshErrorCode::CtxNotFound, "Context not found")
    }

    /// Context expired.
    pub fn ctx_expired() -> Self {
        Self::new(AshErrorCode::CtxExpired, "Context has expired")
    }

    /// Context already used (replay detected).
    pub fn ctx_already_used() -> Self {
        Self::new(AshErrorCode::CtxAlreadyUsed, "Context already consumed")
    }

    /// Binding mismatch.
    pub fn binding_mismatch() -> Self {
        Self::new(
            AshErrorCode::BindingMismatch,
            "Binding does not match endpoint",
        )
    }

    /// Proof missing.
    pub fn proof_missing() -> Self {
        Self::new(AshErrorCode::ProofMissing, "Required proof not provided")
    }

    /// Proof invalid.
    pub fn proof_invalid() -> Self {
        Self::new(AshErrorCode::ProofInvalid, "Proof verification failed")
    }

    /// Canonicalization error.
    ///
    /// PT-002: Uses a fixed message to prevent caller-provided data from leaking
    /// into error messages. All canonicalization failures produce the same generic
    /// message regardless of the specific failure reason.
    pub fn canonicalization_error() -> Self {
        Self::new(
            AshErrorCode::CanonicalizationError,
            "Failed to canonicalize payload",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_http_status() {
        // Context errors (450-459)
        assert_eq!(AshErrorCode::CtxNotFound.http_status(), 450);
        assert_eq!(AshErrorCode::CtxExpired.http_status(), 451);
        assert_eq!(AshErrorCode::CtxAlreadyUsed.http_status(), 452);
        // Seal/Proof errors (460-469)
        assert_eq!(AshErrorCode::ProofInvalid.http_status(), 460);
        // Binding errors (461)
        assert_eq!(AshErrorCode::BindingMismatch.http_status(), 461);
        // Verification errors (473-479)
        assert_eq!(AshErrorCode::ScopeMismatch.http_status(), 473);
        assert_eq!(AshErrorCode::ChainBroken.http_status(), 474);
        assert_eq!(AshErrorCode::ScopedFieldMissing.http_status(), 475);
        // Format/Protocol errors (480-489)
        assert_eq!(AshErrorCode::TimestampInvalid.http_status(), 482);
        assert_eq!(AshErrorCode::ProofMissing.http_status(), 483);
        assert_eq!(AshErrorCode::CanonicalizationError.http_status(), 484);
        assert_eq!(AshErrorCode::ValidationError.http_status(), 485);
        assert_eq!(AshErrorCode::ModeViolation.http_status(), 486);
        // Standard HTTP codes (unique, 1:1 mapping)
        assert_eq!(AshErrorCode::UnsupportedContentType.http_status(), 415);
        assert_eq!(AshErrorCode::InternalError.http_status(), 500);
    }

    #[test]
    fn test_error_code_as_str() {
        assert_eq!(AshErrorCode::CtxNotFound.as_str(), "ASH_CTX_NOT_FOUND");
        assert_eq!(AshErrorCode::CtxAlreadyUsed.as_str(), "ASH_CTX_ALREADY_USED");
    }

    #[test]
    fn test_error_display() {
        let err = AshError::ctx_not_found();
        assert_eq!(err.to_string(), "ASH_CTX_NOT_FOUND: Context not found");
    }

    #[test]
    fn test_error_convenience_functions() {
        assert_eq!(
            AshError::ctx_not_found().code(),
            AshErrorCode::CtxNotFound
        );
        assert_eq!(
            AshError::ctx_expired().code(),
            AshErrorCode::CtxExpired
        );
        assert_eq!(
            AshError::ctx_already_used().code(),
            AshErrorCode::CtxAlreadyUsed
        );
    }

    // CR-001: Verify serde serialization produces spec-compliant ASH_ prefixed strings
    #[test]
    fn test_error_code_serde_serialization() {
        // Serialize: should produce ASH_ prefixed strings
        let serialized = serde_json::to_string(&AshErrorCode::CtxNotFound).unwrap();
        assert_eq!(serialized, r#""ASH_CTX_NOT_FOUND""#);

        let serialized = serde_json::to_string(&AshErrorCode::ValidationError).unwrap();
        assert_eq!(serialized, r#""ASH_VALIDATION_ERROR""#);

        let serialized = serde_json::to_string(&AshErrorCode::ScopedFieldMissing).unwrap();
        assert_eq!(serialized, r#""ASH_SCOPED_FIELD_MISSING""#);
    }

    #[test]
    fn test_error_code_serde_deserialization() {
        // Deserialize: should accept ASH_ prefixed strings
        let code: AshErrorCode = serde_json::from_str(r#""ASH_CTX_NOT_FOUND""#).unwrap();
        assert_eq!(code, AshErrorCode::CtxNotFound);

        let code: AshErrorCode = serde_json::from_str(r#""ASH_PROOF_INVALID""#).unwrap();
        assert_eq!(code, AshErrorCode::ProofInvalid);

        let code: AshErrorCode = serde_json::from_str(r#""ASH_INTERNAL_ERROR""#).unwrap();
        assert_eq!(code, AshErrorCode::InternalError);
    }

    #[test]
    fn test_error_code_serde_roundtrip_all_variants() {
        // Every variant must roundtrip through serde correctly
        let all_codes = [
            AshErrorCode::CtxNotFound,
            AshErrorCode::CtxExpired,
            AshErrorCode::CtxAlreadyUsed,
            AshErrorCode::BindingMismatch,
            AshErrorCode::ProofMissing,
            AshErrorCode::ProofInvalid,
            AshErrorCode::CanonicalizationError,
            AshErrorCode::ValidationError,
            AshErrorCode::ModeViolation,
            AshErrorCode::UnsupportedContentType,
            AshErrorCode::ScopeMismatch,
            AshErrorCode::ChainBroken,
            AshErrorCode::InternalError,
            AshErrorCode::TimestampInvalid,
            AshErrorCode::ScopedFieldMissing,
        ];

        for code in &all_codes {
            let serialized = serde_json::to_string(code).unwrap();
            // Verify ASH_ prefix is present
            assert!(serialized.contains("ASH_"), "Missing ASH_ prefix for {:?}: {}", code, serialized);
            // Verify roundtrip
            let deserialized: AshErrorCode = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*code, deserialized, "Roundtrip failed for {:?}", code);
            // Verify as_str() matches serialized value (minus quotes)
            let expected = format!("\"{}\"", code.as_str());
            assert_eq!(serialized, expected, "Serde output doesn't match as_str() for {:?}", code);
        }
    }

    #[test]
    fn test_retryable_timestamp_invalid() {
        assert!(AshErrorCode::TimestampInvalid.retryable());
    }

    #[test]
    fn test_retryable_internal_error() {
        assert!(AshErrorCode::InternalError.retryable());
    }

    #[test]
    fn test_not_retryable_proof_invalid() {
        assert!(!AshErrorCode::ProofInvalid.retryable());
    }

    #[test]
    fn test_not_retryable_validation_error() {
        assert!(!AshErrorCode::ValidationError.retryable());
    }

    #[test]
    fn test_retryable_ctx_already_used() {
        // BUG-072: CtxAlreadyUsed is retryable due to distributed replication lag
        assert!(AshErrorCode::CtxAlreadyUsed.retryable());
    }

    #[test]
    fn test_not_retryable_all_permanent_codes() {
        let permanent = [
            AshErrorCode::CtxNotFound,
            AshErrorCode::CtxExpired,
            AshErrorCode::ProofInvalid,
            AshErrorCode::BindingMismatch,
            AshErrorCode::ScopeMismatch,
            AshErrorCode::ChainBroken,
            AshErrorCode::ScopedFieldMissing,
            AshErrorCode::ProofMissing,
            AshErrorCode::CanonicalizationError,
            AshErrorCode::ValidationError,
            AshErrorCode::ModeViolation,
            AshErrorCode::UnsupportedContentType,
        ];
        for code in &permanent {
            assert!(!code.retryable(), "{:?} should not be retryable", code);
        }
    }

    #[test]
    fn test_ash_error_retryable_delegates() {
        let retryable = AshError::new(AshErrorCode::TimestampInvalid, "skew");
        assert!(retryable.retryable());

        let permanent = AshError::new(AshErrorCode::ProofInvalid, "bad proof");
        assert!(!permanent.retryable());
    }

    #[test]
    fn test_error_code_serde_rejects_invalid() {
        // Invalid error code strings should fail to deserialize
        let result: Result<AshErrorCode, _> = serde_json::from_str(r#""INVALID_CODE""#);
        assert!(result.is_err());

        // Without ASH_ prefix should fail
        let result: Result<AshErrorCode, _> = serde_json::from_str(r#""CTX_NOT_FOUND""#);
        assert!(result.is_err());
    }
}
