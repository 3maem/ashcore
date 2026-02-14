//! Canonical header extraction for ashcore.
//!
//! This module provides a single, authoritative function for extracting
//! ASH-required headers from any HTTP framework. Middlewares should use
//! `ash_extract_headers()` instead of reimplementing header parsing.
//!
//! ## Why This Exists
//!
//! Previously, every middleware (Express, FastAPI, Laravel, Gin, etc.)
//! reimplemented header extraction with subtle differences in:
//! - Case-insensitive lookup
//! - Multi-value handling
//! - Whitespace trimming
//! - Control character rejection
//!
//! This caused systemic bugs (null nonce bypasses, enum mismatches).
//! Moving extraction into Core eliminates this entire bug class.

use crate::errors::{AshError, AshErrorCode, InternalReason};

// ── Header Names (constants) ─────────────────────────────────────────

/// ASH timestamp header name.
pub const HDR_TIMESTAMP: &str = "x-ash-ts";

/// ASH nonce header name.
pub const HDR_NONCE: &str = "x-ash-nonce";

/// ASH body hash header name.
pub const HDR_BODY_HASH: &str = "x-ash-body-hash";

/// ASH proof header name.
pub const HDR_PROOF: &str = "x-ash-proof";

/// ASH context ID header name.
pub const HDR_CONTEXT_ID: &str = "x-ash-context-id";

/// L9-FIX: Maximum length for any ASH header value in bytes.
/// The longest legitimate value is a SHA-256 hex string (64 chars) or a nonce
/// (up to 512 chars). 4096 bytes provides generous headroom while preventing
/// memory exhaustion from adversarial header values.
const MAX_HEADER_VALUE_LENGTH: usize = 4096;

// ── Trait ─────────────────────────────────────────────────────────────

/// Framework-agnostic header map interface.
///
/// Implement this trait for your HTTP framework's header type to use
/// `ash_extract_headers()`. The implementation must support case-insensitive
/// lookup and returning all values for a given header name.
///
/// # Example (test helper)
///
/// ```rust
/// use ashcore::headers::HeaderMapView;
///
/// struct SimpleHeaders(Vec<(String, String)>);
///
/// impl HeaderMapView for SimpleHeaders {
///     fn get_all_ci(&self, name: &str) -> Vec<&str> {
///         let name_lower = name.to_ascii_lowercase();
///         self.0.iter()
///             .filter(|(k, _)| k.to_ascii_lowercase() == name_lower)
///             .map(|(_, v)| v.as_str())
///             .collect()
///     }
/// }
/// ```
pub trait HeaderMapView {
    /// Return all values for the given header name (case-insensitive).
    ///
    /// Must return an empty Vec if the header is not present.
    /// Must return multiple entries if the header appears multiple times.
    fn get_all_ci(&self, name: &str) -> Vec<&str>;
}

// ── Bundle ────────────────────────────────────────────────────────────

/// Extracted ASH headers, validated and trimmed.
///
/// All required headers are present and contain exactly one value
/// with no control characters.
/// # Security Note
///
/// The `nonce` and `proof` fields contain security-sensitive values. The `Debug`
/// implementation redacts them to prevent accidental exposure in logs.
#[derive(Clone)]
pub struct HeaderBundle {
    /// Unix timestamp string (validated present, not yet parsed)
    pub ts: String,
    /// Nonce string (validated present, not yet format-checked)
    pub nonce: String,
    /// Body hash hex string (validated present)
    pub body_hash: String,
    /// Proof hex string (validated present)
    pub proof: String,
    /// Context ID (optional header)
    pub context_id: Option<String>,
}

/// BUG-091: Custom Debug that redacts nonce and proof to prevent accidental log exposure.
impl std::fmt::Debug for HeaderBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderBundle")
            .field("ts", &self.ts)
            .field("nonce", &"[REDACTED]")
            .field("body_hash", &self.body_hash)
            .field("proof", &"[REDACTED]")
            .field("context_id", &self.context_id)
            .finish()
    }
}

// ── Extraction ────────────────────────────────────────────────────────

/// Extract and validate all required ASH headers from a request.
///
/// # Validation Rules
///
/// - Case-insensitive header lookup
/// - Missing required header → `ASH_VALIDATION_ERROR` (485)
/// - Multiple values for a single-value header → `ASH_VALIDATION_ERROR` (485)
/// - Control characters or newlines in value → `ASH_VALIDATION_ERROR` (485)
/// - Leading/trailing whitespace is trimmed
///
/// # Required Headers
///
/// - `x-ash-ts` — timestamp
/// - `x-ash-nonce` — nonce
/// - `x-ash-body-hash` — body hash
/// - `x-ash-proof` — proof
///
/// # Optional Headers
///
/// - `x-ash-context-id` — context ID (present if server-managed contexts are used)
///
/// # Example
///
/// ```rust
/// use ashcore::headers::{HeaderMapView, ash_extract_headers};
///
/// struct TestHeaders(Vec<(String, String)>);
/// impl HeaderMapView for TestHeaders {
///     fn get_all_ci(&self, name: &str) -> Vec<&str> {
///         let n = name.to_ascii_lowercase();
///         self.0.iter()
///             .filter(|(k, _)| k.to_ascii_lowercase() == n)
///             .map(|(_, v)| v.as_str())
///             .collect()
///     }
/// }
///
/// let headers = TestHeaders(vec![
///     ("X-ASH-TS".into(), "1700000000".into()),
///     ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
///     ("X-Ash-Body-Hash".into(), "a".repeat(64)),
///     ("x-ash-proof".into(), "b".repeat(64)),
/// ]);
///
/// let bundle = ash_extract_headers(&headers).unwrap();
/// assert_eq!(bundle.ts, "1700000000");
/// assert!(bundle.context_id.is_none());
/// ```
pub fn ash_extract_headers(h: &impl HeaderMapView) -> Result<HeaderBundle, AshError> {
    let ts = get_one(h, HDR_TIMESTAMP)?;
    let nonce = get_one(h, HDR_NONCE)?;
    let body_hash = get_one(h, HDR_BODY_HASH)?;
    let proof = get_one(h, HDR_PROOF)?;
    let context_id = get_optional_one(h, HDR_CONTEXT_ID)?;

    Ok(HeaderBundle {
        ts,
        nonce,
        body_hash,
        proof,
        context_id,
    })
}

/// Extract exactly one value for a required header.
///
/// BUG-066: Made pub(crate) so verify.rs can reuse this instead of
/// maintaining a duplicate `extract_single_header` function.
pub(crate) fn get_one(h: &impl HeaderMapView, name: &'static str) -> Result<String, AshError> {
    let vals = h.get_all_ci(name);

    if vals.is_empty() {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrMissing,
                format!("Required header '{}' is missing", name),
            )
            .with_detail("header", name),
        );
    }
    if vals.len() > 1 {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrMultiValue,
                format!("Header '{}' must have exactly one value, got {}", name, vals.len()),
            )
            .with_detail("header", name)
            .with_detail("count", vals.len().to_string()),
        );
    }

    // L9-FIX: Reject oversized header values to prevent memory exhaustion.
    if vals[0].len() > MAX_HEADER_VALUE_LENGTH {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::General,
                format!("Header '{}' exceeds maximum length", name),
            )
            .with_detail("header", name),
        );
    }

    // M9-FIX: Detect comma-concatenated multi-value headers.
    // Some HTTP frameworks merge duplicate headers with commas per RFC 7230 §3.2.2.
    // A single value containing commas likely indicates concatenated duplicates.
    // This check prevents bypass of the multi-value check above.
    if vals[0].contains(',') && (name == HDR_TIMESTAMP || name == HDR_NONCE || name == HDR_PROOF || name == HDR_BODY_HASH) {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrMultiValue,
                format!("Header '{}' appears to contain comma-concatenated values", name),
            )
            .with_detail("header", name),
        );
    }

    // BUG-051: Check for control chars on the RAW value BEFORE trimming.
    // Trimming first would silently strip trailing \r\n, masking CRLF injection.
    if contains_ctl_or_newlines(vals[0]) {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrInvalidChars,
                format!("Header '{}' contains invalid characters", name),
            )
            .with_detail("header", name),
        );
    }

    let v = vals[0].trim();

    // BUG-093: Reject whitespace-only required headers. After trimming, a value
    // that was only whitespace (e.g., "   ") becomes empty. This must be rejected
    // for required headers — otherwise it passes non-empty checks downstream but
    // carries no meaningful value.
    if v.is_empty() {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrMissing,
                format!("Required header '{}' has empty value", name),
            )
            .with_detail("header", name),
        );
    }

    Ok(v.to_string())
}

/// Extract at most one value for an optional header.
fn get_optional_one(h: &impl HeaderMapView, name: &'static str) -> Result<Option<String>, AshError> {
    let vals = h.get_all_ci(name);

    if vals.is_empty() {
        return Ok(None);
    }
    if vals.len() > 1 {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrMultiValue,
                format!("Header '{}' must have exactly one value, got {}", name, vals.len()),
            )
            .with_detail("header", name)
            .with_detail("count", vals.len().to_string()),
        );
    }

    // L9-FIX: Reject oversized header values to prevent memory exhaustion.
    // Matches the same check in get_one() for defense-in-depth consistency.
    if vals[0].len() > MAX_HEADER_VALUE_LENGTH {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::General,
                format!("Header '{}' exceeds maximum length", name),
            )
            .with_detail("header", name),
        );
    }

    // BUG-051: Check for control chars on the RAW value BEFORE trimming.
    if contains_ctl_or_newlines(vals[0]) {
        return Err(
            AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::HdrInvalidChars,
                format!("Header '{}' contains invalid characters", name),
            )
            .with_detail("header", name),
        );
    }

    let v = vals[0].trim();
    // BUG-072: Treat whitespace-only optional headers as absent rather than
    // returning Some(""), which would pass non-empty checks downstream but
    // carry no meaningful value.
    if v.is_empty() {
        return Ok(None);
    }
    Ok(Some(v.to_string()))
}

/// Check if a string contains control characters or newlines.
fn contains_ctl_or_newlines(s: &str) -> bool {
    s.chars().any(|c| c == '\r' || c == '\n' || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simple test implementation of HeaderMapView.
    struct TestHeaders(Vec<(String, String)>);

    impl HeaderMapView for TestHeaders {
        fn get_all_ci(&self, name: &str) -> Vec<&str> {
            let name_lower = name.to_ascii_lowercase();
            self.0
                .iter()
                .filter(|(k, _)| k.to_ascii_lowercase() == name_lower)
                .map(|(_, v)| v.as_str())
                .collect()
        }
    }

    fn valid_headers() -> TestHeaders {
        TestHeaders(vec![
            ("X-ASH-TS".into(), "1700000000".into()),
            ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
            ("X-Ash-Body-Hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ])
    }

    #[test]
    fn test_extract_all_required() {
        let bundle = ash_extract_headers(&valid_headers()).unwrap();
        assert_eq!(bundle.ts, "1700000000");
        assert_eq!(bundle.nonce, "0123456789abcdef0123456789abcdef");
        assert_eq!(bundle.body_hash, "a".repeat(64));
        assert_eq!(bundle.proof, "b".repeat(64));
        assert!(bundle.context_id.is_none());
    }

    #[test]
    fn test_extract_with_context_id() {
        let mut h = valid_headers();
        h.0.push(("X-ASH-Context-ID".into(), "ctx_abc123".into()));
        let bundle = ash_extract_headers(&h).unwrap();
        assert_eq!(bundle.context_id, Some("ctx_abc123".into()));
    }

    #[test]
    fn test_case_insensitive() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("X-ASH-NONCE".into(), "0123456789abcdef0123456789abcdef".into()),
            ("X-Ash-Body-Hash".into(), "a".repeat(64)),
            ("x-AsH-pRoOf".into(), "b".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_ok());
    }

    #[test]
    fn test_missing_timestamp() {
        let h = TestHeaders(vec![
            ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.http_status(), 485);
        assert_eq!(err.reason(), InternalReason::HdrMissing);
        assert!(err.details().unwrap().get("header").unwrap().contains("ts"));
    }

    #[test]
    fn test_missing_nonce() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.reason(), InternalReason::HdrMissing);
    }

    #[test]
    fn test_multi_value_nonce() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-nonce".into(), "aaa".into()),
            ("x-ash-nonce".into(), "bbb".into()),
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.http_status(), 485);
        assert_eq!(err.reason(), InternalReason::HdrMultiValue);
    }

    #[test]
    fn test_control_chars_in_proof() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "proof\ninjection".into()),
        ]);
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.reason(), InternalReason::HdrInvalidChars);
    }

    #[test]
    fn test_trimming() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "  1700000000  ".into()),
            ("x-ash-nonce".into(), " 0123456789abcdef0123456789abcdef ".into()),
            ("x-ash-body-hash".into(), format!(" {} ", "a".repeat(64))),
            ("x-ash-proof".into(), format!(" {} ", "b".repeat(64))),
        ]);
        let bundle = ash_extract_headers(&h).unwrap();
        assert_eq!(bundle.ts, "1700000000");
        assert_eq!(bundle.nonce, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn test_multi_value_optional_context_id() {
        let mut h = valid_headers();
        h.0.push(("x-ash-context-id".into(), "ctx_1".into()));
        h.0.push(("X-ASH-Context-ID".into(), "ctx_2".into()));
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.reason(), InternalReason::HdrMultiValue);
    }
}
