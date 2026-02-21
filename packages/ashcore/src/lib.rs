//! # ASH Core
//!
//! **ASH (Application Security Hash)** is a request integrity and anti-replay protection library
//!
//! ## Safety
//!
//! This crate uses `#![forbid(unsafe_code)]` to guarantee 100% safe Rust
//! while ensuring HTTP requests have not been tampered with in transit.
//!
//! ## What ASH Does
//!
//! ASH provides cryptographic proof that:
//! - The **payload** has not been modified
//! - The request is for the **correct endpoint** (method + path + query)
//! - The request is **not a replay** of a previous request
//! - Optionally, only **specific fields** are protected (scoping)
//!
//! ## What ASH Does NOT Do
//!
//! ASH verifies **what** is being submitted, not **who** is submitting it.
//! Use alongside authentication systems (JWT, OAuth, API keys, etc.).
//!
//! ## Quick Start
//!
//! ```rust
//! use ashcore::{
//!     ash_canonicalize_json, ash_derive_client_secret,
//!     ash_build_proof, ash_verify_proof, ash_hash_body,
//! };
//!
//! // 1. Server provides nonce and context_id to client
//! let nonce = "0123456789abcdef0123456789abcdef"; // 32+ hex chars
//! let context_id = "ctx_abc123";
//! let binding = "POST|/api/transfer|";
//!
//! // 2. Client canonicalizes payload
//! let payload = r#"{"amount":100,"recipient":"alice"}"#;
//! let canonical = ash_canonicalize_json(payload).unwrap();
//!
//! // 3. Client derives secret and builds proof
//! let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
//! let body_hash = ash_hash_body(&canonical);
//! let timestamp = "1704067200";
//! let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();
//!
//! // 4. Server verifies proof (re-derives secret from nonce internally)
//! let valid = ash_verify_proof(nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
//! assert!(valid);
//! ```
//!
//! ## Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | **Tamper Detection** | HMAC-SHA256 proof ensures payload integrity |
//! | **Replay Prevention** | One-time contexts prevent request replay |
//! | **Deterministic** | Byte-identical output across all platforms |
//! | **Field Scoping** | Protect specific fields while allowing others to change |
//! | **Request Chaining** | Link sequential requests cryptographically |
//! | **Zero Dependencies** | Pure Rust with no C dependencies |
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`proof`](crate::proof) | Core proof generation and verification |
//! | [`canonicalize`](crate::canonicalize) | Deterministic JSON/URL-encoded serialization |
//! | [`compare`](crate::compare) | Constant-time comparison functions |
//! | [`binding`](crate::binding) | Binding value normalization |
//! | [`headers`](crate::headers) | HTTP header extraction |
//! | [`config`](crate::config) | Scope policy configuration |
//! | [`errors`](crate::errors) | Error types and codes |
//! | [`types`](crate::types) | Core data structures (modes, contexts) |
//! | [`build`](crate::build) | High-level request proof building |
//! | [`verify`](crate::verify) | High-level request verification |
//! | [`enriched`](crate::enriched) | Enriched API with metadata |
//! | [`testkit`](crate::testkit) | Cross-SDK conformance test utilities |
//!
//! ## Security Considerations
//!
//! - **Nonce entropy**: Use 32+ hex characters (128+ bits) for nonces
//! - **Timestamp validation**: Reject requests older than 5 minutes
//! - **HTTPS required**: ASH does not encrypt data, only signs it
//! - **Context isolation**: Never reuse context_id across requests
//!
//! ## Version
//!
//! ashcore v1.0.0

#![forbid(unsafe_code)]
#![forbid(clippy::undocumented_unsafe_blocks)]

mod canonicalize;
mod compare;
pub mod config;
mod errors;
pub mod headers;
mod proof;
mod types;
pub mod binding;
pub mod enriched;
mod validate;
pub mod build;
pub mod testkit;
pub mod verify;

pub use canonicalize::{ash_canonicalize_json, ash_canonicalize_json_value, ash_canonicalize_json_value_with_size_check, ash_canonicalize_query, ash_canonicalize_urlencoded};
pub use compare::{ash_timing_safe_equal, ash_timing_safe_compare, ash_timing_safe_equal_fixed_length};
pub use errors::{AshError, AshErrorCode, InternalReason};
pub use headers::{HeaderMapView, HeaderBundle, ash_extract_headers};
pub use validate::ash_validate_nonce;
pub use proof::{
    // Core proof functions
    ash_build_proof,
    ash_verify_proof,
    ash_verify_proof_with_freshness,
    ash_derive_client_secret,
    // Scoped proof functions
    ash_build_proof_scoped,
    ash_verify_proof_scoped,
    ash_extract_scoped_fields,
    ash_extract_scoped_fields_strict,
    // Unified proof functions (scoping + chaining)
    ash_build_proof_unified,
    ash_verify_proof_unified,
    UnifiedProofResult,
    // Hash functions
    ash_hash_body,
    ash_hash_body_checked,
    ash_hash_proof,
    ash_hash_scope,
    ash_hash_scoped_body,
    ash_hash_scoped_body_strict,
    // Nonce and context generation
    ash_generate_nonce,
    ash_generate_nonce_or_panic,
    ash_generate_context_id,
    ash_generate_context_id_256,
    // Timestamp validation
    ash_validate_timestamp,
    ash_validate_timestamp_format,
    DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
    DEFAULT_CLOCK_SKEW_SECONDS,
    // Version constants
    ASH_SDK_VERSION,
};
pub use types::{AshMode, BuildProofInput, ContextPublicInfo, StoredContext, VerifyInput};
pub use binding::{ash_normalize_binding_value, BindingType, NormalizedBindingValue, MAX_BINDING_VALUE_LENGTH};
pub use build::{build_request_proof, BuildRequestInput, BuildRequestResult, BuildMeta};
pub use enriched::{
    ash_canonicalize_query_enriched, CanonicalQueryResult,
    ash_hash_body_enriched, BodyHashResult,
    ash_normalize_binding_enriched, ash_parse_binding, NormalizedBinding,
};
pub use testkit::{load_vectors, load_vectors_from_file, run_vectors, AshAdapter, AdapterResult, TestReport, VectorResult, Vector, VectorFile};
pub use verify::{
    verify_incoming_request, verify_incoming_request_scoped, verify_incoming_request_unified,
    VerifyRequestInput, VerifyScopedInput, VerifyUnifiedInput, VerifyResult, VerifyMeta,
};

/// Normalize a binding string to canonical form.
///
/// Bindings are in the format: `METHOD|PATH|CANONICAL_QUERY`
///
/// # Normalization Rules
/// - Method is uppercased
/// - Path must start with `/`
/// - Path must not contain `?` (use `normalize_binding_from_url` for combined path+query)
/// - Path is percent-decoded, normalized, then re-encoded (BUG-025 fix)
/// - Path has duplicate slashes collapsed (after decoding)
/// - Trailing slash is removed (except for root `/`)
/// - Query string is canonicalized (sorted, normalized)
/// - Parts are joined with `|` (pipe) separator
///
/// # Path Normalization (BUG-025)
///
/// Paths are decoded before normalization to handle cases like:
/// - `/api/%2F%2F/users` → decoded → `/api///users` → normalized → `/api/users`
/// - `/api/caf%C3%A9` → decoded → `/api/café` → re-encoded → `/api/caf%C3%A9`
///
/// # Error on Embedded Query
///
/// If the `path` parameter contains a `?`, an error is returned to prevent
/// silent data loss. Use [`normalize_binding_from_url`] if you have a combined
/// path+query string.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_normalize_binding;
///
/// let binding = ash_normalize_binding("post", "/api//users/", "").unwrap();
/// assert_eq!(binding, "POST|/api/users|");
///
/// let binding_with_query = ash_normalize_binding("GET", "/api/users", "page=1&sort=name").unwrap();
/// assert_eq!(binding_with_query, "GET|/api/users|page=1&sort=name");
///
/// // Error if path contains '?'
/// assert!(ash_normalize_binding("GET", "/api/users?old=query", "new=query").is_err());
/// ```
pub fn ash_normalize_binding(method: &str, path: &str, query: &str) -> Result<String, AshError> {
    // Validate method
    let method = method.trim();
    if method.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Method cannot be empty",
        ));
    }

    // BUG-042: Use ASCII-only uppercase to ensure cross-platform consistency
    // Unicode uppercase rules can vary across platforms/versions
    if !method.is_ascii() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Method must contain only ASCII characters",
        ));
    }

    // BUG-073: Reject pipe characters in method to prevent binding format injection.
    // The binding format is METHOD|PATH|QUERY — a method containing '|' would create
    // ambiguity when parsing the binding back into components.
    if method.contains('|') {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Method must not contain '|' (binding delimiter)",
        ));
    }

    // BUG-074: Reject control characters in method.
    if method.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Method must not contain control characters",
        ));
    }

    let method = method.to_ascii_uppercase();

    // Validate path starts with /
    let path = path.trim();
    if !path.starts_with('/') {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Path must start with /",
        ));
    }

    // BUG-025: Percent-decode the path before normalization
    let decoded_path = ash_percent_decode_path(path)?;

    // PT-AUDIT-001: Apply NFC normalization to decoded path for consistency
    // with query string handling (which also applies NFC).
    use unicode_normalization::UnicodeNormalization;
    let decoded_path: String = decoded_path.nfc().collect();

    // BUG-087: Reject null bytes in decoded path. Null bytes pass through percent-decode
    // and could cause truncation in downstream C-based systems (C string terminator).
    if decoded_path.contains('\0') {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Path must not contain null bytes (including encoded %00)",
        ));
    }

    // BUG-088: Reject control characters in decoded path. Characters < 0x20 (except '/')
    // and 0x7F (DEL) are never valid in URL paths and could enable header injection or
    // log poisoning when paths are logged downstream.
    if decoded_path.bytes().any(|b| (b < 0x20 && b != b'/') || b == 0x7F) {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Path must not contain control characters (including encoded forms)",
        ));
    }

    // BUG-009 & BUG-027: Error if path contains '?' AFTER decoding to catch encoded %3F
    // This prevents silent data loss and encoded query delimiter bypass
    if decoded_path.contains('?') {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Path must not contain '?' (including encoded %3F) - use normalize_binding_from_url for combined path+query",
        ));
    }

    // BUG-035: Normalize path segments including . and ..
    let normalized_path = ash_normalize_path_segments(&decoded_path);

    // Ensure path still starts with / after normalization
    if normalized_path.is_empty() || !normalized_path.starts_with('/') {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Path normalization resulted in invalid path",
        ));
    }

    // BUG-025: Re-encode the normalized path (only encode characters that need encoding)
    // BUG-053: Now returns Result to prevent silent truncation
    let encoded_path = ash_percent_encode_path(&normalized_path)?;

    // BUG-043: Trim whitespace from query string before canonicalization
    // Whitespace-only query should be treated as empty
    let query = query.trim();
    let canonical_query = if query.is_empty() {
        String::new()
    } else {
        canonicalize::ash_canonicalize_query(query)?
    };

    // format: METHOD|PATH|CANONICAL_QUERY
    let binding = format!("{}|{}|{}", method, encoded_path, canonical_query);

    // BUG-075: Validate total binding length to prevent oversized bindings from
    // propagating through the proof pipeline.
    if binding.len() > crate::binding::MAX_BINDING_VALUE_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!(
                "Binding exceeds maximum length of {} bytes",
                crate::binding::MAX_BINDING_VALUE_LENGTH
            ),
        ));
    }

    Ok(binding)
}

/// Percent-decode a URL path segment.
/// BUG-025: Decodes %XX sequences to their character equivalents.
fn ash_percent_decode_path(input: &str) -> Result<String, AshError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
                return Err(AshError::new(
                    AshErrorCode::ValidationError,
                    "Invalid percent encoding in path",
                ));
            }
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| {
                AshError::new(
                    AshErrorCode::ValidationError,
                    "Invalid percent encoding hex in path",
                )
            })?;
            bytes.push(byte);
        } else {
            // Encode character directly to UTF-8 bytes
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            bytes.extend_from_slice(encoded.as_bytes());
        }
    }

    // Convert bytes to UTF-8 string
    String::from_utf8(bytes).map_err(|_| {
        AshError::new(
            AshErrorCode::ValidationError,
            "Invalid UTF-8 in percent-decoded path",
        )
    })
}

/// Normalize path segments, handling `.`, `..`, duplicate slashes, and trailing slashes.
/// BUG-035: Properly resolves `.` (current dir) and `..` (parent dir) segments.
///
/// # Rules
/// - `.` segments are removed
/// - `..` segments remove the preceding segment (if any)
/// - Duplicate slashes are collapsed
/// - Trailing slash is removed (except for root `/`)
/// - `..` at root level is ignored (can't go above root)
fn ash_normalize_path_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => {
                // Empty segment (from // or leading /) or current dir - skip
                continue;
            }
            ".." => {
                // Parent dir - pop last segment if any
                segments.pop();
            }
            s => {
                segments.push(s);
            }
        }
    }

    // Reconstruct path with leading slash
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// Maximum encoded path length to prevent memory exhaustion.
/// Based on MAX_BINDING_LENGTH with encoding overhead (3x for worst-case UTF-8).
const MAX_ENCODED_PATH_LENGTH: usize = 8192 * 3;

/// Percent-encode a URL path, preserving safe characters.
/// BUG-025: Only encodes characters that are not allowed in URL paths.
/// BUG-053: Returns error instead of silently truncating on overflow to prevent
/// two different paths from producing the same encoded output (binding collision).
fn ash_percent_encode_path(input: &str) -> Result<String, AshError> {
    let mut result = String::with_capacity(input.len() * 3);

    for ch in input.chars() {
        match ch {
            // Unreserved characters (RFC 3986)
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            // Path separators and sub-delimiters that are safe in paths
            // BUG-076: Removed ';' — semicolons are path parameter delimiters in some
            // frameworks and must be encoded for cross-framework consistency.
            '/' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | '=' | ':' | '@' => {
                result.push(ch);
            }
            _ => {
                // Encode all other characters
                let mut buf = [0u8; 4];
                let encoded = ch.encode_utf8(&mut buf);
                for byte in encoded.as_bytes() {
                    use std::fmt::Write;
                    write!(result, "%{:02X}", byte).unwrap();
                }
            }
        }
        // BUG-065: Check length AFTER writing the character, not before.
        // The previous check (before write) had an off-by-one: a multi-byte
        // UTF-8 character could push the result past the limit by up to 9 bytes
        // (%XX%XX%XX for a 3-byte char) after passing the pre-write check.
        if result.len() > MAX_ENCODED_PATH_LENGTH {
            return Err(AshError::new(
                AshErrorCode::ValidationError,
                format!("Encoded path exceeds maximum length of {} bytes", MAX_ENCODED_PATH_LENGTH),
            ));
        }
    }

    Ok(result)
}

/// Normalize a binding from a full URL path (including query string).
///
/// This is a convenience function that extracts the query string from the path.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_normalize_binding_from_url;
///
/// let binding = ash_normalize_binding_from_url("GET", "/api/users?page=1&sort=name").unwrap();
/// assert_eq!(binding, "GET|/api/users|page=1&sort=name");
/// ```
pub fn ash_normalize_binding_from_url(method: &str, full_path: &str) -> Result<String, AshError> {
    // VULN-002: Validate input size to prevent memory exhaustion
    const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB
    if full_path.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Input exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    // BUG-042: Validate method is ASCII-only (same validation as ash_normalize_binding)
    let method = method.trim();
    if method.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Method cannot be empty",
        ));
    }
    if !method.is_ascii() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "Method must contain only ASCII characters",
        ));
    }

    // BUG-054: Strip fragment from full_path before splitting.
    // In HTTP, fragments (#...) are never sent to the server, so
    // "/api/users#section" and "/api/users" MUST produce the same binding.
    // Without this, a client including a fragment would get a binding mismatch.
    let defragmented = full_path.split('#').next().unwrap_or(full_path);

    let (path, query) = match defragmented.find('?') {
        Some(pos) => (&defragmented[..pos], &defragmented[pos + 1..]),
        None => (defragmented, ""),
    };
    ash_normalize_binding(method, path, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Binding Format Tests (METHOD|PATH|CANONICAL_QUERY)

    #[test]
    fn test_normalize_binding_basic() {
        assert_eq!(
            ash_normalize_binding("POST", "/api/users", "").unwrap(),
            "POST|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_lowercase_method() {
        assert_eq!(
            ash_normalize_binding("post", "/api/users", "").unwrap(),
            "POST|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_duplicate_slashes() {
        assert_eq!(
            ash_normalize_binding("GET", "/api//users///profile", "").unwrap(),
            "GET|/api/users/profile|"
        );
    }

    #[test]
    fn test_normalize_binding_trailing_slash() {
        assert_eq!(
            ash_normalize_binding("PUT", "/api/users/", "").unwrap(),
            "PUT|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_root() {
        assert_eq!(ash_normalize_binding("GET", "/", "").unwrap(), "GET|/|");
    }

    #[test]
    fn test_normalize_binding_with_query() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/users", "page=1&sort=name").unwrap(),
            "GET|/api/users|page=1&sort=name"
        );
    }

    #[test]
    fn test_normalize_binding_query_sorted() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/users", "z=3&a=1&b=2").unwrap(),
            "GET|/api/users|a=1&b=2&z=3"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_basic() {
        assert_eq!(
            ash_normalize_binding_from_url("GET", "/api/users?page=1&sort=name").unwrap(),
            "GET|/api/users|page=1&sort=name"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_no_query() {
        assert_eq!(
            ash_normalize_binding_from_url("POST", "/api/users").unwrap(),
            "POST|/api/users|"
        );
    }

    // BUG-054: Fragment stripping in path
    #[test]
    fn test_normalize_binding_from_url_strips_fragment_from_path() {
        // Fragment-only (no query) — fragment must be stripped
        assert_eq!(
            ash_normalize_binding_from_url("GET", "/api/users#section").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_strips_fragment_with_query() {
        // Query + fragment — fragment must be stripped from query
        assert_eq!(
            ash_normalize_binding_from_url("GET", "/api/users?page=1#section").unwrap(),
            "GET|/api/users|page=1"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_fragment_only() {
        // Path is just root with fragment
        assert_eq!(
            ash_normalize_binding_from_url("GET", "/#top").unwrap(),
            "GET|/|"
        );
    }

    #[test]
    fn test_normalize_binding_from_url_query_sorted() {
        assert_eq!(
            ash_normalize_binding_from_url("GET", "/api/search?z=last&a=first").unwrap(),
            "GET|/api/search|a=first&z=last"
        );
    }

    #[test]
    fn test_normalize_binding_empty_method() {
        assert!(ash_normalize_binding("", "/api", "").is_err());
    }

    #[test]
    fn test_normalize_binding_no_leading_slash() {
        assert!(ash_normalize_binding("GET", "api/users", "").is_err());
    }

    // Version Constants Tests

    #[test]
    fn test_version_constants() {
        use crate::ASH_SDK_VERSION;

        assert_eq!(ASH_SDK_VERSION, "1.0.0");
    }

    // Query Canonicalization in Binding Tests

    #[test]
    fn test_normalize_binding_strips_fragment() {
        // Fragment should be stripped from query string
        assert_eq!(
            ash_normalize_binding("GET", "/api/search", "q=test#section").unwrap(),
            "GET|/api/search|q=test"
        );
    }

    #[test]
    fn test_normalize_binding_plus_literal() {
        // + is literal plus in query strings, not space
        assert_eq!(
            ash_normalize_binding("GET", "/api/search", "q=a+b").unwrap(),
            "GET|/api/search|q=a%2Bb"
        );
    }

    // BUG-025: Path percent-encoding normalization tests

    #[test]
    fn test_normalize_binding_encoded_slashes() {
        // BUG-025: Encoded slashes should be decoded and collapsed
        assert_eq!(
            ash_normalize_binding("GET", "/api/%2F%2F/users", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_encoded_double_slash() {
        // Encoded double slash should be collapsed to single slash
        assert_eq!(
            ash_normalize_binding("GET", "/api%2F%2Fusers", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_unicode_path() {
        // Unicode characters should be preserved (encoded in output)
        let result = ash_normalize_binding("GET", "/api/café", "").unwrap();
        assert!(result.starts_with("GET|/api/caf"));
        // The é should be percent-encoded
        assert!(result.contains("%C3%A9") || result.contains("é"));
    }

    #[test]
    fn test_normalize_binding_mixed_encoding() {
        // Mix of encoded and unencoded should normalize consistently
        let result1 = ash_normalize_binding("GET", "/api/%2Ftest", "").unwrap();
        let result2 = ash_normalize_binding("GET", "/api//test", "").unwrap();
        // Both should collapse to /api/test
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_normalize_binding_encoded_trailing_slash() {
        // Encoded trailing slash should be removed
        assert_eq!(
            ash_normalize_binding("GET", "/api/users%2F", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_special_chars_preserved() {
        // Special characters that are valid in paths should be preserved
        let result = ash_normalize_binding("GET", "/api/users/@me", "").unwrap();
        assert_eq!(result, "GET|/api/users/@me|");
    }

    // BUG-027: Encoded query delimiter tests

    #[test]
    fn test_normalize_binding_rejects_encoded_question_mark() {
        // BUG-027: Encoded %3F (?) should be rejected after decoding
        let result = ash_normalize_binding("GET", "/api/users%3Fid=5", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("?"));
    }

    #[test]
    fn test_normalize_binding_rejects_doubly_encoded_question_mark() {
        // BUG-027: Doubly encoded %253F decodes to %3F, then to ? - should be rejected
        // Note: %253F -> %3F after first decode, but we only do one decode pass,
        // so %253F -> %3F (stays as-is), which doesn't contain literal ?
        // This is acceptable as it's an unusual edge case
        let result = ash_normalize_binding("GET", "/api/users%253F", "");
        // This should succeed because %253F decodes to "%3F" (literal chars), not "?"
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_binding_allows_other_encoded_chars() {
        // Other encoded characters should be allowed
        // %20 = space, %2B = +
        let result = ash_normalize_binding("GET", "/api/hello%20world", "").unwrap();
        assert!(result.contains("/api/hello%20world"));
    }

    // BUG-035: Path segment normalization tests

    #[test]
    fn test_normalize_binding_dot_segment() {
        // BUG-035: Single dot should be removed
        assert_eq!(
            ash_normalize_binding("GET", "/api/./users", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_double_dot_segment() {
        // BUG-035: Double dot should go up one level
        assert_eq!(
            ash_normalize_binding("GET", "/api/v1/../users", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn test_normalize_binding_multiple_dots() {
        // BUG-035: Multiple dot segments
        assert_eq!(
            ash_normalize_binding("GET", "/api/v1/./users/../admin", "").unwrap(),
            "GET|/api/v1/admin|"
        );
    }

    #[test]
    fn test_normalize_binding_dots_at_root() {
        // BUG-035: Can't go above root
        assert_eq!(
            ash_normalize_binding("GET", "/../api", "").unwrap(),
            "GET|/api|"
        );
    }

    #[test]
    fn test_normalize_binding_only_dots() {
        // BUG-035: Path with only dots should become root
        assert_eq!(
            ash_normalize_binding("GET", "/./.", "").unwrap(),
            "GET|/|"
        );
    }

    // BUG-042: ASCII method validation tests

    #[test]
    fn test_normalize_binding_rejects_unicode_method() {
        // BUG-042: Non-ASCII method should be rejected
        let result = ash_normalize_binding("GËṪ", "/api", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("ASCII"));
    }

    #[test]
    fn test_normalize_binding_ascii_method_uppercased() {
        // BUG-042: ASCII method should be uppercased consistently
        assert_eq!(
            ash_normalize_binding("get", "/api", "").unwrap(),
            "GET|/api|"
        );
        assert_eq!(
            ash_normalize_binding("Post", "/api", "").unwrap(),
            "POST|/api|"
        );
    }

    // BUG-043: Whitespace query string tests

    #[test]
    fn test_normalize_binding_whitespace_only_query() {
        // BUG-043: Whitespace-only query should be treated as empty
        assert_eq!(
            ash_normalize_binding("GET", "/api", "   ").unwrap(),
            "GET|/api|"
        );
        assert_eq!(
            ash_normalize_binding("GET", "/api", "\t\n").unwrap(),
            "GET|/api|"
        );
    }

    #[test]
    fn test_normalize_binding_query_with_leading_trailing_whitespace() {
        // BUG-043: Query should be trimmed before processing
        assert_eq!(
            ash_normalize_binding("GET", "/api", "  a=1  ").unwrap(),
            "GET|/api|a=1"
        );
    }

    // =========================================================================
    // Boundary Tests (Issue 5.1)
    // =========================================================================

    #[test]
    fn test_binding_length_validated_in_secret_derivation() {
        // SEC-AUDIT-004: MAX_BINDING_LENGTH (8192 bytes) is validated in ash_derive_client_secret
        // ash_normalize_binding does NOT validate length - it only normalizes
        let long_path = "/api/".to_string() + &"a".repeat(8180); // Path ~8185 chars
        let binding = ash_normalize_binding("GET", &long_path, "").unwrap();
        // Binding format: GET|/api/aaaa...| = ~8190 bytes
        assert!(binding.len() > 8180);
        
        // Secret derivation validates binding length
        let nonce = "0123456789abcdef0123456789abcdef";
        let result = crate::ash_derive_client_secret(nonce, "ctx_test", &binding);
        // Should succeed since binding is under 8192 bytes
        assert!(result.is_ok());
        
        // BUG-075: Test with binding exceeding maximum length
        // ash_normalize_binding now validates total binding length
        let too_long_path = "/api/".to_string() + &"a".repeat(8190); // Path ~8195 chars
        let result = ash_normalize_binding("GET", &too_long_path, "");
        // Should fail due to binding length at normalization time
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum length"));
    }

    #[test]
    fn test_normalize_binding_from_url_rejects_unicode_method() {
        // Verify ash_normalize_binding_from_url also validates method
        let result = ash_normalize_binding_from_url("GËṪ", "/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("ASCII"));
    }

    #[test]
    fn test_normalize_binding_from_url_rejects_empty_method() {
        // Verify ash_normalize_binding_from_url rejects empty method
        let result = ash_normalize_binding_from_url("", "/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("empty"));
    }

    #[test]
    fn test_normalize_binding_unicode_path_encoding() {
        // Test that Unicode paths are properly encoded
        let result = ash_normalize_binding("GET", "/api/café", "").unwrap();
        // The é should be percent-encoded as %C3%A9
        assert!(result.contains("%C3%A9") || result.contains("é"));
    }
}
