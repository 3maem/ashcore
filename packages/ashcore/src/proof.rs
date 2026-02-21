//! Cryptographic proof generation and verification using HMAC-SHA256.
//!
//! This module provides the core security functions for ASH:
//!
//! ## Overview
//!
//! ASH (Application Security Hash) proofs are deterministic integrity tokens that:
//! - Verify request payload has not been tampered with
//! - Bind requests to specific endpoints (method + path + query)
//! - Prevent replay attacks through one-time contexts
//! - Support field-level scoping for partial payload protection
//! - Enable request chaining for sequential operations
//!
//! ## Core Functions
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`ash_derive_client_secret`] | Derive HMAC key from server nonce |
//! | [`ash_build_proof`] | Generate proof for a request |
//! | [`ash_verify_proof`] | Verify a proof on the server |
//! | [`ash_hash_body`] | Hash canonicalized payload |
//!
//! ## Scoped Proofs
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`ash_build_proof_scoped`] | Proof protecting specific fields only |
//! | [`ash_verify_proof_scoped`] | Verify scoped proof |
//! | [`ash_extract_scoped_fields`] | Extract fields from payload by scope |
//! | [`ash_hash_scoped_body`] | Hash only scoped fields |
//!
//! ## Unified Proofs (Scoping + Chaining)
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`ash_build_proof_unified`] | Full-featured proof with scoping and chaining |
//! | [`ash_verify_proof_unified`] | Verify unified proof |
//!
//! ## Proof Generation Flow
//!
//! ```text
//! Server                              Client
//!   │                                    │
//!   │──── nonce + context_id ──────────>│
//!   │                                    │
//!   │                                    ├─ derive_client_secret(nonce, context_id, binding)
//!   │                                    │
//!   │                                    ├─ canonicalize(payload)
//!   │                                    │
//!   │                                    ├─ hash_body(canonical_payload)
//!   │                                    │
//!   │                                    ├─ build_proof(client_secret, timestamp, binding, body_hash)
//!   │                                    │
//!   │<─── proof + timestamp + payload ──│
//!   │                                    │
//!   ├─ derive_client_secret(...)        │
//!   ├─ hash_body(...)                   │
//!   ├─ verify_proof(...)                │
//!   │                                    │
//! ```
//!
//! ## Security Properties
//!
//! - **HMAC-SHA256**: Cryptographically secure message authentication
//! - **Constant-time comparison**: Prevents timing attacks during verification
//! - **Minimum entropy**: Requires 128-bit nonces to prevent brute force
//! - **Context binding**: Proofs are invalid for different endpoints
//! - **Timestamp validation**: Prevents replay of old requests
//!
//! ## Example
//!
//! ```rust
//! use ashcore::{
//!     ash_derive_client_secret, ash_build_proof, ash_verify_proof,
//!     ash_hash_body, ash_canonicalize_json,
//! };
//!
//! // Server provides nonce and context_id
//! let nonce = "0123456789abcdef0123456789abcdef";
//! let context_id = "ctx_abc123";
//! let binding = "POST|/api/transfer|";
//!
//! // Client derives secret and builds proof
//! let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
//! let payload = r#"{"amount":100,"recipient":"alice"}"#;
//! let canonical = ash_canonicalize_json(payload).unwrap();
//! let body_hash = ash_hash_body(&canonical);
//! let timestamp = "1704067200";
//! let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();
//!
//! // Server verifies proof (re-derives secret from nonce internally)
//! let is_valid = ash_verify_proof(nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
//! assert!(is_valid);
//! ```

use sha2::{Digest, Sha256};

use crate::compare::ash_timing_safe_equal;
use crate::errors::{AshError, AshErrorCode};

// =========================================================================
// ASH Version Constants
// =========================================================================

/// ASH SDK version (library version).
pub const ASH_SDK_VERSION: &str = "1.0.0";

// =========================================================================
// Core Proof Functions (HMAC-SHA256)
// =========================================================================

use hmac::{Hmac, Mac};
use sha2::Sha256 as HmacSha256;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256Type = Hmac<HmacSha256>;

/// Minimum bytes for nonce generation to ensure adequate entropy.
const MIN_NONCE_BYTES: usize = 16;

// Nonce validation constants are in validate.rs (canonical location).
// SEC-014: 32 hex chars minimum (128 bits entropy).
// SEC-NONCE-001: 512 chars maximum.

/// Maximum array index allowed in scope paths to prevent memory exhaustion.
/// SEC-011: Limits memory allocation when processing scope paths like "items[N]".
const MAX_ARRAY_INDEX: usize = 10000;

/// Maximum total array elements that can be allocated during scope extraction.
/// BUG-036: Prevents DoS via multiple large array allocations.
const MAX_TOTAL_ARRAY_ALLOCATION: usize = 10000;

/// Maximum scope path depth to prevent stack overflow.
/// SEC-019: Limits recursion depth in nested scope paths.
const MAX_SCOPE_PATH_DEPTH: usize = 32;

/// Maximum reasonable timestamp (year 3000 in Unix time).
/// SEC-018: Prevents integer overflow and unreasonable future timestamps.
const MAX_TIMESTAMP: u64 = 32503680000;

/// Maximum number of scope fields to prevent DoS.
/// BUG-018: Limits processing time for scope extraction.
const MAX_SCOPE_FIELDS: usize = 100;

/// Scope field delimiter for hashing (using \x1F unit separator to avoid collision).
/// BUG-002: Prevents collision when field names contain commas.
const SCOPE_FIELD_DELIMITER: char = '\x1F';

/// Maximum binding length to prevent memory exhaustion.
/// SEC-AUDIT-004: Prevents DoS via extremely long bindings.
const MAX_BINDING_LENGTH: usize = 8192; // 8KB

/// Maximum context_id length to prevent DoS via headers/storage.
/// SEC-CTX-001: Limits context_id to reasonable size for headers and storage.
const MAX_CONTEXT_ID_LENGTH: usize = 256;

/// Maximum scope field name length to prevent DoS.
/// SEC-SCOPE-001: Limits individual field name length.
const MAX_SCOPE_FIELD_NAME_LENGTH: usize = 64;

/// Maximum total scope string length after canonicalization.
/// SEC-SCOPE-001: Limits total scope definition size.
const MAX_TOTAL_SCOPE_LENGTH: usize = 4096;

/// Generate a cryptographically secure random nonce.
///
/// # Arguments
/// * `bytes` - Number of bytes (minimum 16, recommended 32)
///
/// # Returns
/// Hex-encoded nonce (64 chars for 32 bytes), or error if RNG fails.
///
/// # Errors
/// Returns error if:
/// - `bytes` is less than 16 (insufficient entropy)
/// - System RNG fails
///
/// # Security (SEC-002)
/// Returns Result instead of panicking on RNG failure.
pub fn ash_generate_nonce(bytes: usize) -> Result<String, AshError> {
    // Validate minimum entropy requirement
    if bytes < MIN_NONCE_BYTES {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Nonce must be at least {} bytes for adequate entropy", MIN_NONCE_BYTES),
        ));
    }

    use getrandom::getrandom;
    use zeroize::Zeroizing;
    // BUG-062: Use Zeroizing wrapper for automatic cleanup on all exit paths
    // (including early returns from getrandom errors). Previously, manual
    // buf.zeroize() only ran on the success path.
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    getrandom(&mut buf).map_err(|e| {
        AshError::new(
            AshErrorCode::InternalError,
            format!("Random number generation failed: {}", e),
        )
    })?;
    let result = hex::encode(&*buf);
    Ok(result)
}

/// Generate a cryptographically secure random nonce (convenience wrapper).
///
/// # Panics
/// Panics if:
/// - `bytes` is less than 16 (insufficient entropy)
/// - System RNG fails
///
/// Use `ash_generate_nonce` for the fallible version that returns `Result`.
///
/// # Deprecated
/// Prefer `ash_generate_nonce()` which returns Result.
pub fn ash_generate_nonce_or_panic(bytes: usize) -> String {
    ash_generate_nonce(bytes).expect("Nonce generation failed (check byte count >= 16 and RNG availability)")
}

/// Generate a unique context ID with "ash_" prefix.
///
/// Uses 128 bits (16 bytes) of randomness by default.
/// For high-security applications, use `generate_context_id_256` for 256 bits.
pub fn ash_generate_context_id() -> Result<String, AshError> {
    Ok(format!("ash_{}", ash_generate_nonce(16)?))
}

/// Generate a unique context ID with 256 bits of entropy.
///
/// # Security (SEC-010)
/// Uses 32 bytes of randomness for applications requiring higher security.
pub fn ash_generate_context_id_256() -> Result<String, AshError> {
    Ok(format!("ash_{}", ash_generate_nonce(32)?))
}

/// Derive client secret from server nonce.
///
/// SECURITY PROPERTIES:
/// - One-way: Cannot derive nonce from clientSecret (HMAC is irreversible)
/// - Context-bound: Unique per contextId + binding combination
/// - Safe to expose: Client can use it but cannot forge other contexts
///
/// # Arguments
///
/// * `nonce` - Server-generated nonce (minimum 32 hex characters for adequate entropy)
/// * `context_id` - Context identifier (must not be empty, must not contain `|` delimiter)
/// * `binding` - Canonical binding string (may contain `|` as part of the `METHOD|PATH|QUERY` format)
///
/// # Errors
///
/// Returns error if:
/// - `nonce` has fewer than 32 hex characters (SEC-014: weak key material)
/// - `nonce` contains non-hexadecimal characters (BUG-004: invalid nonce format)
/// - `context_id` is empty (BUG-041: ambiguous context)
/// - `context_id` contains `|` character (SEC-015: delimiter collision)
///
/// # Security Notes
///
/// - **SEC-014**: Requires minimum 32 hex chars (128 bits) to prevent weak key derivation
/// - **BUG-004**: Validates nonce is valid hexadecimal to ensure entropy
/// - **BUG-041**: Requires non-empty context_id to prevent ambiguous contexts
/// - **SEC-015**: Rejects context_id containing `|` to prevent delimiter collision attacks
/// - **BUG-001**: Delimiter collision prevented by context_id validation (binding may contain `|`)
///
/// The HMAC message format is `context_id|binding`. Since context_id is validated to not
/// contain `|`, the first `|` in the message unambiguously separates context_id from binding.
/// This allows binding to contain `|` (as in the `METHOD|PATH|QUERY` format).
///
/// Formula: clientSecret = HMAC-SHA256(nonce, contextId + "|" + binding)
pub fn ash_derive_client_secret(nonce: &str, context_id: &str, binding: &str) -> Result<String, AshError> {
    // SEC-014, SEC-NONCE-001, BUG-004: Validate nonce format via standalone validator
    crate::validate::ash_validate_nonce(nonce)?;

    // BUG-041: Validate context_id is not empty
    if context_id.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "context_id cannot be empty",
        ));
    }

    // SEC-CTX-001: Validate context_id doesn't exceed maximum length
    if context_id.len() > MAX_CONTEXT_ID_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("context_id exceeds maximum length of {} characters", MAX_CONTEXT_ID_LENGTH),
        ));
    }

    // SEC-CTX-001: Validate context_id contains only allowed characters
    // Allowed: A-Z a-z 0-9 _ - .
    if !context_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot",
        ));
    }

    // SEC-015 & BUG-001: context_id delimiter collision is prevented by the
    // charset validation above (only ASCII alphanumeric + _ - . allowed, which excludes |)

    // PT-001: Validate binding is not empty to ensure endpoint-bound secrets
    if binding.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "binding cannot be empty",
        ));
    }

    // SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
    if binding.len() > MAX_BINDING_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("binding exceeds maximum length of {} bytes", MAX_BINDING_LENGTH),
        ));
    }

    // M2: Normalize nonce to lowercase hex before use as HMAC key.
    // This ensures cross-SDK consistency regardless of hex case (e.g., "AABB" == "aabb").
    // BUG-056: Zeroize nonce key material after HMAC derivation.
    // M3-FIX: Always create an owned lowercase copy so we can zeroize it.
    // Previously, the else-branch pointed to the caller's &str which could not be zeroized.
    use zeroize::Zeroizing;
    let nonce_key = Zeroizing::new(nonce.to_ascii_lowercase());

    let mac =
        HmacSha256Type::new_from_slice(nonce_key.as_bytes()).map_err(|_| {
            AshError::new(AshErrorCode::InternalError, "HMAC key initialization failed")
        })?;
    let message = Zeroizing::new(format!("{}|{}", context_id, binding));
    let mut mac = mac;
    mac.update(message.as_bytes());
    // Zeroizing wrapper auto-zeroizes nonce_key and message on drop
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Expected length of SHA-256 hash in hex (32 bytes = 64 hex chars).
const SHA256_HEX_LENGTH: usize = 64;

/// Build cryptographic proof (client-side).
///
/// Formula: proof = HMAC-SHA256(clientSecret, timestamp + "|" + binding + "|" + bodyHash)
///
/// # Arguments
///
/// * `client_secret` - Derived client secret (must not be empty)
/// * `timestamp` - Unix timestamp as string (must not be empty)
/// * `binding` - Canonical binding (must not be empty)
/// * `body_hash` - SHA-256 hash of canonical body (must be 64 hex chars)
///
/// # Returns
///
/// Returns `Ok(proof)` on success, or `Err` if any required input is invalid.
///
/// # Security Note (SEC-012)
///
/// All inputs are validated to be non-empty and body_hash is validated for format.
pub fn ash_build_proof(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    body_hash: &str,
) -> Result<String, AshError> {
    // SEC-012: Validate required inputs are non-empty
    if client_secret.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "client_secret cannot be empty",
        ));
    }

    // BUG-057: Validate timestamp format on the build side (not just verify side).
    // Without this, a client can build a proof with timestamp "abc" or "0123" and
    // get no early feedback — the proof will always fail verification.
    ash_validate_timestamp_format(timestamp)?;

    if binding.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "binding cannot be empty",
        ));
    }

    // SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
    if binding.len() > MAX_BINDING_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("binding exceeds maximum length of {} bytes", MAX_BINDING_LENGTH),
        ));
    }

    // BUG-040: Validate body_hash format (must be valid SHA-256 hex)
    if body_hash.len() != SHA256_HEX_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!(
                "body_hash must be {} hex characters (SHA-256), got {}",
                SHA256_HEX_LENGTH,
                body_hash.len()
            ),
        ));
    }
    if !body_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "body_hash must contain only hexadecimal characters (0-9, a-f, A-F)",
        ));
    }

    // Normalize body_hash to lowercase for cross-SDK consistency (matches Node.js behavior)
    let body_hash = body_hash.to_ascii_lowercase();

    let message = Zeroizing::new(format!("{}|{}|{}", timestamp, binding, body_hash));
    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .map_err(|_| AshError::new(AshErrorCode::InternalError, "HMAC key initialization failed"))?;
    mac.update(message.as_bytes());
    // BUG-060: Zeroize HMAC message after use — Zeroizing handles this on drop.
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Verify proof (server-side).
///
/// # Returns
///
/// `Ok(true)` if proof is valid, `Ok(false)` if proof is invalid,
/// `Err` if inputs are malformed.
///
/// # Timestamp Validation
///
/// This function validates the timestamp format but does NOT check expiry.
/// Use `ash_validate_timestamp()` separately if you need to enforce timestamp freshness.
pub fn ash_verify_proof(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    body_hash: &str,
    client_proof: &str,
) -> Result<bool, AshError> {
    // BUG-007 & BUG-012: Validate timestamp format
    ash_validate_timestamp_format(timestamp)?;

    // M4-FIX: Use Zeroizing wrapper for panic-safe zeroization.
    // Previously used manual zeroize() which would not run if ash_build_proof panicked.
    let client_secret = Zeroizing::new(ash_derive_client_secret(nonce, context_id, binding)?);
    let result = ash_build_proof(&client_secret, timestamp, binding, body_hash);
    drop(client_secret); // Zeroizing auto-zeroizes on drop
    let expected_proof = Zeroizing::new(result?);
    // BUG-078: Zeroize expected proof after comparison to prevent it from
    // persisting in memory, where it could be extracted via memory dumps.
    let is_valid = ash_timing_safe_equal(expected_proof.as_bytes(), client_proof.as_bytes());
    drop(expected_proof); // Zeroizing auto-zeroizes on drop
    Ok(is_valid)
}

/// Verify proof with timestamp freshness check (server-side).
///
/// SEC-AUDIT-002: Convenience function that combines proof verification
/// with timestamp freshness validation to prevent replay attacks.
///
/// # Returns
///
/// `Ok(true)` if proof is valid and timestamp is fresh,
/// `Ok(false)` if proof is invalid,
/// `Err` if inputs are malformed or timestamp is expired/future.
///
/// # Arguments
///
/// * `nonce` - Server-generated nonce
/// * `context_id` - Context identifier
/// * `binding` - Canonical binding string
/// * `timestamp` - Unix timestamp as string
/// * `body_hash` - SHA-256 hash of canonical body
/// * `client_proof` - Proof received from client
/// * `max_age_seconds` - Maximum allowed age of the timestamp
/// * `clock_skew_seconds` - Tolerance for future timestamps
///
/// # Example
///
/// ```rust
/// use ashcore::{ash_verify_proof_with_freshness, ash_derive_client_secret, ash_build_proof, ash_hash_body};
///
/// let nonce = "0123456789abcdef0123456789abcdef";
/// let context_id = "ctx_abc123";
/// let binding = "POST|/api/test|";
/// let now = std::time::SystemTime::now()
///     .duration_since(std::time::UNIX_EPOCH)
///     .unwrap()
///     .as_secs();
/// let timestamp = now.to_string();
/// let body_hash = ash_hash_body("{}");
///
/// let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
/// let proof = ash_build_proof(&client_secret, &timestamp, binding, &body_hash).unwrap();
///
/// // Verify with 5 minute max age and 60 second clock skew
/// let result = ash_verify_proof_with_freshness(
///     nonce, context_id, binding, &timestamp, &body_hash, &proof,
///     300, 60
/// );
/// assert!(result.unwrap());
/// ```
#[allow(clippy::too_many_arguments)]
pub fn ash_verify_proof_with_freshness(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    body_hash: &str,
    client_proof: &str,
    max_age_seconds: u64,
    clock_skew_seconds: u64,
) -> Result<bool, AshError> {
    // First validate timestamp freshness (this also validates format)
    ash_validate_timestamp(timestamp, max_age_seconds, clock_skew_seconds)?;

    // Then verify the proof
    // M4-FIX: Use Zeroizing wrapper for panic-safe zeroization.
    // Previously used manual zeroize() which would not run if ash_build_proof panicked.
    let client_secret = Zeroizing::new(ash_derive_client_secret(nonce, context_id, binding)?);
    let result = ash_build_proof(&client_secret, timestamp, binding, body_hash);
    drop(client_secret); // Zeroizing auto-zeroizes on drop
    let expected_proof = Zeroizing::new(result?);
    // BUG-078: Zeroize expected proof after comparison
    let is_valid = ash_timing_safe_equal(expected_proof.as_bytes(), client_proof.as_bytes());
    drop(expected_proof); // Zeroizing auto-zeroizes on drop
    Ok(is_valid)
}

/// Maximum payload size for hashing (matches canonicalization limit).
/// BUG-058: Prevents CPU-bound DoS from hashing unbounded input.
const MAX_HASH_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Compute SHA-256 hash of canonical body.
///
/// # Safety Expectation
///
/// This function expects input that has already been canonicalized via
/// `ash_canonicalize_json` (which enforces `MAX_PAYLOAD_SIZE`). If called
/// with uncanonicalized input from untrusted sources, use
/// [`ash_hash_body_checked`] instead to enforce size limits.
///
/// BUG-058: Enforces size limit in both debug and release builds.
/// Returns the SHA-256 empty-string hash for inputs exceeding the limit,
/// preventing CPU-bound DoS while maintaining the infallible signature.
/// For explicit error handling, use [`ash_hash_body_checked`] instead.
pub fn ash_hash_body(canonical_body: &str) -> String {
    if canonical_body.len() > MAX_HASH_PAYLOAD_SIZE {
        // BUG-061: In release builds, reject oversized input by returning the
        // hash of an empty string. This is safe because:
        // 1. Canonicalized input from ash_canonicalize_json is always ≤ 10MB
        // 2. Oversized input reaching here indicates a bug or bypass attempt
        // 3. The proof will fail verification, alerting the caller
        debug_assert!(
            false,
            "ash_hash_body called with input exceeding {} bytes; use ash_hash_body_checked for untrusted input",
            MAX_HASH_PAYLOAD_SIZE
        );
        let mut hasher = Sha256::new();
        hasher.update(b"");
        return hex::encode(hasher.finalize());
    }
    let mut hasher = Sha256::new();
    hasher.update(canonical_body.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of canonical body with size validation.
///
/// BUG-058: Size-safe variant for untrusted input. Returns error if input
/// exceeds 10 MB to prevent CPU-bound DoS.
///
/// Use this when the input has NOT been canonicalized via `ash_canonicalize_json`.
pub fn ash_hash_body_checked(canonical_body: &str) -> Result<String, AshError> {
    if canonical_body.len() > MAX_HASH_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Body exceeds maximum size of {} bytes for hashing", MAX_HASH_PAYLOAD_SIZE),
        ));
    }
    Ok(ash_hash_body(canonical_body))
}

/// Sort and deduplicate scope fields for deterministic ordering.
/// BUG-023: Auto-sorting prevents client/server scope order mismatches.
fn ash_normalize_scope(scope: &[&str]) -> Vec<String> {
    let mut sorted: Vec<String> = scope.iter().map(|s| s.to_string()).collect();
    sorted.sort();
    sorted.dedup();
    sorted
}

/// Join scope fields safely using unit separator to prevent collision.
/// BUG-002: Using '\x1F' (unit separator) instead of comma prevents collision
/// when field names contain commas.
/// BUG-023: Scope is now auto-sorted for deterministic ordering.
/// BUG-028: Validates field names don't contain the delimiter to prevent hash collisions.
/// BUG-039: Validates field names are not empty to prevent confusion.
/// SEC-SCOPE-001: Validates field name length and total scope length.
fn ash_join_scope_fields(scope: &[&str]) -> Result<String, AshError> {
    let mut total_length: usize = 0;

    for field in scope {
        // BUG-039: Reject empty field names
        if field.is_empty() {
            return Err(AshError::new(
                AshErrorCode::ValidationError,
                "Scope field names cannot be empty",
            ));
        }

        // SEC-SCOPE-001: Validate individual field name length
        if field.len() > MAX_SCOPE_FIELD_NAME_LENGTH {
            return Err(AshError::new(
                AshErrorCode::ValidationError,
                format!("Scope field name exceeds maximum length of {} characters", MAX_SCOPE_FIELD_NAME_LENGTH),
            ));
        }

        // Track total length (field + delimiter)
        total_length = total_length.saturating_add(field.len()).saturating_add(1);

        // BUG-028: Validate no field names contain the delimiter character
        // SEC-AUDIT-003: Use generic error message to avoid information disclosure
        if field.contains(SCOPE_FIELD_DELIMITER) {
            return Err(AshError::new(
                AshErrorCode::ValidationError,
                "Scope field contains reserved delimiter character (U+001F)",
            ));
        }
    }

    // SEC-SCOPE-001: Validate total scope length
    if total_length > MAX_TOTAL_SCOPE_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Total scope length exceeds maximum of {} bytes", MAX_TOTAL_SCOPE_LENGTH),
        ));
    }

    let normalized = ash_normalize_scope(scope);
    Ok(normalized.join(&SCOPE_FIELD_DELIMITER.to_string()))
}

/// Compute SHA-256 hash of scope fields.
/// Uses unit separator ('\x1F') to prevent collision with field names containing commas.
///
/// # Errors
/// Returns error if any field name contains the delimiter character (U+001F).
/// BUG-028: This prevents hash collisions from field names containing the delimiter.
pub fn ash_hash_scope(scope: &[&str]) -> Result<String, AshError> {
    if scope.is_empty() {
        return Ok(String::new());
    }
    Ok(ash_hash_body(&ash_join_scope_fields(scope)?))
}

#[cfg(test)]
mod tests_proof {
    use super::*;

    // Test nonces must be at least 32 hex chars (16 bytes)
    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef"; // 32 hex chars
    const TEST_NONCE_2: &str = "fedcba9876543210fedcba9876543210"; // Different 32 hex chars
    // Valid SHA-256 hash for testing (64 hex chars)
    const TEST_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    #[allow(dead_code)]
    const TEST_BODY_HASH_2: &str = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

    #[test]
    fn test_derive_client_secret_deterministic() {
        let secret1 = ash_derive_client_secret(TEST_NONCE, "ctx_abc", "POST /login").unwrap();
        let secret2 = ash_derive_client_secret(TEST_NONCE, "ctx_abc", "POST /login").unwrap();
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_derive_client_secret_different_inputs() {
        let secret1 = ash_derive_client_secret(TEST_NONCE, "ctx_abc", "POST /login").unwrap();
        let secret2 = ash_derive_client_secret(TEST_NONCE_2, "ctx_abc", "POST /login").unwrap();
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_derive_client_secret_rejects_short_nonce() {
        // SEC-014: Short nonces should be rejected
        let result = ash_derive_client_secret("short", "ctx_abc", "POST /login");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("hex characters"));
    }

    #[test]
    fn test_derive_client_secret_rejects_non_hex_nonce() {
        // BUG-004: Non-hex nonces should be rejected
        let result = ash_derive_client_secret("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "ctx_abc", "POST /login");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("hexadecimal"));
    }

    #[test]
    fn test_derive_client_secret_rejects_delimiter_in_context_id() {
        // SEC-015 & SEC-CTX-001: Context IDs with | should be rejected
        // Now rejected by charset validation (only alphanumeric + _ - . allowed)
        let result = ash_derive_client_secret(TEST_NONCE, "ctx|abc", "POST /login");
        assert!(result.is_err());
        // Error message mentions either "delimiter" or invalid characters
        let msg = result.unwrap_err().message().to_lowercase();
        assert!(msg.contains("delimiter") || msg.contains("alphanumeric") || msg.contains("character"));
    }

    #[test]
    fn test_derive_client_secret_allows_delimiter_in_binding() {
        // BUG-001: Bindings with | are allowed (format uses METHOD|PATH|QUERY)
        // Collision prevented by context_id validation
        let result = ash_derive_client_secret(TEST_NONCE, "ctx_abc", "POST|/login|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_client_secret_rejects_empty_context_id() {
        // BUG-041: Empty context_id should be rejected
        let result = ash_derive_client_secret(TEST_NONCE, "", "POST /login");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("empty"));
    }

    #[test]
    fn test_build_proof_deterministic() {
        let proof1 = ash_build_proof("secret", "1234567890", "POST /login", TEST_BODY_HASH).unwrap();
        let proof2 = ash_build_proof("secret", "1234567890", "POST /login", TEST_BODY_HASH).unwrap();
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_build_proof_rejects_empty_inputs() {
        // SEC-012: Validate that empty inputs are rejected
        assert!(ash_build_proof("", "1234567890", "POST /login", TEST_BODY_HASH).is_err());
        assert!(ash_build_proof("secret", "", "POST /login", TEST_BODY_HASH).is_err());
        assert!(ash_build_proof("secret", "1234567890", "", TEST_BODY_HASH).is_err());
        // Empty body_hash is now caught by length validation
        assert!(ash_build_proof("secret", "1234567890", "POST /login", "").is_err());
    }

    #[test]
    fn test_build_proof_rejects_invalid_body_hash() {
        // BUG-040: Invalid body hash format should be rejected
        // Too short
        assert!(ash_build_proof("secret", "1234567890", "POST /login", "abc123").is_err());
        // Too long
        let too_long = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855aa";
        assert!(ash_build_proof("secret", "1234567890", "POST /login", too_long).is_err());
        // Non-hex characters
        let non_hex = "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(ash_build_proof("secret", "1234567890", "POST /login", non_hex).is_err());
    }

    #[test]
    fn test_ash_verify_proof() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc";
        let binding = "POST /login";
        let timestamp = "1234567890";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&client_secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        assert!(ash_verify_proof(
            nonce, context_id, binding, timestamp, TEST_BODY_HASH, &proof
        ).unwrap());
    }

    #[test]
    fn test_ash_hash_body() {
        let hash = ash_hash_body(r#"{"name":"John"}"#);
        assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_timestamp_rejects_leading_zeros() {
        // BUG-038: Leading zeros should be rejected
        let result = ash_validate_timestamp_format("0123456789");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("leading zeros"));

        // But "0" itself is valid
        let result = ash_validate_timestamp_format("0");
        assert!(result.is_ok());
    }

    // SEC-CTX-001: Context ID length and charset validation
    #[test]
    fn test_context_id_max_length() {
        let long_context = "a".repeat(257); // Over MAX_CONTEXT_ID_LENGTH (256)
        let result = ash_derive_client_secret(TEST_NONCE, &long_context, "POST|/api|");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum length"));
    }

    #[test]
    fn test_context_id_at_max_length() {
        let max_context = "a".repeat(256); // Exactly MAX_CONTEXT_ID_LENGTH
        let result = ash_derive_client_secret(TEST_NONCE, &max_context, "POST|/api|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_context_id_rejects_invalid_chars() {
        // SEC-CTX-001: Only ASCII alphanumeric + _ - . allowed
        let result = ash_derive_client_secret(TEST_NONCE, "ctx with space", "POST|/api|");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("alphanumeric"));

        let result = ash_derive_client_secret(TEST_NONCE, "ctx@special", "POST|/api|");
        assert!(result.is_err());

        let result = ash_derive_client_secret(TEST_NONCE, "ctx\x00null", "POST|/api|");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_id_allows_valid_chars() {
        // Allowed: A-Z a-z 0-9 _ - .
        let result = ash_derive_client_secret(TEST_NONCE, "ctx_ABC-123.test", "POST|/api|");
        assert!(result.is_ok());
    }

    // SEC-NONCE-001 & SEC-AUDIT-005: Nonce/HMAC key length validation
    #[test]
    fn test_nonce_max_length() {
        let long_nonce = "0".repeat(513); // Over MAX_NONCE_LENGTH (512)
        let result = ash_derive_client_secret(&long_nonce, "ctx_test", "POST|/api|");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum length"));
    }

    #[test]
    fn test_nonce_at_max_length() {
        let max_nonce = "0".repeat(512); // Exactly MAX_NONCE_LENGTH
        let result = ash_derive_client_secret(&max_nonce, "ctx_test", "POST|/api|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_context_id_unicode_rejected() {
        // SEC-CTX-001: Context IDs must be ASCII alphanumeric + _ - .
        // Unicode characters are rejected regardless of byte length
        let unicode_context = "ctx_".to_string() + &"é".repeat(10);
        let result = ash_derive_client_secret(TEST_NONCE, &unicode_context, "POST|/api|");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("alphanumeric"));
    }
}

// SEC-SCOPE-001: Scope field length validation tests
#[cfg(test)]
mod tests_sec_scope_001 {
    use super::*;

    #[test]
    fn test_scope_field_name_max_length() {
        let long_field = "a".repeat(65); // Over MAX_SCOPE_FIELD_NAME_LENGTH (64)
        let scope = vec![long_field.as_str()];
        let result = ash_hash_scope(&scope);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum length"));
    }

    #[test]
    fn test_scope_field_name_at_max_length() {
        let max_field = "a".repeat(64); // Exactly MAX_SCOPE_FIELD_NAME_LENGTH
        let scope = vec![max_field.as_str()];
        let result = ash_hash_scope(&scope);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scope_total_length_limit() {
        // Create many fields that together exceed MAX_TOTAL_SCOPE_LENGTH (4096)
        // 100 fields * 50 chars each = 5000 bytes > 4096
        let fields: Vec<String> = (0..100).map(|i| format!("field_{:045}", i)).collect();
        let scope: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let result = ash_hash_scope(&scope);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("Total scope length"));
    }

    #[test]
    fn test_scope_within_total_length_limit() {
        // 50 fields * 50 chars = 2500 bytes < 4096
        let fields: Vec<String> = (0..50).map(|i| format!("field_{:043}", i)).collect();
        let scope: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let result = ash_hash_scope(&scope);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scope_max_array_allocation() {
        // BUG-036: Test that total array allocation exceeding MAX_TOTAL_ARRAY_ALLOCATION (10000) is rejected
        let payload: Value = serde_json::json!({"items": [1, 2, 3]});
        
        // Valid allocation (small indices, total < 10000)
        let scope = vec!["items[0]", "items[1]", "items[2]"];
        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_ok());
        
        // Excessive allocation should be rejected
        // items[10000] requires 10001 elements (index + 1), exceeding MAX_TOTAL_ARRAY_ALLOCATION (10000)
        let scope = vec!["items[10000]"];
        let result = ash_extract_scoped_fields(&payload, &scope);
        // Should be rejected due to allocation limit
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("array indices"));
    }
}

// =========================================================================
// Context Scoping (Selective Field Protection)
// =========================================================================

use serde_json::{Map, Value};

use crate::canonicalize::ash_canonicalize_json_value;

/// Default maximum age for timestamps (5 minutes).
pub const DEFAULT_MAX_TIMESTAMP_AGE_SECONDS: u64 = 300;

/// Default clock skew tolerance (30 seconds).
///
/// BUG-077: Reduced from 60 to 30 seconds to match the ASH specification.
/// The previous 60-second value was overly permissive and doubled the
/// spec-recommended window for replay attacks.
pub const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;

/// Validate timestamp format only (not freshness).
///
/// # BUG-007 & BUG-012
///
/// Validates that timestamp:
/// - Contains only ASCII digits (no whitespace, no signs)
/// - Has no leading zeros (except "0" itself) - BUG-038
/// - Parses as valid u64
/// - Is within reasonable bounds
///
/// This is used by verification functions to ensure well-formed input.
/// For freshness validation, use `ash_validate_timestamp()`.
pub fn ash_validate_timestamp_format(timestamp: &str) -> Result<u64, AshError> {
    // BUG-012: Check for non-digit characters (no whitespace, no signs)
    if timestamp.is_empty() {
        return Err(AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp cannot be empty",
        ));
    }

    if !timestamp.chars().all(|c| c.is_ascii_digit()) {
        return Err(AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp must contain only digits (0-9)",
        ));
    }

    // BUG-038: Reject leading zeros (except "0" itself)
    // This ensures cross-implementation consistency in normalization
    if timestamp.len() > 1 && timestamp.starts_with('0') {
        return Err(AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp must not have leading zeros",
        ));
    }

    // Parse timestamp
    let ts: u64 = timestamp.parse().map_err(|_| {
        AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp must be a valid integer",
        )
    })?;

    // SEC-018: Check for unreasonably large timestamp
    if ts > MAX_TIMESTAMP {
        return Err(AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp exceeds maximum allowed value",
        ));
    }

    Ok(ts)
}

/// Validate a timestamp string.
///
/// # Arguments
/// * `timestamp` - Unix timestamp as string (seconds since epoch)
/// * `max_age_seconds` - Maximum allowed age of the timestamp
/// * `clock_skew_seconds` - Tolerance for future timestamps (clock skew)
///
/// # Returns
/// Ok(()) if valid, Err with appropriate error if invalid.
///
/// # Boundary Conditions
/// - A timestamp exactly `max_age_seconds` old is **valid** (boundary inclusive)
/// - A timestamp exactly `clock_skew_seconds` in the future is **valid**
///
/// # Security Notes
/// - **SEC-005**: Validates timestamps to prevent replay attacks with stale proofs
/// - **SEC-018**: Rejects unreasonably large timestamps (beyond year 3000)
///
/// # Example
/// ```rust
/// use ashcore::ash_validate_timestamp;
///
/// // Get current timestamp
/// let now = std::time::SystemTime::now()
///     .duration_since(std::time::UNIX_EPOCH)
///     .unwrap()
///     .as_secs();
///
/// // Recent timestamp should be valid
/// assert!(ash_validate_timestamp(&now.to_string(), 300, 60).is_ok());
///
/// // Old timestamp should fail
/// let old = now - 600; // 10 minutes ago
/// assert!(ash_validate_timestamp(&old.to_string(), 300, 60).is_err());
/// ```
pub fn ash_validate_timestamp(
    timestamp: &str,
    max_age_seconds: u64,
    clock_skew_seconds: u64,
) -> Result<(), AshError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // BUG-007 & BUG-012: Use strict format validation
    let ts = ash_validate_timestamp_format(timestamp)?;

    // Get current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            AshError::new(
                AshErrorCode::InternalError,
                "System time error",
            )
        })?
        .as_secs();

    // BUG-045: Check for future timestamp with overflow protection
    // Use saturating_add to prevent overflow if now is near u64::MAX
    if ts > now.saturating_add(clock_skew_seconds) {
        return Err(AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp is in the future",
        ));
    }

    // Check for expired timestamp
    if now > ts && now - ts > max_age_seconds {
        return Err(AshError::new(
            AshErrorCode::TimestampInvalid,
            "Timestamp has expired",
        ));
    }

    Ok(())
}

/// Extract scoped fields from a JSON value.
///
/// # Path Syntax
///
/// Scope paths use dot notation for nested fields and bracket notation for arrays:
/// - `"name"` - top-level field
/// - `"user.name"` - nested field
/// - `"items[0]"` - array element
/// - `"items[0].id"` - nested field in array element
///
/// # Limitations
///
/// **Field names containing dots are NOT supported.** The dot character (`.`) is
/// used as the path separator, so a field like `{"user.name": "John"}` cannot be
/// directly addressed. The path `"user.name"` will look for `payload["user"]["name"]`,
/// not `payload["user.name"]`.
///
/// If you need to protect fields with dots in their names, either:
/// 1. Rename the fields before signing
/// 2. Use full payload protection (empty scope)
pub fn ash_extract_scoped_fields(payload: &Value, scope: &[&str]) -> Result<Value, AshError> {
    ash_extract_scoped_fields_internal(payload, scope, false)
}

/// Extract scoped fields from a JSON value with strict mode.
///
/// # Arguments
/// * `payload` - The JSON payload to extract from
/// * `scope` - List of field paths to extract
/// * `strict` - If true, all scoped fields must exist in payload
///
/// # Security (SEC-006)
/// Strict mode ensures all expected scoped fields are present,
/// preventing accidental scope mismatches.
///
/// # Example
/// ```rust
/// use ashcore::ash_extract_scoped_fields_strict;
/// use serde_json::json;
///
/// let payload = json!({"amount": 100});
/// let scope = vec!["amount", "recipient"];
///
/// // Non-strict mode: missing fields are ignored
/// assert!(ash_extract_scoped_fields_strict(&payload, &scope, false).is_ok());
///
/// // Strict mode: missing fields cause error
/// assert!(ash_extract_scoped_fields_strict(&payload, &scope, true).is_err());
/// ```
pub fn ash_extract_scoped_fields_strict(
    payload: &Value,
    scope: &[&str],
    strict: bool,
) -> Result<Value, AshError> {
    ash_extract_scoped_fields_internal(payload, scope, strict)
}

/// Internal implementation of scoped field extraction.
fn ash_extract_scoped_fields_internal(
    payload: &Value,
    scope: &[&str],
    strict: bool,
) -> Result<Value, AshError> {
    if scope.is_empty() {
        return Ok(payload.clone());
    }

    // BUG-018: Limit scope field count to prevent DoS
    if scope.len() > MAX_SCOPE_FIELDS {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Scope exceeds maximum of {} fields", MAX_SCOPE_FIELDS),
        ));
    }

    // BUG-036: Calculate total array allocation needed and validate
    let total_allocation = ash_calculate_total_array_allocation(scope);
    if total_allocation > MAX_TOTAL_ARRAY_ALLOCATION {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!(
                "Scope array indices exceed maximum total allocation of {} elements",
                MAX_TOTAL_ARRAY_ALLOCATION
            ),
        ));
    }

    // BUG-083: Validate field names early (matching ash_join_scope_fields validation).
    // Previously, field name validation only happened in ash_join_scope_fields during
    // hashing, not during extraction. This could allow extraction to succeed but
    // hashing to fail, producing confusing errors.
    for field_path in scope {
        if field_path.is_empty() {
            return Err(AshError::new(
                AshErrorCode::ValidationError,
                "Scope field names cannot be empty",
            ));
        }
        if field_path.contains(SCOPE_FIELD_DELIMITER) {
            return Err(AshError::new(
                AshErrorCode::ValidationError,
                "Scope field contains reserved delimiter character (U+001F)",
            ));
        }
    }

    let mut result = Map::new();

    for field_path in scope {
        let value = ash_get_nested_value(payload, field_path);
        if let Some(v) = value {
            ash_set_nested_value(&mut result, field_path, v);
        } else if strict {
            // SEC-006: In strict mode, missing fields are an error
            return Err(AshError::new(
                AshErrorCode::ScopedFieldMissing,
                format!("Required scoped field missing: {}", field_path),
            ));
        }
    }

    Ok(Value::Object(result))
}

/// Calculate total array allocation needed for a set of scope paths.
/// BUG-036: Prevents DoS via multiple large array allocations.
/// BUG-050: Uses saturating arithmetic to prevent overflow panic in debug mode.
fn ash_calculate_total_array_allocation(scope: &[&str]) -> usize {
    let mut total = 0usize;
    for path in scope {
        for part in path.split('.') {
            let notation = ash_parse_all_array_indices(part);
            for idx in &notation.indices {
                // Each index requires at least (idx + 1) elements
                // BUG-050: Use saturating_add for idx+1 to prevent overflow
                total = total.saturating_add(idx.saturating_add(1));
            }
        }
    }
    total
}

fn ash_get_nested_value(payload: &Value, path: &str) -> Option<Value> {
    ash_get_nested_value_with_depth(payload, path, 0)
}

/// Internal implementation with depth tracking.
/// BUG-021: Added depth tracking and MAX_ARRAY_INDEX checks for consistency with set_nested_value.
fn ash_get_nested_value_with_depth(payload: &Value, path: &str, depth: usize) -> Option<Value> {
    // SEC-019: Check path depth to prevent stack overflow
    if depth > MAX_SCOPE_PATH_DEPTH {
        return None;
    }

    let parts: Vec<&str> = path.split('.').collect();

    // SEC-019: Also check total path depth
    if parts.len() > MAX_SCOPE_PATH_DEPTH {
        return None;
    }

    let mut current = payload;

    for part in parts {
        // BUG-022: Parse all array indices from the part (supports items[0][1])
        let indices = ash_parse_all_array_indices(part);

        match current {
            Value::Object(map) => {
                current = map.get(indices.key)?;
                // Apply all indices sequentially
                for idx in &indices.indices {
                    // SEC-011: Check array index limit
                    if *idx > MAX_ARRAY_INDEX {
                        return None;
                    }
                    if let Value::Array(arr) = current {
                        current = arr.get(*idx)?;
                    } else {
                        return None;
                    }
                }
            }
            Value::Array(arr) => {
                // Direct array access (path segment is just a number)
                let idx: usize = indices.key.parse().ok()?;
                // SEC-011: Check array index limit
                if idx > MAX_ARRAY_INDEX {
                    return None;
                }
                current = arr.get(idx)?;
                // Apply any additional indices
                for idx in &indices.indices {
                    if *idx > MAX_ARRAY_INDEX {
                        return None;
                    }
                    if let Value::Array(arr) = current {
                        current = arr.get(*idx)?;
                    } else {
                        return None;
                    }
                }
            }
            _ => return None,
        }
    }

    Some(current.clone())
}

/// Result of parsing array notation from a path segment.
/// BUG-022: Supports multi-dimensional arrays like `items[0][1]`.
struct ArrayNotation<'a> {
    /// The key part (e.g., "items" from "items[0][1]")
    key: &'a str,
    /// All indices in order (e.g., [0, 1] from "items[0][1]")
    indices: Vec<usize>,
}

/// Parse all array indices from a path segment (e.g., "items[0][1]" -> key="items", indices=[0, 1]).
///
/// BUG-022: Supports multi-dimensional array access.
///
/// Handles edge cases:
/// - No brackets: "items" -> key="items", indices=[]
/// - Single index: "items[0]" -> key="items", indices=[0]
/// - Multi-dimensional: "items[0][1]" -> key="items", indices=[0, 1]
/// - Empty brackets: "items[]" -> key="items", indices=[] (invalid, treated as no index)
/// - Invalid index: "items[abc]" -> key="items", indices=[] (stops parsing)
/// - Mixed valid/invalid: "items[0][abc]" -> key="items", indices=[] (invalidated due to unparsed content)
/// - Trailing text after valid indices: "items[0]extra" -> key="items", indices=[] (invalidated)
fn ash_parse_all_array_indices(part: &str) -> ArrayNotation<'_> {
    let bracket_start = match part.find('[') {
        Some(pos) => pos,
        None => return ArrayNotation { key: part, indices: vec![] },
    };

    let key = &part[..bracket_start];
    let mut indices = Vec::new();
    let mut remaining = &part[bracket_start..];

    // Parse all [N] patterns
    while remaining.starts_with('[') {
        let bracket_end = match remaining.find(']') {
            Some(pos) => pos,
            None => break, // Malformed - no closing bracket
        };

        let index_str = &remaining[1..bracket_end];
        if index_str.is_empty() {
            break; // Empty brackets - stop parsing
        }

        match index_str.parse::<usize>() {
            Ok(idx) => indices.push(idx),
            Err(_) => break, // Invalid index - stop parsing
        }

        remaining = &remaining[bracket_end + 1..];
    }

    // If there's trailing text after the last ], the path is malformed.
    // Treat malformed array notation as non-matching by returning empty indices.
    // This ensures "items[0]extra" is treated as accessing field "items" without
    // array indexing, which will safely fail to match in strict mode.
    if !remaining.is_empty() {
        return ArrayNotation { key, indices: vec![] };
    }

    ArrayNotation { key, indices }
}

/// Set a nested value in a JSON map using a dot-separated path.
///
/// # Limitations
///
/// - **SEC-011**: Array indices limited to MAX_ARRAY_INDEX (10,000) to prevent memory exhaustion
/// - **SEC-019**: Path depth limited to MAX_SCOPE_PATH_DEPTH (32) to prevent stack overflow
/// - **BUG-022**: Supports multi-dimensional arrays (e.g., "matrix[0][1]")
/// - Field names containing dots cannot be addressed (use top-level keys only)
/// - Indices exceeding the limit are silently ignored
fn ash_set_nested_value(result: &mut Map<String, Value>, path: &str, value: Value) {
    ash_set_nested_value_with_depth(result, path, value, 0);
}

/// Internal implementation with depth tracking.
fn ash_set_nested_value_with_depth(result: &mut Map<String, Value>, path: &str, value: Value, depth: usize) {
    // SEC-019: Check recursion depth to prevent stack overflow
    if depth > MAX_SCOPE_PATH_DEPTH {
        return;
    }

    let parts: Vec<&str> = path.split('.').collect();
    if parts.len() > MAX_SCOPE_PATH_DEPTH {
        return; // Silently ignore overly deep paths
    }

    if parts.len() == 1 {
        let notation = ash_parse_all_array_indices(parts[0]);
        if notation.indices.is_empty() {
            // Simple key, no array notation
            result.insert(notation.key.to_string(), value);
        } else {
            // BUG-022: Handle multi-dimensional array notation
            ash_set_value_at_indices(result, notation.key, &notation.indices, value);
        }
        return;
    }

    let notation = ash_parse_all_array_indices(parts[0]);
    let remaining_path = parts[1..].join(".");

    if notation.indices.is_empty() {
        // Simple nested object
        let nested = result
            .entry(notation.key.to_string())
            .or_insert_with(|| Value::Object(Map::new()));

        if let Value::Object(nested_map) = nested {
            ash_set_nested_value_with_depth(nested_map, &remaining_path, value, depth + 1);
        }
    } else {
        // BUG-022: Handle multi-dimensional array in path
        let target = ash_get_or_create_at_indices(result, notation.key, &notation.indices);
        if let Some(Value::Object(nested_map)) = target {
            ash_set_nested_value_with_depth(nested_map, &remaining_path, value, depth + 1);
        }
    }
}

/// Set a value at multi-dimensional array indices.
/// BUG-022: Supports paths like "matrix[0][1]".
fn ash_set_value_at_indices(result: &mut Map<String, Value>, key: &str, indices: &[usize], value: Value) {
    if indices.is_empty() {
        result.insert(key.to_string(), value);
        return;
    }

    // SEC-011: Check all indices before proceeding
    for idx in indices {
        if *idx > MAX_ARRAY_INDEX {
            return; // Silently ignore oversized indices
        }
    }

    // Get or create the top-level array
    let arr = result
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));

    ash_set_value_in_nested_array(arr, indices, value);
}

/// Recursively set a value in nested arrays.
fn ash_set_value_in_nested_array(current: &mut Value, indices: &[usize], value: Value) {
    if indices.is_empty() {
        *current = value;
        return;
    }

    let idx = indices[0];
    let remaining = &indices[1..];

    // Ensure current is an array
    if !current.is_array() {
        *current = Value::Array(Vec::new());
    }

    if let Value::Array(arr) = current {
        // Extend array if needed
        while arr.len() <= idx {
            if remaining.is_empty() {
                arr.push(Value::Null);
            } else {
                arr.push(Value::Array(Vec::new()));
            }
        }

        if remaining.is_empty() {
            arr[idx] = value;
        } else {
            ash_set_value_in_nested_array(&mut arr[idx], remaining, value);
        }
    }
}

/// Get or create a nested object at multi-dimensional array indices.
/// Returns a mutable reference to the nested map if successful.
fn ash_get_or_create_at_indices<'a>(
    result: &'a mut Map<String, Value>,
    key: &str,
    indices: &[usize],
) -> Option<&'a mut Value> {
    if indices.is_empty() {
        return result.get_mut(key);
    }

    // SEC-011: Check all indices before proceeding
    for idx in indices {
        if *idx > MAX_ARRAY_INDEX {
            return None;
        }
    }

    // Get or create the top-level array
    let arr = result
        .entry(key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));

    ash_navigate_to_nested_index(arr, indices)
}

/// Navigate to a nested position in arrays, creating structure as needed.
fn ash_navigate_to_nested_index<'a>(current: &'a mut Value, indices: &[usize]) -> Option<&'a mut Value> {
    if indices.is_empty() {
        return Some(current);
    }

    let idx = indices[0];
    let remaining = &indices[1..];

    // Ensure current is an array
    if !current.is_array() {
        *current = Value::Array(Vec::new());
    }

    if let Value::Array(arr) = current {
        // Extend array if needed
        while arr.len() <= idx {
            if remaining.is_empty() {
                arr.push(Value::Object(Map::new()));
            } else {
                arr.push(Value::Array(Vec::new()));
            }
        }

        if remaining.is_empty() {
            // Ensure the target is an object for further nesting
            if !arr[idx].is_object() {
                arr[idx] = Value::Object(Map::new());
            }
            Some(&mut arr[idx])
        } else {
            ash_navigate_to_nested_index(&mut arr[idx], remaining)
        }
    } else {
        None
    }
}
/// Build cryptographic proof with scoped fields.
///
/// # Scope Auto-Sorting (BUG-023 fix)
///
/// The scope array is **automatically sorted** for deterministic ordering.
/// `["b", "a"]` and `["a", "b"]` will produce the **same** hash.
/// This prevents client/server scope order mismatches.
///
/// # Empty Payload (BUG-024 fix)
///
/// Empty string payload `""` is treated as empty object `{}`.
pub fn ash_build_proof_scoped(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    payload: &str,
    scope: &[&str],
) -> Result<(String, String), AshError> {
    // BUG-046: Validate required inputs (matching ash_build_proof validation)
    if client_secret.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "client_secret cannot be empty",
        ));
    }
    // BUG-079: Validate timestamp format (matching ash_build_proof validation).
    // Previously only checked for empty, so malformed timestamps like "abc" or "0123"
    // would produce proofs that always fail verification with no early feedback.
    ash_validate_timestamp_format(timestamp)?;

    if binding.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "binding cannot be empty",
        ));
    }

    // SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
    if binding.len() > MAX_BINDING_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("binding exceeds maximum length of {} bytes", MAX_BINDING_LENGTH),
        ));
    }

    // BUG-080: Validate payload size before parsing to prevent CPU-bound DoS.
    // Without this, an attacker could submit a multi-GB payload that gets fully
    // parsed by serde_json before any size check.
    if payload.len() > MAX_HASH_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_HASH_PAYLOAD_SIZE),
        ));
    }

    // BUG-024: Handle empty payload as empty object
    let json_payload: Value = if payload.is_empty() || payload.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        // SEC-AUDIT-006: Sanitize error message to prevent information disclosure
        serde_json::from_str(payload)
            .map_err(|_e| AshError::canonicalization_error())?
    };

    let scoped_payload = ash_extract_scoped_fields(&json_payload, scope)?;

    // Use proper canonicalization (sorted keys, NFC normalization, etc.)
    let canonical_scoped = ash_canonicalize_json_value(&scoped_payload)?;

    // BUG-081: ash_hash_body already returns lowercase hex — the extra
    // .to_ascii_lowercase() was redundant (SHA-256 hex from hex::encode is always lowercase).
    let body_hash = ash_hash_body(&canonical_scoped);

    // BUG-002 & BUG-028: Use unit separator instead of comma to prevent collision
    let scope_hash = ash_hash_scope(scope)?;

    let message = Zeroizing::new(format!("{}|{}|{}|{}", timestamp, binding, body_hash, scope_hash));
    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .map_err(|_| AshError::new(AshErrorCode::InternalError, "HMAC key initialization failed"))?;
    mac.update(message.as_bytes());
    // BUG-082: Zeroize HMAC message after use — Zeroizing handles this on drop.
    let proof = hex::encode(mac.finalize().into_bytes());

    Ok((proof, scope_hash))
}

/// Verify proof with scoped fields.
#[allow(clippy::too_many_arguments)]
pub fn ash_verify_proof_scoped(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    payload: &str,
    scope: &[&str],
    scope_hash: &str,
    client_proof: &str,
) -> Result<bool, AshError> {
    // BUG-007 & BUG-012: Validate timestamp format
    ash_validate_timestamp_format(timestamp)?;

    // BUG-049 & SEC-013: Validate consistency - scope_hash must be empty when scope is empty
    if scope.is_empty() && !scope_hash.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ScopeMismatch,
            "scope_hash must be empty when scope is empty",
        ));
    }

    // M11-FIX: SEC-013 inverse — scope_hash must NOT be empty when scope is non-empty.
    // Previously returned Ok(false) from the timing-safe comparison, which is correct
    // but provides inconsistent error semantics. Now returns explicit Err(ScopeMismatch).
    if !scope.is_empty() && scope_hash.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ScopeMismatch,
            "scope_hash must not be empty when scope is provided",
        ));
    }

    // BUG-002 & BUG-028: Use unit separator instead of comma
    let expected_scope_hash = ash_hash_scope(scope)?;
    if !ash_timing_safe_equal(expected_scope_hash.as_bytes(), scope_hash.as_bytes()) {
        return Ok(false);
    }

    // M4-FIX: Use Zeroizing wrapper for panic-safe zeroization.
    use zeroize::Zeroizing;
    let client_secret = Zeroizing::new(ash_derive_client_secret(nonce, context_id, binding)?);

    let result =
        ash_build_proof_scoped(&client_secret, timestamp, binding, payload, scope);
    drop(client_secret); // Zeroizing auto-zeroizes on drop
    let (expected_proof, _) = result?;
    let expected_proof = Zeroizing::new(expected_proof);

    // BUG-078: Zeroize expected proof after comparison (auto via Zeroizing drop)
    let is_valid = ash_timing_safe_equal(
        expected_proof.as_bytes(),
        client_proof.as_bytes(),
    );
    drop(expected_proof);
    Ok(is_valid)
}

/// Hash scoped payload for client-side use.
///
/// Missing scope fields are silently ignored. Use `ash_hash_scoped_body_strict`
/// if you want to enforce that all scope fields exist.
pub fn ash_hash_scoped_body(payload: &str, scope: &[&str]) -> Result<String, AshError> {
    ash_hash_scoped_body_internal(payload, scope, false)
}

/// Hash scoped payload with strict mode.
///
/// # BUG-011
///
/// This variant requires all scope fields to exist in the payload,
/// matching the behavior of `extract_scoped_fields_strict`.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_hash_scoped_body_strict;
///
/// let payload = r#"{"amount": 100}"#;
/// let scope = vec!["amount", "recipient"];
///
/// // Strict mode: missing "recipient" causes error
/// assert!(ash_hash_scoped_body_strict(payload, &scope).is_err());
/// ```
pub fn ash_hash_scoped_body_strict(payload: &str, scope: &[&str]) -> Result<String, AshError> {
    ash_hash_scoped_body_internal(payload, scope, true)
}

/// Internal implementation of hash_scoped_body with strict mode option.
/// BUG-024: Handles empty payload as empty object.
fn ash_hash_scoped_body_internal(payload: &str, scope: &[&str], strict: bool) -> Result<String, AshError> {
    // BUG-080: Validate payload size before parsing to prevent CPU DoS.
    // Same guard applied in ash_build_proof_scoped and ash_build_proof_unified.
    if payload.len() > MAX_HASH_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_HASH_PAYLOAD_SIZE),
        ));
    }

    // BUG-024: Handle empty payload as empty object
    let json_payload: Value = if payload.is_empty() || payload.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        // SEC-AUDIT-006: Sanitize error message to prevent information disclosure
        serde_json::from_str(payload)
            .map_err(|_e| AshError::canonicalization_error())?
    };

    let scoped_payload = ash_extract_scoped_fields_internal(&json_payload, scope, strict)?;

    // Use proper canonicalization (sorted keys, NFC normalization, etc.)
    let canonical_scoped = ash_canonicalize_json_value(&scoped_payload)?;

    Ok(ash_hash_body(&canonical_scoped))
}

#[cfg(test)]
mod tests_scoping {
    use super::*;

    // Test nonces must be at least 32 hex chars (16 bytes)
    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_build_verify_scoped_proof() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1","notes":"hi"}"#;
        let scope = vec!["amount", "recipient"];

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let (proof, scope_hash) =
            ash_build_proof_scoped(&client_secret, timestamp, binding, payload, &scope).unwrap();

        let is_valid = ash_verify_proof_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_scoped_proof_ignores_unscoped_changes() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let scope = vec!["amount", "recipient"];

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();

        let payload1 = r#"{"amount":1000,"recipient":"user1","notes":"hello"}"#;
        let (proof, scope_hash) =
            ash_build_proof_scoped(&client_secret, timestamp, binding, payload1, &scope).unwrap();

        let payload2 = r#"{"amount":1000,"recipient":"user1","notes":"world"}"#;

        let is_valid = ash_verify_proof_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload2,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_scoped_proof_detects_scoped_changes() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let scope = vec!["amount", "recipient"];

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();

        let payload1 = r#"{"amount":1000,"recipient":"user1","notes":"hello"}"#;
        let (proof, scope_hash) =
            ash_build_proof_scoped(&client_secret, timestamp, binding, payload1, &scope).unwrap();

        let payload2 = r#"{"amount":9999,"recipient":"user1","notes":"hello"}"#;

        let is_valid = ash_verify_proof_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload2,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_extract_scoped_fields_with_array_index() {
        // Test that array notation preserves array structure
        let payload: Value = serde_json::from_str(
            r#"{"items":[{"id":1,"name":"a"},{"id":2,"name":"b"}],"total":100}"#
        ).unwrap();

        let scope = vec!["items[0]"];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        // Should preserve array structure: {"items":[{"id":1,"name":"a"}]}
        assert!(scoped.is_object());
        let items = scoped.get("items").expect("should have items key");
        assert!(items.is_array(), "items should be an array, got: {:?}", items);
        let arr = items.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], 1);
    }

    #[test]
    fn test_extract_scoped_fields_with_nested_array_path() {
        // Test nested path with array notation: items[0].id
        let payload: Value = serde_json::from_str(
            r#"{"items":[{"id":1,"name":"a"},{"id":2,"name":"b"}]}"#
        ).unwrap();

        let scope = vec!["items[0].id"];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        // Should be: {"items":[{"id":1}]}
        assert!(scoped.is_object());
        let items = scoped.get("items").expect("should have items key");
        assert!(items.is_array(), "items should be an array");
        let arr = items.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], 1);
    }

    // =========================================================================
    // Boundary Tests (Issue 5.1)
    // =========================================================================

    #[test]
    fn test_scope_max_path_depth() {
        // SEC-019: Test that paths exceeding MAX_SCOPE_PATH_DEPTH (32) are handled
        let payload: Value = serde_json::json!({"level1": {"level2": {"level3": "value"}}});
        
        // Valid depth (3 levels)
        let scope = vec!["level1.level2.level3"];
        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_ok());
        
        // Extremely deep path should be handled gracefully (not panic)
        let deep_path: String = (0..50).map(|i| format!("level{}", i)).collect::<Vec<_>>().join(".");
        let scope = vec![deep_path.as_str()];
        let result = ash_extract_scoped_fields(&payload, &scope);
        // Should either succeed with partial extraction or return empty/not found
        // But should NOT panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_scope_max_array_index() {
        // SEC-011: Test that array indices exceeding MAX_ARRAY_INDEX (10000) are handled
        // The index limit is checked during array access, not during scope extraction
        let payload: Value = serde_json::json!({"items": [1, 2, 3]});
        
        // Valid index - field is found
        let scope = vec!["items[0]"];
        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_ok());
        let scoped = result.unwrap();
        assert!(scoped.get("items").is_some());
        
        // Large index (but under allocation limit) - field is not found gracefully
        // This returns Ok with empty object because field is not found (array too small)
        let scope = vec!["items[100]"];
        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_ok());
        let scoped = result.unwrap();
        assert!(scoped.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_scope_max_fields_limit() {
        // BUG-018: Test that scope field count exceeding MAX_SCOPE_FIELDS (100) is rejected
        let payload: Value = serde_json::json!({"field0": 0, "field1": 1});
        
        // Valid field count
        let scope_strings: Vec<String> = (0..10).map(|i| format!("field{}", i)).collect();
        let scope: Vec<&str> = scope_strings.iter().map(|s| s.as_str()).collect();
        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_ok());
        
        // Exceeding field count should be rejected
        let scope_strings: Vec<String> = (0..150).map(|i| format!("field{}", i)).collect();
        let scope_refs: Vec<&str> = scope_strings.iter().map(|s| s.as_str()).collect();
        let result = ash_extract_scoped_fields(&payload, &scope_refs);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum"));
    }
}

// =========================================================================
// Unified Proof Functions (Scoping + Chaining)
// =========================================================================

/// Result from unified proof generation.
///
/// BUG-097b: Implements `Drop` to zeroize cryptographic material (proof, chain_hash)
/// when the struct goes out of scope, preventing secret leakage in memory dumps.
/// BUG-FIX: Clone removed to prevent un-tracked copies of zeroized secret material.
/// Use std::mem::take to extract fields when needed.
#[derive(Debug, PartialEq)]
pub struct UnifiedProofResult {
    /// The cryptographic proof.
    pub proof: String,
    /// Hash of the scope (empty if no scoping).
    pub scope_hash: String,
    /// Hash of the previous proof (empty if no chaining).
    pub chain_hash: String,
}

impl Drop for UnifiedProofResult {
    fn drop(&mut self) {
        self.proof.zeroize();
        self.chain_hash.zeroize();
    }
}

/// Hash a proof for chaining purposes.
///
/// Used to create chain links between sequential requests.
///
/// # Errors
/// Returns error if proof is empty. BUG-029: Empty proofs should not be allowed
/// in chains to prevent ambiguous chain starts.
pub fn ash_hash_proof(proof: &str) -> Result<String, AshError> {
    // BUG-029: Validate non-empty proof to prevent ambiguous chain starts
    if proof.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "proof cannot be empty for chain hashing",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(proof.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Build unified cryptographic proof (client-side).
///
/// Supports optional scoping and chaining:
/// - `scope`: Fields to protect (empty = full payload)
/// - `previous_proof`: Previous proof in chain (None or Some("") = no chaining)
///
/// # Scope Auto-Sorting (BUG-023 fix)
///
/// The scope array is **automatically sorted** for deterministic ordering.
/// `["b", "a"]` and `["a", "b"]` will produce the **same** hash.
/// This prevents client/server scope order mismatches.
///
/// # Empty Payload (BUG-024 fix)
///
/// Empty string payload `""` is treated as empty object `{}`.
///
/// # Note on Empty Previous Proof
///
/// Both `previous_proof = None` and `previous_proof = Some("")` are treated as
/// "no chaining" and produce an empty chain_hash.
///
/// Formula:
/// ```text
/// scopeHash  = scope.len() > 0 ? SHA256(sorted(scope).join("\x1F")) : ""
/// bodyHash   = SHA256(canonicalize(scopedPayload))
/// chainHash  = previous_proof.is_some() ? SHA256(previous_proof) : ""
/// proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
/// ```
pub fn ash_build_proof_unified(
    client_secret: &str,
    timestamp: &str,
    binding: &str,
    payload: &str,
    scope: &[&str],
    previous_proof: Option<&str>,
) -> Result<UnifiedProofResult, AshError> {
    // BUG-047: Validate required inputs (matching ash_build_proof validation)
    if client_secret.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "client_secret cannot be empty",
        ));
    }
    // BUG-079: Validate timestamp format (matching ash_build_proof validation).
    ash_validate_timestamp_format(timestamp)?;

    if binding.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            "binding cannot be empty",
        ));
    }

    // SEC-AUDIT-004: Validate binding length to prevent memory exhaustion
    if binding.len() > MAX_BINDING_LENGTH {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("binding exceeds maximum length of {} bytes", MAX_BINDING_LENGTH),
        ));
    }

    // BUG-080: Validate payload size before parsing to prevent CPU-bound DoS.
    if payload.len() > MAX_HASH_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_HASH_PAYLOAD_SIZE),
        ));
    }

    // BUG-024: Handle empty payload as empty object
    let json_payload: Value = if payload.is_empty() || payload.trim().is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        // SEC-AUDIT-006: Sanitize error message to prevent information disclosure
        serde_json::from_str(payload)
            .map_err(|_e| AshError::canonicalization_error())?
    };

    let scoped_payload = ash_extract_scoped_fields(&json_payload, scope)?;

    // Use proper canonicalization (sorted keys, NFC normalization, etc.)
    let canonical_scoped = ash_canonicalize_json_value(&scoped_payload)?;

    // BUG-081: ash_hash_body already returns lowercase hex — redundant .to_ascii_lowercase() removed.
    let body_hash = ash_hash_body(&canonical_scoped);

    // Compute scope hash (empty string if no scope)
    // BUG-002 & BUG-028: Use unit separator instead of comma
    let scope_hash = ash_hash_scope(scope)?;

    // Compute chain hash (empty string if no previous proof)
    // BUG-029: ash_hash_proof now validates non-empty
    let chain_hash = match previous_proof {
        Some(prev) if !prev.is_empty() => ash_hash_proof(prev)?,
        _ => String::new(),
    };

    // Build proof message: timestamp|binding|bodyHash|scopeHash|chainHash
    let message = Zeroizing::new(format!(
        "{}|{}|{}|{}|{}",
        timestamp, binding, body_hash, scope_hash, chain_hash
    ));

    let mut mac = HmacSha256Type::new_from_slice(client_secret.as_bytes())
        .map_err(|_| AshError::new(AshErrorCode::InternalError, "HMAC key initialization failed"))?;
    mac.update(message.as_bytes());
    // BUG-082: Zeroize HMAC message after use — Zeroizing handles this on drop.
    let proof = hex::encode(mac.finalize().into_bytes());

    Ok(UnifiedProofResult {
        proof,
        scope_hash,
        chain_hash,
    })
}

/// Verify unified proof (server-side).
///
/// Validates proof with optional scoping and chaining.
///
/// # Consistency Validation (SEC-013)
///
/// This function validates consistency between parameters:
/// - If `scope` is empty, `scope_hash` must also be empty
/// - If `previous_proof` is None/empty, `chain_hash` must also be empty
///
/// This prevents scenarios where a client sends mismatched scope/chain parameters.
#[allow(clippy::too_many_arguments)]
pub fn ash_verify_proof_unified(
    nonce: &str,
    context_id: &str,
    binding: &str,
    timestamp: &str,
    payload: &str,
    client_proof: &str,
    scope: &[&str],
    scope_hash: &str,
    previous_proof: Option<&str>,
    chain_hash: &str,
) -> Result<bool, AshError> {
    // BUG-007 & BUG-012: Validate timestamp format
    ash_validate_timestamp_format(timestamp)?;

    // SEC-013: Validate consistency - scope_hash must be empty when scope is empty
    if scope.is_empty() && !scope_hash.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ScopeMismatch,
            "scope_hash must be empty when scope is empty",
        ));
    }

    // M11-FIX: SEC-013 inverse — scope_hash must NOT be empty when scope is non-empty.
    if !scope.is_empty() && scope_hash.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ScopeMismatch,
            "scope_hash must not be empty when scope is provided",
        ));
    }

    // Validate scope hash if scoping is used
    // BUG-002 & BUG-028: Use unit separator instead of comma
    if !scope.is_empty() {
        let expected_scope_hash = ash_hash_scope(scope)?;
        if !ash_timing_safe_equal(expected_scope_hash.as_bytes(), scope_hash.as_bytes()) {
            return Ok(false);
        }
    }

    // SEC-013: Validate consistency - chain_hash must be empty when previous_proof is absent
    let has_previous = previous_proof.is_some_and(|p| !p.is_empty());
    if !has_previous && !chain_hash.is_empty() {
        return Err(AshError::new(
            AshErrorCode::ChainBroken,
            "chain_hash must be empty when previous_proof is absent",
        ));
    }

    // Validate chain hash if chaining is used
    // BUG-029: ash_hash_proof now validates non-empty
    if let Some(prev) = previous_proof {
        if !prev.is_empty() {
            let expected_chain_hash = ash_hash_proof(prev)?;
            if !ash_timing_safe_equal(expected_chain_hash.as_bytes(), chain_hash.as_bytes()) {
                return Ok(false);
            }
        }
    }

    // Derive client secret and compute expected proof
    // M4-FIX: Use Zeroizing wrapper for panic-safe zeroization.
    use zeroize::Zeroizing;
    let client_secret = Zeroizing::new(ash_derive_client_secret(nonce, context_id, binding)?);

    let build_result = ash_build_proof_unified(
        &client_secret,
        timestamp,
        binding,
        payload,
        scope,
        previous_proof,
    );
    drop(client_secret); // Zeroizing auto-zeroizes on drop
    let result = build_result?;

    // BUG-078: Zeroize expected proof after comparison
    // M2-FIX: UnifiedProofResult now has Drop that zeroizes proof + chain_hash
    let is_valid = ash_timing_safe_equal(
        result.proof.as_bytes(),
        client_proof.as_bytes(),
    );
    drop(result);
    Ok(is_valid)
}

#[cfg(test)]
mod tests_unified {
    use super::*;

    // Test nonces must be at least 32 hex chars (16 bytes)
    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_unified_basic() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";
        let payload = r#"{"name":"John","age":30}"#;

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[],  // No scoping
            None, // No chaining
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            None,
            "",
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_scoped_only() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1","notes":"hi"}"#;
        let scope = vec!["amount", "recipient"];

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &scope,
            None, // No chaining
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(!result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &scope,
            &result.scope_hash,
            None,
            "",
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_chained_only() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /checkout";
        let timestamp = "1234567890";
        let payload = r#"{"cart_id":"cart_123"}"#;
        let previous_proof = "abc123def456";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[], // No scoping
            Some(previous_proof),
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());

        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            Some(previous_proof),
            &result.chain_hash,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_full() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /payment";
        let timestamp = "1234567890";
        let payload = r#"{"amount":500,"currency":"USD","notes":"tip"}"#;
        let scope = vec!["amount", "currency"];
        let previous_proof = "checkout_proof_xyz";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &scope,
            Some(previous_proof),
        )
        .unwrap();

        assert!(!result.proof.is_empty());
        assert!(!result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());

        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &scope,
            &result.scope_hash,
            Some(previous_proof),
            &result.chain_hash,
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_unified_chain_broken() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /payment";
        let timestamp = "1234567890";
        let payload = r#"{"amount":500}"#;
        let previous_proof = "original_proof";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[],
            Some(previous_proof),
        )
        .unwrap();

        // Try to verify with wrong previous proof
        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            Some("tampered_proof"), // Wrong previous proof
            &result.chain_hash,
        )
        .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_unified_scope_tampered() {
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1"}"#;
        let scope = vec!["amount"];

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result =
            ash_build_proof_unified(&client_secret, timestamp, binding, payload, &scope, None)
                .unwrap();

        // Try to verify with different scope
        let tampered_scope = vec!["recipient"];
        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &tampered_scope,    // Different scope
            &result.scope_hash, // Original scope hash
            None,
            "",
        )
        .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_ash_hash_proof() {
        let proof = "test_proof_123";
        let hash1 = ash_hash_proof(proof).unwrap();
        let hash2 = ash_hash_proof(proof).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
    }

    #[test]
    fn test_ash_hash_proof_rejects_empty() {
        // BUG-029: Empty proof should be rejected
        let result = ash_hash_proof("");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("empty"));
    }

    // SEC-013: Consistency validation tests

    #[test]
    fn test_unified_rejects_scope_hash_when_scope_empty() {
        // SEC-013: scope_hash must be empty when scope is empty
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";
        let payload = r#"{"name":"John"}"#;

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[], // No scoping
            None,
        )
        .unwrap();

        // Try to verify with non-empty scope_hash when scope is empty
        let verify_result = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],              // Empty scope
            "fake_scope_hash", // Non-empty scope_hash - should fail
            None,
            "",
        );

        assert!(verify_result.is_err());
        assert_eq!(verify_result.unwrap_err().code(), crate::AshErrorCode::ScopeMismatch);
    }

    #[test]
    fn test_unified_rejects_chain_hash_when_no_previous_proof() {
        // SEC-013: chain_hash must be empty when previous_proof is absent
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";
        let payload = r#"{"name":"John"}"#;

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[],
            None, // No chaining
        )
        .unwrap();

        // Try to verify with non-empty chain_hash when previous_proof is None
        let verify_result = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &result.proof,
            &[],
            "",
            None,              // No previous proof
            "fake_chain_hash", // Non-empty chain_hash - should fail
        );

        assert!(verify_result.is_err());
        assert_eq!(verify_result.unwrap_err().code(), crate::AshErrorCode::ChainBroken);
    }
}

// SEC-011: Large array index protection tests
#[cfg(test)]
mod tests_sec011 {
    use super::*;

    #[test]
    fn test_large_array_index_rejected() {
        // SEC-011 & BUG-036: Large array indices should be rejected to prevent memory exhaustion
        let payload: Value = serde_json::from_str(
            r#"{"items":[{"id":1}]}"#
        ).unwrap();

        // BUG-036: This should be rejected due to allocation limit
        let scope = vec!["items[999999]"];
        let result = ash_extract_scoped_fields(&payload, &scope);

        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("allocation"));
    }

    #[test]
    fn test_valid_array_index_works() {
        // Normal array indices should work
        let payload: Value = serde_json::from_str(
            r#"{"items":[{"id":1},{"id":2},{"id":3}]}"#
        ).unwrap();

        let scope = vec!["items[1]"];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert!(scoped.is_object());
        let items = scoped.get("items").expect("should have items");
        let arr = items.as_array().unwrap();
        assert_eq!(arr.len(), 2); // Index 0 is null, index 1 has value
        assert_eq!(arr[1]["id"], 2);
    }

    #[test]
    fn test_moderate_array_index_within_limit() {
        // Array index within per-index limit (10000) but also within total allocation limit
        let payload: Value = serde_json::from_str(
            r#"{"items":[{"id":1}]}"#
        ).unwrap();

        // 100 elements is fine
        let scope = vec!["items[99]"];
        let result = ash_extract_scoped_fields(&payload, &scope);

        // Should succeed (allocation = 100 elements, well under 10000 limit)
        assert!(result.is_ok());
    }
}

// SEC-018: Timestamp validation tests
#[cfg(test)]
mod tests_sec018 {
    use super::*;

    #[test]
    fn test_rejects_unreasonably_large_timestamp() {
        // SEC-018: Very large timestamps should be rejected
        let huge_timestamp = "99999999999999999"; // Way beyond year 3000
        let result = ash_validate_timestamp(huge_timestamp, 300, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum"));
    }

    #[test]
    fn test_accepts_normal_timestamp() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let result = ash_validate_timestamp(&now.to_string(), 300, 60);
        assert!(result.is_ok());
    }
}

// SEC-019: Scope path depth protection tests
#[cfg(test)]
mod tests_sec019 {
    use super::*;

    #[test]
    fn test_deep_scope_path_ignored() {
        // SEC-019: Very deep scope paths should be silently ignored
        let payload: Value = serde_json::json!({"a": {"b": {"c": 1}}});

        // Create a path deeper than MAX_SCOPE_PATH_DEPTH
        let deep_path = (0..35).map(|_| "x").collect::<Vec<_>>().join(".");
        let scope = vec![deep_path.as_str()];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        // Result should be empty object since the deep path is ignored
        assert!(scoped.is_object());
        assert!(scoped.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_normal_depth_path_works() {
        // Paths with normal depth should work
        let payload: Value = serde_json::json!({"a": {"b": {"c": 1}}});
        let scope = vec!["a.b.c"];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert!(scoped.is_object());
        let c_value = scoped.get("a")
            .and_then(|a| a.get("b"))
            .and_then(|b| b.get("c"));
        assert_eq!(c_value, Some(&serde_json::json!(1)));
    }
}

// BUG-022: Multi-dimensional array notation tests
#[cfg(test)]
mod tests_bug022 {
    use super::*;

    #[test]
    fn test_multi_dimensional_array_get() {
        // BUG-022: Support paths like matrix[0][1]
        let payload: Value = serde_json::json!({
            "matrix": [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
        });

        let scope = vec!["matrix[1][2]"];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        // Should extract matrix[1][2] = 6
        assert!(scoped.is_object());
        let matrix = scoped.get("matrix").expect("should have matrix");
        let arr = matrix.as_array().unwrap();
        // arr[0] and arr[1][0], arr[1][1] should be null, arr[1][2] should be 6
        assert_eq!(arr.len(), 2); // Indices 0 and 1
        let inner = arr[1].as_array().unwrap();
        assert_eq!(inner.len(), 3); // Indices 0, 1, 2
        assert_eq!(inner[2], 6);
    }

    #[test]
    fn test_multi_dimensional_array_nested_object() {
        // BUG-022: Support paths like items[0][1].name
        let payload: Value = serde_json::json!({
            "items": [
                [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}],
                [{"id": 3, "name": "c"}, {"id": 4, "name": "d"}]
            ]
        });

        let scope = vec!["items[1][0].name"];
        let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();

        // Should extract items[1][0].name = "c"
        let items = scoped.get("items").expect("should have items");
        let outer = items.as_array().unwrap();
        assert_eq!(outer.len(), 2);
        let inner = outer[1].as_array().unwrap();
        assert_eq!(inner.len(), 1);
        let obj = inner[0].as_object().unwrap();
        assert_eq!(obj.get("name").unwrap(), "c");
    }

    #[test]
    fn test_ash_parse_all_array_indices() {
        // Test the helper function directly
        let notation = ash_parse_all_array_indices("items[0][1][2]");
        assert_eq!(notation.key, "items");
        assert_eq!(notation.indices, vec![0, 1, 2]);

        let notation2 = ash_parse_all_array_indices("simple");
        assert_eq!(notation2.key, "simple");
        assert!(notation2.indices.is_empty());

        let notation3 = ash_parse_all_array_indices("arr[5]");
        assert_eq!(notation3.key, "arr");
        assert_eq!(notation3.indices, vec![5]);
    }

    #[test]
    fn test_multi_dimensional_invalid_index() {
        // Invalid indices should invalidate - prevents partial/ambiguous access
        let notation = ash_parse_all_array_indices("items[0][abc][2]");
        assert_eq!(notation.key, "items");
        // All indices are invalidated because there's unparseable content
        // This is safer than partial access which could lead to unexpected behavior
        assert!(notation.indices.is_empty());
    }

    #[test]
    fn test_multi_dimensional_trailing_text() {
        // Trailing text after indices invalidates all indices but preserves key
        let notation = ash_parse_all_array_indices("items[0][1]extra");
        assert_eq!(notation.key, "items");
        // Indices are invalidated due to trailing text - safer than partial access
        assert!(notation.indices.is_empty());
    }
}

// BUG-023: Scope auto-sorting tests
#[cfg(test)]
mod tests_bug023 {
    use super::*;

    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_scope_order_independent() {
        // BUG-023: Different scope orders should produce same hash
        let scope1 = vec!["amount", "recipient"];
        let scope2 = vec!["recipient", "amount"];

        let hash1 = ash_hash_scope(&scope1).unwrap();
        let hash2 = ash_hash_scope(&scope2).unwrap();

        assert_eq!(hash1, hash2, "Scope order should not affect hash");
    }

    #[test]
    fn test_scope_deduplication() {
        // BUG-023: Duplicate fields should be deduplicated
        let scope1 = vec!["amount", "amount", "recipient"];
        let scope2 = vec!["amount", "recipient"];

        let hash1 = ash_hash_scope(&scope1).unwrap();
        let hash2 = ash_hash_scope(&scope2).unwrap();

        assert_eq!(hash1, hash2, "Duplicate fields should be deduplicated");
    }

    #[test]
    fn test_scope_rejects_delimiter_in_field_name() {
        // BUG-028: Field names containing delimiter should be rejected
        let scope_with_delimiter = vec!["amount", "field\x1Fname"];

        let result = ash_hash_scope(&scope_with_delimiter);
        assert!(result.is_err(), "Should reject field names containing delimiter");
        assert!(result.unwrap_err().message().contains("delimiter"));
    }

    #[test]
    fn test_scoped_proof_order_independent() {
        // BUG-023: Client and server with different scope orders should verify successfully
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /transfer";
        let timestamp = "1234567890";
        let payload = r#"{"amount":1000,"recipient":"user1","notes":"hi"}"#;

        // Client uses one order
        let client_scope = vec!["recipient", "amount"];
        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let (proof, scope_hash) =
            ash_build_proof_scoped(&client_secret, timestamp, binding, payload, &client_scope).unwrap();

        // Server uses different order
        let server_scope = vec!["amount", "recipient"];
        let is_valid = ash_verify_proof_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &server_scope, // Different order!
            &scope_hash,
            &proof,
        )
        .unwrap();

        assert!(is_valid, "Verification should succeed regardless of scope order");
    }
}

// BUG-036: Total array allocation limit tests
#[cfg(test)]
mod tests_bug036 {
    use super::*;

    #[test]
    fn test_rejects_excessive_array_allocation() {
        // BUG-036: Multiple large array indices should be rejected
        let payload: Value = serde_json::json!({});

        // Each index creates (idx+1) elements, so this would create way too many
        let scope = vec![
            "items[9999]",
            "other[9999]",
        ];
        // Total allocation: 10000 + 10000 = 20000, exceeds 10000 limit

        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("allocation"));
    }

    #[test]
    fn test_accepts_reasonable_array_allocation() {
        // Reasonable allocation should work
        let payload: Value = serde_json::json!({
            "items": [{"id": 1}, {"id": 2}, {"id": 3}]
        });

        let scope = vec!["items[0]", "items[1]", "items[2]"];
        // Total allocation: 1 + 2 + 3 = 6 elements

        let result = ash_extract_scoped_fields(&payload, &scope);
        assert!(result.is_ok());
    }

    #[test]
    fn test_allocation_calculation() {
        // Test the allocation calculation helper
        let scope = vec!["items[10]", "matrix[5][5]"];
        // items[10] = 11 elements
        // matrix[5][5] = 6 + 6 = 12 elements
        // Total = 23
        let total = ash_calculate_total_array_allocation(&scope);
        assert_eq!(total, 23);
    }

    #[test]
    fn test_allocation_calculation_overflow_protection() {
        // BUG-050: Ensure overflow doesn't cause panic or incorrect result
        // Using usize::MAX would overflow idx+1 without protection
        // The saturating arithmetic should prevent this
        let scope = vec!["items[18446744073709551615]"]; // usize::MAX on 64-bit

        // This should not panic and should return usize::MAX (saturated)
        let total = ash_calculate_total_array_allocation(&scope);
        // With saturating_add, usize::MAX + 1 saturates to usize::MAX
        assert_eq!(total, usize::MAX);
    }
}

// BUG-039: Empty scope field name tests
#[cfg(test)]
mod tests_bug039 {
    use super::*;

    #[test]
    fn test_rejects_empty_scope_field_name() {
        // BUG-039: Empty field names should be rejected
        let scope = vec!["amount", ""];
        let result = ash_hash_scope(&scope);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("empty"));
    }

    #[test]
    fn test_rejects_only_empty_scope_field() {
        let scope = vec![""];
        let result = ash_hash_scope(&scope);
        assert!(result.is_err());
    }

    #[test]
    fn test_accepts_valid_scope_fields() {
        let scope = vec!["amount", "recipient"];
        let result = ash_hash_scope(&scope);
        assert!(result.is_ok());
    }
}

// BUG-024: Empty payload handling tests
#[cfg(test)]
mod tests_bug024 {
    use super::*;

    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_empty_payload_scoped() {
        // BUG-024: Empty payload should be treated as empty object
        let client_secret = "test_secret";
        let timestamp = "1234567890";
        let binding = "POST /api/test";

        // These should all work without error
        let result1 = ash_build_proof_scoped(client_secret, timestamp, binding, "", &[]);
        assert!(result1.is_ok(), "Empty string payload should work");

        let result2 = ash_build_proof_scoped(client_secret, timestamp, binding, "  ", &[]);
        assert!(result2.is_ok(), "Whitespace-only payload should work");
    }

    #[test]
    fn test_empty_payload_unified() {
        // BUG-024: Empty payload in unified function
        let client_secret = "test_secret";
        let timestamp = "1234567890";
        let binding = "POST /api/test";

        let result = ash_build_proof_unified(
            client_secret,
            timestamp,
            binding,
            "",
            &[],
            None,
        );
        assert!(result.is_ok(), "Empty string payload should work");
    }

    #[test]
    fn test_empty_payload_hash_scoped_body() {
        // BUG-024: hash_scoped_body should handle empty payload
        let result = ash_hash_scoped_body("", &[]);
        assert!(result.is_ok(), "Empty payload should work");

        let result2 = ash_hash_scoped_body("   ", &[]);
        assert!(result2.is_ok(), "Whitespace payload should work");
    }

    #[test]
    fn test_empty_payload_produces_consistent_hash() {
        // BUG-024: Empty string and {} should produce same result
        let hash1 = ash_hash_scoped_body("", &[]).unwrap();
        let hash2 = ash_hash_scoped_body("{}", &[]).unwrap();

        assert_eq!(hash1, hash2, "Empty string and {{}} should produce same hash");
    }

    #[test]
    fn test_empty_payload_verification() {
        // BUG-024: Full verification with empty payload
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &client_secret,
            timestamp,
            binding,
            "",
            &[],
            None,
        ).unwrap();

        // Verify with empty payload
        let is_valid = ash_verify_proof_unified(
            nonce,
            context_id,
            binding,
            timestamp,
            "",
            &result.proof,
            &[],
            "",
            None,
            "",
        ).unwrap();

        assert!(is_valid);
    }
}

// BUG-046, BUG-047: Input validation tests for scoped/unified build functions
#[cfg(test)]
mod tests_bug046_047 {
    use super::*;

    #[test]
    fn test_build_proof_scoped_rejects_empty_client_secret() {
        // BUG-046: Empty client_secret should be rejected
        let result = ash_build_proof_scoped("", "1234567890", "POST|/api|", "{}", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("client_secret"));
    }

    #[test]
    fn test_build_proof_scoped_rejects_empty_timestamp() {
        // BUG-046/BUG-079: Empty timestamp should be rejected via ash_validate_timestamp_format
        let result = ash_build_proof_scoped("secret", "", "POST|/api|", "{}", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("Timestamp"));
    }

    #[test]
    fn test_build_proof_scoped_rejects_empty_binding() {
        // BUG-046: Empty binding should be rejected
        let result = ash_build_proof_scoped("secret", "1234567890", "", "{}", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("binding"));
    }

    #[test]
    fn test_build_proof_unified_rejects_empty_client_secret() {
        // BUG-047: Empty client_secret should be rejected
        let result = ash_build_proof_unified("", "1234567890", "POST|/api|", "{}", &[], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("client_secret"));
    }

    #[test]
    fn test_build_proof_unified_rejects_empty_timestamp() {
        // BUG-047/BUG-079: Empty timestamp should be rejected via ash_validate_timestamp_format
        let result = ash_build_proof_unified("secret", "", "POST|/api|", "{}", &[], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("Timestamp"));
    }

    #[test]
    fn test_build_proof_unified_rejects_empty_binding() {
        // BUG-047: Empty binding should be rejected
        let result = ash_build_proof_unified("secret", "1234567890", "", "{}", &[], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("binding"));
    }
}

// BUG-049: SEC-013 consistency validation in verify_proof_scoped
#[cfg(test)]
mod tests_bug049 {
    use super::*;

    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_verify_proof_scoped_rejects_scope_hash_when_scope_empty() {
        // BUG-049 & SEC-013: scope_hash must be empty when scope is empty
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";
        let payload = r#"{"name":"John"}"#;

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let (proof, _) = ash_build_proof_scoped(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[], // No scoping
        ).unwrap();

        // Try to verify with non-empty scope_hash when scope is empty
        let verify_result = ash_verify_proof_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &[],               // Empty scope
            "fake_scope_hash", // Non-empty scope_hash - should fail
            &proof,
        );

        assert!(verify_result.is_err());
        assert_eq!(verify_result.unwrap_err().code(), crate::AshErrorCode::ScopeMismatch);
    }

    #[test]
    fn test_verify_proof_scoped_accepts_valid_empty_scope() {
        // BUG-049: Valid case - empty scope with empty scope_hash should work
        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST /api/test";
        let timestamp = "1234567890";
        let payload = r#"{"name":"John"}"#;

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(
            &client_secret,
            timestamp,
            binding,
            payload,
            &[], // No scoping
        ).unwrap();

        assert!(scope_hash.is_empty(), "scope_hash should be empty for empty scope");

        // Verify should succeed
        let verify_result = ash_verify_proof_scoped(
            nonce,
            context_id,
            binding,
            timestamp,
            payload,
            &[],
            "",
            &proof,
        );

        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }
}

// SEC-AUDIT: Security audit tests
#[cfg(test)]
mod tests_security_audit {
    use super::*;

    const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef";
    const TEST_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn test_sec_audit_004_binding_length_limit_derive() {
        // SEC-AUDIT-004: Binding length should be limited
        let long_binding = "a".repeat(8193); // > 8KB
        let result = ash_derive_client_secret(TEST_NONCE, "ctx_abc", &long_binding);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum length"));
    }

    #[test]
    fn test_sec_audit_004_binding_length_limit_build() {
        // SEC-AUDIT-004: Binding length should be limited in build_proof
        let long_binding = "a".repeat(8193); // > 8KB
        let result = ash_build_proof("secret", "1234567890", &long_binding, TEST_BODY_HASH);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum length"));
    }

    #[test]
    fn test_sec_audit_004_binding_at_limit_ok() {
        // Binding at exactly 8KB should be OK
        let long_binding = "a".repeat(8192);
        let result = ash_build_proof("secret", "1234567890", &long_binding, TEST_BODY_HASH);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sec_audit_002_verify_with_freshness() {
        // SEC-AUDIT-002: Test the new convenience function
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST|/api/test|";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = now.to_string();

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&client_secret, &timestamp, binding, TEST_BODY_HASH).unwrap();

        // Fresh timestamp should work
        let result = ash_verify_proof_with_freshness(
            nonce, context_id, binding, &timestamp, TEST_BODY_HASH, &proof,
            300, 60
        );
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_sec_audit_002_verify_with_freshness_rejects_expired() {
        // SEC-AUDIT-002: Expired timestamp should be rejected
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = TEST_NONCE;
        let context_id = "ctx_abc123";
        let binding = "POST|/api/test|";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_timestamp = (now - 600).to_string(); // 10 minutes ago

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&client_secret, &old_timestamp, binding, TEST_BODY_HASH).unwrap();

        // Expired timestamp should fail
        let result = ash_verify_proof_with_freshness(
            nonce, context_id, binding, &old_timestamp, TEST_BODY_HASH, &proof,
            300, 60  // 5 minute max age
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("expired"));
    }

    #[test]
    fn test_sec_audit_003_generic_error_message() {
        // SEC-AUDIT-003: Error message should not include user input
        let field_with_delimiter = format!("secret_field{}name", SCOPE_FIELD_DELIMITER);
        let result = ash_hash_scope(&[&field_with_delimiter]);
        assert!(result.is_err());
        // Should NOT contain the actual field name in the error
        let error_msg = result.unwrap_err().message().to_string();
        assert!(!error_msg.contains("secret_field")); // User input should not be echoed
        assert!(!error_msg.contains("name")); // User input should not be echoed
        assert!(error_msg.contains("delimiter")); // Generic error info is OK
    }
}
