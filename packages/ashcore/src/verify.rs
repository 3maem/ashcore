//! High-level request verification (Phase 3-A).
//!
//! `verify_incoming_request()` orchestrates existing Core primitives in a
//! fixed execution order. No new logic — only assembly.
//!
//! ## Why This Exists
//!
//! Before this function, every middleware reimplemented the same multi-step
//! pipeline: extract headers → validate timestamp → normalize binding →
//! hash body → compare → verify proof. Each reimplementation introduced
//! divergence (different error ordering, different validation sequencing).
//!
//! Now the middleware reduces to:
//! ```text
//! context = store.lookup(context_id)
//! canonical_body = canonicalize(body, content_type)
//! result = verify_incoming_request(input)
//! if result.ok { proceed } else { return result.error.http_status }
//! ```
//!
//! ## Execution Order (Locked)
//!
//! The following order is fixed and must not change. It determines which
//! error is returned when multiple inputs are invalid.
//!
//! 1. Extract headers (ts, body-hash, proof from `HeaderMapView`)
//! 2. Validate timestamp format
//! 3. Validate timestamp freshness (skew)
//! 4. Validate nonce format
//! 5. Normalize binding (method + path + query)
//! 6. Hash canonical body
//! 7. Compare computed body hash with header body hash
//! 8. Verify proof (re-derives secret, HMAC comparison)
//! 9. Return ok

use crate::compare::ash_timing_safe_equal;
use crate::errors::{AshError, AshErrorCode, InternalReason};
use crate::headers::{self, HeaderMapView, HDR_BODY_HASH, HDR_PROOF, HDR_TIMESTAMP};
use crate::proof::{
    ash_build_proof, ash_build_proof_scoped, ash_derive_client_secret,
    ash_hash_body, ash_hash_scope, ash_validate_timestamp_format,
    ash_verify_proof_unified,
};
use crate::validate::ash_validate_nonce;
use zeroize::Zeroizing;

// ── Input ─────────────────────────────────────────────────────────────

/// Input for high-level request verification.
///
/// The middleware is responsible for:
/// - Looking up the context in the store → providing `nonce` and `context_id`
/// - Reading the body and canonicalizing it (based on content type)
/// - Providing the raw HTTP headers via `HeaderMapView`
///
/// The verifier handles everything else: header extraction, validation,
/// binding normalization, body hash comparison, and proof verification.
pub struct VerifyRequestInput<'a, H: HeaderMapView> {
    /// HTTP headers (implements `HeaderMapView` for case-insensitive lookup)
    pub headers: &'a H,

    /// HTTP method (e.g., "POST", "GET")
    pub method: &'a str,

    /// URL path without query string (e.g., "/api/transfer")
    pub path: &'a str,

    /// Raw query string without leading `?` (e.g., "page=1&sort=name")
    pub raw_query: &'a str,

    /// Canonicalized body string (caller canonicalizes based on content type)
    pub canonical_body: &'a str,

    /// Server nonce (from store lookup, not from headers)
    pub nonce: &'a str,

    /// Context ID (from store lookup or header extraction)
    pub context_id: &'a str,

    /// Maximum allowed timestamp age in seconds (e.g., 300 = 5 minutes)
    pub max_age_seconds: u64,

    /// Clock skew tolerance in seconds (e.g., 60)
    pub clock_skew_seconds: u64,
}

// ── Output ────────────────────────────────────────────────────────────

/// Result of high-level request verification.
pub struct VerifyResult {
    /// Whether the request passed all checks
    pub ok: bool,

    /// The error if verification failed (None if ok)
    pub error: Option<AshError>,

    /// Debug metadata (only populated in debug builds)
    pub meta: Option<VerifyMeta>,
}

/// Non-normative debug metadata. Must not contain secrets.
pub struct VerifyMeta {
    /// The canonical query string that was computed
    pub canonical_query: String,

    /// The body hash that was computed from the canonical body
    pub computed_body_hash: String,

    /// The binding string that was assembled
    pub binding: String,
}

impl VerifyResult {
    fn fail(error: AshError) -> Self {
        Self {
            ok: false,
            error: Some(error),
            meta: None,
        }
    }

    fn success(meta: Option<VerifyMeta>) -> Self {
        Self {
            ok: true,
            error: None,
            meta,
        }
    }
}

// ── Verification Function ─────────────────────────────────────────────

/// Verify an incoming HTTP request using ashcore (basic proofs only).
///
/// **Note**: This function only handles basic (non-scoped, non-chained) proofs.
/// For scoped or unified proof verification, use `ash_verify_proof_scoped` or
/// `ash_verify_proof_unified` from the `proof` module directly.
///
/// Orchestrates all Core primitives in a fixed execution order.
/// Returns the first error encountered (no error accumulation).
///
/// # Execution Order (locked)
///
/// 1. Extract `x-ash-ts`, `x-ash-body-hash`, `x-ash-proof` from headers
/// 2. Validate timestamp format (digits, no leading zeros, within bounds)
/// 3. Validate timestamp freshness (not expired, not future)
/// 4. Validate nonce format (length, hex charset)
/// 5. Normalize binding (METHOD|PATH|CANONICAL_QUERY)
/// 6. Hash canonical body → computed_body_hash
/// 7. Compare computed_body_hash with header body hash (timing-safe)
/// 8. Verify proof (re-derive secret, build expected proof, compare)
/// 9. Return ok
///
/// # Example
///
/// ```rust
/// use ashcore::headers::HeaderMapView;
/// use ashcore::verify::{verify_incoming_request, VerifyRequestInput};
///
/// struct MyHeaders(Vec<(String, String)>);
/// impl HeaderMapView for MyHeaders {
///     fn get_all_ci(&self, name: &str) -> Vec<&str> {
///         let n = name.to_ascii_lowercase();
///         self.0.iter()
///             .filter(|(k, _)| k.to_ascii_lowercase() == n)
///             .map(|(_, v)| v.as_str())
///             .collect()
///     }
/// }
///
/// // In a real middleware, these come from the request + store
/// let headers = MyHeaders(vec![
///     ("x-ash-ts".into(), "1700000000".into()),
///     ("x-ash-body-hash".into(), "some_hash".into()),
///     ("x-ash-proof".into(), "some_proof".into()),
/// ]);
///
/// let input = VerifyRequestInput {
///     headers: &headers,
///     method: "POST",
///     path: "/api/transfer",
///     raw_query: "",
///     canonical_body: "{}",
///     nonce: "0123456789abcdef0123456789abcdef",
///     context_id: "ctx_abc123",
///     max_age_seconds: 300,
///     clock_skew_seconds: 60,
/// };
///
/// let result = verify_incoming_request(&input);
/// // result.ok will be false because the proof won't match,
/// // but the pipeline executes correctly
/// ```
pub fn verify_incoming_request<H: HeaderMapView>(input: &VerifyRequestInput<'_, H>) -> VerifyResult {
    // ── Step 1: Extract required headers ──────────────────────────────
    // BUG-066: Reuse headers::get_one instead of duplicate extract_single_header.
    let ts = match headers::get_one(input.headers, HDR_TIMESTAMP) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };

    let header_body_hash = match headers::get_one(input.headers, HDR_BODY_HASH) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };

    let proof = match headers::get_one(input.headers, HDR_PROOF) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };

    // ── Step 2: Validate timestamp format ─────────────────────────────
    if let Err(e) = ash_validate_timestamp_format(&ts) {
        return VerifyResult::fail(e);
    }

    // ── Step 3: Validate timestamp freshness ──────────────────────────
    if let Err(e) = validate_timestamp_with_reference(
        &ts,
        input.max_age_seconds,
        input.clock_skew_seconds,
    ) {
        return VerifyResult::fail(e);
    }

    // ── Step 4: Validate nonce format ─────────────────────────────────
    if let Err(e) = ash_validate_nonce(input.nonce) {
        return VerifyResult::fail(e);
    }

    // ── Step 5: Normalize binding ─────────────────────────────────────
    let binding = match crate::ash_normalize_binding(input.method, input.path, input.raw_query) {
        Ok(b) => b,
        Err(e) => return VerifyResult::fail(e),
    };

    // ── Step 6: Hash canonical body ───────────────────────────────────
    let computed_body_hash = crate::proof::ash_hash_body(input.canonical_body);

    // ── Step 7: Compare body hashes (timing-safe) ─────────────────────
    if !ash_timing_safe_equal(computed_body_hash.as_bytes(), header_body_hash.as_bytes()) {
        return VerifyResult::fail(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::General,
            "Body hash mismatch",
        ));
    }

    // ── Step 8: Verify proof ──────────────────────────────────────────
    // M4-FIX: Use Zeroizing wrapper for panic-safe zeroization.
    let client_secret = match ash_derive_client_secret(input.nonce, input.context_id, &binding) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => return VerifyResult::fail(e),
    };

    let result = ash_build_proof(&client_secret, &ts, &binding, &computed_body_hash);
    drop(client_secret); // Zeroizing auto-zeroizes on drop
    let expected_proof = match result {
        Ok(p) => Zeroizing::new(p),
        Err(e) => return VerifyResult::fail(e),
    };

    // BUG-078: Zeroize expected proof after comparison to prevent it from
    // persisting in memory. M4-FIX: Zeroizing wrapper handles this on drop.
    let proof_valid = ash_timing_safe_equal(expected_proof.as_bytes(), proof.as_bytes());
    drop(expected_proof);

    if !proof_valid {
        return VerifyResult::fail(AshError::new(
            AshErrorCode::ProofInvalid,
            "Proof verification failed",
        ));
    }

    // ── Step 9: Success ───────────────────────────────────────────────
    let meta = if cfg!(debug_assertions) {
        // BUG-055: Extract the canonical query from the binding (third pipe-delimited
        // segment), not from raw_query which is unsorted/unnormalized.
        let canonical_query = binding
            .rsplit('|')
            .next()
            .unwrap_or("")
            .to_string();
        Some(VerifyMeta {
            canonical_query,
            computed_body_hash,
            binding,
        })
    } else {
        None
    };

    VerifyResult::success(meta)
}

// ── Scoped Verification ──────────────────────────────────────────────

/// Input for high-level scoped request verification.
///
/// Like `VerifyRequestInput`, but additionally includes scope fields and
/// scope hash for field-level payload protection.
pub struct VerifyScopedInput<'a, H: HeaderMapView> {
    /// HTTP headers (implements `HeaderMapView` for case-insensitive lookup)
    pub headers: &'a H,
    /// HTTP method (e.g., "POST", "GET")
    pub method: &'a str,
    /// URL path without query string (e.g., "/api/transfer")
    pub path: &'a str,
    /// Raw query string without leading `?`
    pub raw_query: &'a str,
    /// Canonicalized body string (caller canonicalizes based on content type)
    pub canonical_body: &'a str,
    /// Server nonce (from store lookup, not from headers)
    pub nonce: &'a str,
    /// Context ID (from store lookup or header extraction)
    pub context_id: &'a str,
    /// Maximum allowed timestamp age in seconds
    pub max_age_seconds: u64,
    /// Clock skew tolerance in seconds
    pub clock_skew_seconds: u64,
    /// Scope fields (e.g., &["amount", "recipient"])
    pub scope: &'a [&'a str],
    /// Expected scope hash (from the client)
    pub scope_hash: &'a str,
}

/// Verify an incoming scoped HTTP request using ashcore.
///
/// Same pipeline as `verify_incoming_request` but additionally validates
/// the scope hash and uses `ash_build_proof_scoped` for proof comparison.
///
/// # Execution Order (locked)
///
/// Steps 1-7 are identical to `verify_incoming_request`.
/// Step 8 additionally validates scope hash, then compares scoped proof.
pub fn verify_incoming_request_scoped<H: HeaderMapView>(
    input: &VerifyScopedInput<'_, H>,
) -> VerifyResult {
    // ── Steps 1-3: Extract headers + validate timestamp ──────────────
    let ts = match headers::get_one(input.headers, HDR_TIMESTAMP) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };
    let header_body_hash = match headers::get_one(input.headers, HDR_BODY_HASH) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };
    let proof = match headers::get_one(input.headers, HDR_PROOF) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };
    if let Err(e) = ash_validate_timestamp_format(&ts) {
        return VerifyResult::fail(e);
    }
    if let Err(e) = validate_timestamp_with_reference(&ts, input.max_age_seconds, input.clock_skew_seconds) {
        return VerifyResult::fail(e);
    }

    // ── Step 4: Validate nonce format ─────────────────────────────────
    if let Err(e) = ash_validate_nonce(input.nonce) {
        return VerifyResult::fail(e);
    }

    // ── Step 5: Normalize binding ─────────────────────────────────────
    let binding = match crate::ash_normalize_binding(input.method, input.path, input.raw_query) {
        Ok(b) => b,
        Err(e) => return VerifyResult::fail(e),
    };

    // ── Step 6: Hash canonical body ───────────────────────────────────
    let computed_body_hash = ash_hash_body(input.canonical_body);

    // ── Step 7: Compare body hashes (timing-safe) ─────────────────────
    if !ash_timing_safe_equal(computed_body_hash.as_bytes(), header_body_hash.as_bytes()) {
        return VerifyResult::fail(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::General,
            "Body hash mismatch",
        ));
    }

    // ── Step 8a: Validate scope hash ──────────────────────────────────
    let expected_scope_hash = match ash_hash_scope(input.scope) {
        Ok(h) => h,
        Err(e) => return VerifyResult::fail(e),
    };
    if !ash_timing_safe_equal(expected_scope_hash.as_bytes(), input.scope_hash.as_bytes()) {
        return VerifyResult::fail(AshError::new(
            AshErrorCode::ScopeMismatch,
            "Scope hash mismatch",
        ));
    }

    // ── Step 8b: Verify scoped proof ──────────────────────────────────
    let client_secret = match ash_derive_client_secret(input.nonce, input.context_id, &binding) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => return VerifyResult::fail(e),
    };
    let result = ash_build_proof_scoped(
        &client_secret, &ts, &binding, input.canonical_body, input.scope,
    );
    drop(client_secret);
    let (expected_proof, _) = match result {
        Ok(r) => r,
        Err(e) => return VerifyResult::fail(e),
    };
    let expected_proof = Zeroizing::new(expected_proof);
    let proof_valid = ash_timing_safe_equal(expected_proof.as_bytes(), proof.as_bytes());
    drop(expected_proof);

    if !proof_valid {
        return VerifyResult::fail(AshError::new(
            AshErrorCode::ProofInvalid,
            "Proof verification failed",
        ));
    }

    // ── Step 9: Success ───────────────────────────────────────────────
    let meta = if cfg!(debug_assertions) {
        let canonical_query = binding.rsplit('|').next().unwrap_or("").to_string();
        Some(VerifyMeta {
            canonical_query,
            computed_body_hash,
            binding,
        })
    } else {
        None
    };
    VerifyResult::success(meta)
}

// ── Unified Verification ─────────────────────────────────────────────

/// Input for high-level unified request verification.
///
/// Handles both scoped and chained proofs in a single orchestrator.
pub struct VerifyUnifiedInput<'a, H: HeaderMapView> {
    /// HTTP headers (implements `HeaderMapView` for case-insensitive lookup)
    pub headers: &'a H,
    /// HTTP method (e.g., "POST", "GET")
    pub method: &'a str,
    /// URL path without query string (e.g., "/api/transfer")
    pub path: &'a str,
    /// Raw query string without leading `?`
    pub raw_query: &'a str,
    /// Canonicalized body string (caller canonicalizes based on content type)
    pub canonical_body: &'a str,
    /// Server nonce (from store lookup, not from headers)
    pub nonce: &'a str,
    /// Context ID (from store lookup or header extraction)
    pub context_id: &'a str,
    /// Maximum allowed timestamp age in seconds
    pub max_age_seconds: u64,
    /// Clock skew tolerance in seconds
    pub clock_skew_seconds: u64,
    /// Scope fields (empty slice if no scoping)
    pub scope: &'a [&'a str],
    /// Expected scope hash (empty string if no scoping)
    pub scope_hash: &'a str,
    /// Previous proof hex for chain validation (None if no chaining)
    pub previous_proof: Option<&'a str>,
    /// Expected chain hash (empty string if no chaining)
    pub chain_hash: &'a str,
}

/// Verify an incoming unified HTTP request using ashcore.
///
/// Handles scoped proofs, chained proofs, or both. Same pipeline as
/// `verify_incoming_request` with additional scope/chain validation.
pub fn verify_incoming_request_unified<H: HeaderMapView>(
    input: &VerifyUnifiedInput<'_, H>,
) -> VerifyResult {
    // ── Steps 1-3: Extract headers + validate timestamp ──────────────
    let ts = match headers::get_one(input.headers, HDR_TIMESTAMP) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };
    let header_body_hash = match headers::get_one(input.headers, HDR_BODY_HASH) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };
    let proof = match headers::get_one(input.headers, HDR_PROOF) {
        Ok(v) => v,
        Err(e) => return VerifyResult::fail(e),
    };
    if let Err(e) = ash_validate_timestamp_format(&ts) {
        return VerifyResult::fail(e);
    }
    if let Err(e) = validate_timestamp_with_reference(&ts, input.max_age_seconds, input.clock_skew_seconds) {
        return VerifyResult::fail(e);
    }

    // ── Step 4: Validate nonce format ─────────────────────────────────
    if let Err(e) = ash_validate_nonce(input.nonce) {
        return VerifyResult::fail(e);
    }

    // ── Step 5: Normalize binding ─────────────────────────────────────
    let binding = match crate::ash_normalize_binding(input.method, input.path, input.raw_query) {
        Ok(b) => b,
        Err(e) => return VerifyResult::fail(e),
    };

    // ── Step 6: Hash canonical body ───────────────────────────────────
    let computed_body_hash = ash_hash_body(input.canonical_body);

    // ── Step 7: Compare body hashes (timing-safe) ─────────────────────
    if !ash_timing_safe_equal(computed_body_hash.as_bytes(), header_body_hash.as_bytes()) {
        return VerifyResult::fail(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::General,
            "Body hash mismatch",
        ));
    }

    // ── Step 8: Verify unified proof via low-level function ───────────
    match ash_verify_proof_unified(
        input.nonce,
        input.context_id,
        &binding,
        &ts,
        input.canonical_body,
        &proof,
        input.scope,
        input.scope_hash,
        input.previous_proof,
        input.chain_hash,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return VerifyResult::fail(AshError::new(
                AshErrorCode::ProofInvalid,
                "Proof verification failed",
            ));
        }
        Err(e) => return VerifyResult::fail(e),
    }

    // ── Step 9: Success ───────────────────────────────────────────────
    let meta = if cfg!(debug_assertions) {
        let canonical_query = binding.rsplit('|').next().unwrap_or("").to_string();
        Some(VerifyMeta {
            canonical_query,
            computed_body_hash,
            binding,
        })
    } else {
        None
    };
    VerifyResult::success(meta)
}

// ── Internal Helpers ──────────────────────────────────────────────────

/// Validate timestamp freshness using system clock.
/// Wraps `ash_validate_timestamp` which uses `SystemTime::now()` internally.
fn validate_timestamp_with_reference(
    timestamp: &str,
    max_age_seconds: u64,
    clock_skew_seconds: u64,
) -> Result<(), AshError> {
    crate::proof::ash_validate_timestamp(timestamp, max_age_seconds, clock_skew_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHeaders(Vec<(String, String)>);

    impl HeaderMapView for TestHeaders {
        fn get_all_ci(&self, name: &str) -> Vec<&str> {
            let n = name.to_ascii_lowercase();
            self.0
                .iter()
                .filter(|(k, _)| k.to_ascii_lowercase() == n)
                .map(|(_, v)| v.as_str())
                .collect()
        }
    }

    fn now_ts() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn make_valid_request() -> (TestHeaders, String, String) {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test123";
        let binding = "POST|/api/transfer|";
        let timestamp = now_ts();
        let canonical_body = r#"{"amount":100}"#;
        let body_hash = crate::proof::ash_hash_body(canonical_body);

        let client_secret =
            ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof =
            ash_build_proof(&client_secret, &timestamp, binding, &body_hash).unwrap();

        let headers = TestHeaders(vec![
            ("x-ash-ts".into(), timestamp),
            ("x-ash-body-hash".into(), body_hash),
            ("x-ash-proof".into(), proof),
        ]);

        (headers, canonical_body.to_string(), nonce.to_string())
    }

    #[test]
    fn test_valid_request_passes() {
        let (headers, canonical_body, nonce) = make_valid_request();

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: &canonical_body,
            nonce: &nonce,
            context_id: "ctx_test123",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(result.ok, "Expected ok, got error: {:?}", result.error);
    }

    #[test]
    fn test_missing_timestamp_fails() {
        let headers = TestHeaders(vec![
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        let err = result.error.unwrap();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.reason(), InternalReason::HdrMissing);
    }

    #[test]
    fn test_invalid_timestamp_format_fails() {
        let headers = TestHeaders(vec![
            ("x-ash-ts".into(), "not_a_number".into()),
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        assert_eq!(result.error.unwrap().code(), AshErrorCode::TimestampInvalid);
    }

    #[test]
    fn test_expired_timestamp_fails() {
        let headers = TestHeaders(vec![
            ("x-ash-ts".into(), "1000000000".into()), // 2001, way expired
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        assert_eq!(result.error.unwrap().code(), AshErrorCode::TimestampInvalid);
    }

    #[test]
    fn test_body_hash_mismatch_fails() {
        let (mut headers, _canonical_body, nonce) = make_valid_request();
        // Tamper with body-hash header
        for (k, v) in &mut headers.0 {
            if k.to_ascii_lowercase() == "x-ash-body-hash" {
                *v = "f".repeat(64); // wrong hash
            }
        }

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":100}"#,
            nonce: &nonce,
            context_id: "ctx_test123",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        let err = result.error.unwrap();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert!(err.message().contains("Body hash"));
    }

    #[test]
    fn test_wrong_proof_fails() {
        let (mut headers, canonical_body, nonce) = make_valid_request();
        // Tamper with proof header
        for (k, v) in &mut headers.0 {
            if k.to_ascii_lowercase() == "x-ash-proof" {
                *v = "f".repeat(64); // wrong proof
            }
        }

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: &canonical_body,
            nonce: &nonce,
            context_id: "ctx_test123",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        assert_eq!(result.error.unwrap().code(), AshErrorCode::ProofInvalid);
    }

    #[test]
    fn test_tampered_body_fails() {
        let (headers, _canonical_body, nonce) = make_valid_request();

        // Original body was {"amount":100}, send different body
        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":999}"#, // tampered
            nonce: &nonce,
            context_id: "ctx_test123",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        // Should fail at body hash comparison (step 7)
        let err = result.error.unwrap();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    // ── Precedence tests ──────────────────────────────────────────────

    #[test]
    fn precedence_missing_ts_before_body_hash_mismatch() {
        // Missing timestamp AND wrong body hash → timestamp error first
        let headers = TestHeaders(vec![
            // no x-ash-ts
            ("x-ash-body-hash".into(), "wrong".repeat(10)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        assert_eq!(result.error.unwrap().reason(), InternalReason::HdrMissing);
    }

    #[test]
    fn precedence_bad_ts_format_before_bad_nonce() {
        // Bad timestamp format AND bad nonce → timestamp error first
        let headers = TestHeaders(vec![
            ("x-ash-ts".into(), "not_number".into()),
            ("x-ash-body-hash".into(), "a".repeat(64)),
            ("x-ash-proof".into(), "b".repeat(64)),
        ]);

        let input = VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "short", // bad nonce
            context_id: "ctx_test",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        };

        let result = verify_incoming_request(&input);
        assert!(!result.ok);
        assert_eq!(result.error.unwrap().code(), AshErrorCode::TimestampInvalid);
    }
}
