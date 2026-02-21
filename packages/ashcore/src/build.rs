//! High-level request proof building (Phase 3-B).
//!
//! `build_request_proof()` orchestrates existing Core primitives in a
//! fixed execution order. No new logic — only assembly.
//!
//! ## Why This Exists
//!
//! Before this function, every client SDK reimplemented the same multi-step
//! pipeline: normalize binding → hash body → derive client secret →
//! build proof → assemble headers. Each reimplementation introduced
//! divergence (different validation ordering, different normalization paths).
//!
//! Now the client SDK reduces to:
//! ```text
//! canonical_body = canonicalize(body, content_type)
//! result = build_request_proof(input)
//! set_header("x-ash-ts", result.timestamp)
//! set_header("x-ash-nonce", result.nonce)
//! set_header("x-ash-body-hash", result.body_hash)
//! set_header("x-ash-proof", result.proof)
//! ```
//!
//! ## Execution Order (Locked)
//!
//! The following order is fixed and must not change:
//!
//! 1. Validate nonce format
//! 2. Validate timestamp format
//! 3. Normalize binding (method + path + query)
//! 4. Hash canonical body
//! 5. Derive client secret (nonce + context_id + binding)
//! 6. Build proof (client_secret + timestamp + binding + body_hash)
//! 7. Return assembled result

use crate::errors::AshError;
use crate::proof::{
    ash_build_proof, ash_build_proof_scoped, ash_build_proof_unified, ash_derive_client_secret,
    ash_hash_body, ash_validate_timestamp_format,
};
use crate::validate::ash_validate_nonce;
use zeroize::{Zeroize, Zeroizing};

// ── Input ─────────────────────────────────────────────────────────────

/// Input for high-level request proof building.
///
/// The client SDK is responsible for:
/// - Obtaining `nonce` and `context_id` from the server
/// - Canonicalizing the body (based on content type)
/// - Generating a current timestamp
///
/// The builder handles everything else: nonce validation, timestamp
/// validation, binding normalization, body hashing, secret derivation,
/// and proof computation.
pub struct BuildRequestInput<'a> {
    /// HTTP method (e.g., "POST", "GET")
    pub method: &'a str,

    /// URL path without query string (e.g., "/api/transfer")
    pub path: &'a str,

    /// Raw query string without leading `?` (e.g., "page=1&sort=name")
    pub raw_query: &'a str,

    /// Canonicalized body string (caller canonicalizes based on content type)
    pub canonical_body: &'a str,

    /// Server nonce (from context response)
    pub nonce: &'a str,

    /// Context ID (from context response)
    pub context_id: &'a str,

    /// Unix timestamp as string (caller generates current time)
    pub timestamp: &'a str,

    /// Optional: scope fields for scoped proof (e.g., &["amount", "recipient"])
    pub scope: Option<&'a [&'a str]>,

    /// Optional: previous proof hex for request chaining
    pub previous_proof: Option<&'a str>,
}

/// BUG-092: Custom Debug that redacts nonce to prevent accidental log exposure.
impl<'a> std::fmt::Debug for BuildRequestInput<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildRequestInput")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("raw_query", &self.raw_query)
            .field("canonical_body", &self.canonical_body)
            .field("nonce", &"[REDACTED]")
            .field("context_id", &self.context_id)
            .field("timestamp", &self.timestamp)
            .field("scope", &self.scope)
            .field("previous_proof", &self.previous_proof.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

// ── Output ────────────────────────────────────────────────────────────

/// Result of high-level request proof building.
///
/// Contains all values the client needs to set as HTTP headers.
///
/// BUG-084: Implements `Zeroize` and `Drop` (via zeroize) because `proof` and
/// `body_hash` are security-sensitive values that should not persist in memory.
#[derive(Debug)]
pub struct BuildRequestResult {
    /// The cryptographic proof (64-char lowercase hex)
    pub proof: String,

    /// The body hash (64-char lowercase hex)
    pub body_hash: String,

    /// The normalized binding string (METHOD|PATH|CANONICAL_QUERY)
    pub binding: String,

    /// The timestamp used (echoed back for header)
    pub timestamp: String,

    /// The nonce used (echoed back for header)
    pub nonce: String,

    /// Scope hash (empty string if no scoping)
    pub scope_hash: String,

    /// Chain hash (empty string if no chaining)
    pub chain_hash: String,

    /// Debug metadata (only populated in debug builds)
    pub meta: Option<BuildMeta>,
}

/// BUG-084: Zeroize security-sensitive fields on drop.
/// BUG-097: Also zeroize scope_hash and chain_hash — they are derived from
/// the client secret and could aid proof reconstruction if leaked.
/// L7-FIX: Also zeroize binding and timestamp — binding is an input to secret
/// derivation, and zeroizing all fields is defense-in-depth.
impl Drop for BuildRequestResult {
    fn drop(&mut self) {
        self.proof.zeroize();
        self.body_hash.zeroize();
        self.nonce.zeroize();
        self.scope_hash.zeroize();
        self.chain_hash.zeroize();
        self.binding.zeroize();
        self.timestamp.zeroize();
    }
}

/// Non-normative debug metadata. Must not contain secrets.
#[derive(Debug)]
pub struct BuildMeta {
    /// The canonical query string that was computed
    pub canonical_query: String,
}

// ── Build Function ───────────────────────────────────────────────────

/// Build an HTTP request proof using ashcore.
///
/// Orchestrates all Core primitives in a fixed execution order.
/// Returns the first error encountered (no error accumulation).
///
/// # Execution Order (locked)
///
/// 1. Validate nonce format (length, hex charset)
/// 2. Validate timestamp format (digits, no leading zeros, within bounds)
/// 3. Normalize binding (METHOD|PATH|CANONICAL_QUERY)
/// 4. Hash canonical body → body_hash
/// 5. Derive client secret (nonce + context_id + binding)
/// 6. Build proof (client_secret + timestamp + binding + body_hash)
/// 7. Return result with all header values
///
/// # Proof Modes
///
/// - **Basic**: `scope` is None, `previous_proof` is None → standard proof
/// - **Scoped**: `scope` is Some → scoped proof with scope_hash
/// - **Unified**: `scope` is Some and/or `previous_proof` is Some → unified proof
///
/// # Example
///
/// ```rust
/// use ashcore::build::{build_request_proof, BuildRequestInput};
///
/// let input = BuildRequestInput {
///     method: "POST",
///     path: "/api/transfer",
///     raw_query: "",
///     canonical_body: r#"{"amount":100,"recipient":"alice"}"#,
///     nonce: "0123456789abcdef0123456789abcdef",
///     context_id: "ctx_abc123",
///     timestamp: "1700000000",
///     scope: None,
///     previous_proof: None,
/// };
///
/// let result = build_request_proof(&input).unwrap();
/// assert_eq!(result.body_hash.len(), 64);
/// assert_eq!(result.proof.len(), 64);
/// assert_eq!(result.binding, "POST|/api/transfer|");
/// ```
pub fn build_request_proof(input: &BuildRequestInput<'_>) -> Result<BuildRequestResult, AshError> {
    // ── Step 1: Validate nonce format ─────────────────────────────────
    ash_validate_nonce(input.nonce)?;

    // ── Step 2: Validate timestamp format ─────────────────────────────
    ash_validate_timestamp_format(input.timestamp)?;

    // ── Step 3: Normalize binding ─────────────────────────────────────
    let binding =
        crate::ash_normalize_binding(input.method, input.path, input.raw_query)?;

    // ── Step 4: Hash canonical body ───────────────────────────────────
    let body_hash = ash_hash_body(input.canonical_body);

    // ── Step 5: Derive client secret ──────────────────────────────────
    // M4-FIX: Use Zeroizing wrapper for panic-safe zeroization.
    // Previously manual .zeroize() would be skipped on panic.
    let client_secret = Zeroizing::new(
        ash_derive_client_secret(input.nonce, input.context_id, &binding)?
    );

    // ── Step 6: Build proof ───────────────────────────────────────────
    let result = match (input.scope, input.previous_proof) {
        // Unified: scope and/or chain
        (Some(scope), Some(prev)) => {
            let r = ash_build_proof_unified(
                &client_secret,
                input.timestamp,
                &binding,
                input.canonical_body,
                scope,
                Some(prev),
            );
            r.map(|mut r| {
                let proof = std::mem::take(&mut r.proof);
                let scope_hash = std::mem::take(&mut r.scope_hash);
                let chain_hash = std::mem::take(&mut r.chain_hash);
                (proof, scope_hash, chain_hash)
            })
        }
        // Unified with chain only (no scope)
        (None, Some(prev)) => {
            let r = ash_build_proof_unified(
                &client_secret,
                input.timestamp,
                &binding,
                input.canonical_body,
                &[],
                Some(prev),
            );
            r.map(|mut r| {
                let proof = std::mem::take(&mut r.proof);
                let scope_hash = std::mem::take(&mut r.scope_hash);
                let chain_hash = std::mem::take(&mut r.chain_hash);
                (proof, scope_hash, chain_hash)
            })
        }
        // Scoped only (no chain)
        (Some(scope), None) if !scope.is_empty() => {
            let r = ash_build_proof_scoped(
                &client_secret,
                input.timestamp,
                &binding,
                input.canonical_body,
                scope,
            );
            r.map(|(proof, scope_hash)| (proof, scope_hash, String::new()))
        }
        // Basic proof (no scope, no chain)
        _ => {
            let r = ash_build_proof(&client_secret, input.timestamp, &binding, &body_hash);
            r.map(|proof| (proof, String::new(), String::new()))
        }
    };
    // client_secret is auto-zeroized by Zeroizing wrapper on drop (even on panic)
    drop(client_secret);
    let (proof, scope_hash, chain_hash) = result?;

    // ── Step 7: Assemble result ───────────────────────────────────────
    let canonical_query = if binding.contains('|') {
        // Extract query part from binding (METHOD|PATH|QUERY)
        binding.rsplit('|').next().unwrap_or("").to_string()
    } else {
        String::new()
    };

    let meta = if cfg!(debug_assertions) {
        Some(BuildMeta { canonical_query })
    } else {
        None
    };

    Ok(BuildRequestResult {
        proof,
        body_hash,
        binding,
        timestamp: input.timestamp.to_string(),
        nonce: input.nonce.to_string(),
        scope_hash,
        chain_hash,
        meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{AshErrorCode, InternalReason};

    #[test]
    fn test_basic_build_succeeds() {
        let input = BuildRequestInput {
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":100}"#,
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test123",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        };

        let result = build_request_proof(&input).unwrap();
        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.body_hash.len(), 64);
        assert_eq!(result.binding, "POST|/api/transfer|");
        assert_eq!(result.timestamp, "1700000000");
        assert_eq!(result.nonce, "0123456789abcdef0123456789abcdef");
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_build_normalizes_method() {
        let input = BuildRequestInput {
            method: "post",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        };

        let result = build_request_proof(&input).unwrap();
        assert!(result.binding.starts_with("POST|"));
    }

    #[test]
    fn test_build_normalizes_path() {
        let input = BuildRequestInput {
            method: "GET",
            path: "/api//users/",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        };

        let result = build_request_proof(&input).unwrap();
        assert_eq!(result.binding, "GET|/api/users|");
    }

    #[test]
    fn test_build_canonicalizes_query() {
        let input = BuildRequestInput {
            method: "GET",
            path: "/api/search",
            raw_query: "z=3&a=1",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        };

        let result = build_request_proof(&input).unwrap();
        assert_eq!(result.binding, "GET|/api/search|a=1&z=3");
    }

    #[test]
    fn test_build_bad_nonce_fails_first() {
        let input = BuildRequestInput {
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "short",
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        };

        let err = build_request_proof(&input).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
        assert_eq!(err.reason(), InternalReason::NonceTooShort);
    }

    #[test]
    fn test_build_bad_timestamp_fails_second() {
        let input = BuildRequestInput {
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            timestamp: "not_a_number",
            scope: None,
            previous_proof: None,
        };

        let err = build_request_proof(&input).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
    }

    #[test]
    fn test_build_bad_path_fails() {
        let input = BuildRequestInput {
            method: "POST",
            path: "no_leading_slash",
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        };

        let err = build_request_proof(&input).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    #[test]
    fn test_build_verify_roundtrip() {
        // Build a proof, then verify it matches what verify_incoming_request expects
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_roundtrip";
        let canonical_body = r#"{"amount":100}"#;
        let timestamp = "1700000000";

        let build_result = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/transfer",
            raw_query: "sort=name",
            canonical_body,
            nonce,
            context_id,
            timestamp,
            scope: None,
            previous_proof: None,
        })
        .unwrap();

        // Re-derive and verify manually using low-level primitives
        let client_secret =
            ash_derive_client_secret(nonce, context_id, &build_result.binding).unwrap();
        let expected_proof =
            ash_build_proof(&client_secret, timestamp, &build_result.binding, &build_result.body_hash)
                .unwrap();

        assert_eq!(build_result.proof, expected_proof);
    }

    #[test]
    fn test_build_scoped_proof() {
        let input = BuildRequestInput {
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":100,"recipient":"alice"}"#,
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_scoped",
            timestamp: "1700000000",
            scope: Some(&["amount", "recipient"]),
            previous_proof: None,
        };

        let result = build_request_proof(&input).unwrap();
        assert_eq!(result.proof.len(), 64);
        assert!(!result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_build_chained_proof() {
        // First build a basic proof
        let first = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/step1",
            raw_query: "",
            canonical_body: r#"{"step":1}"#,
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_chain",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        })
        .unwrap();

        // Then build a chained proof
        let second = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/step2",
            raw_query: "",
            canonical_body: r#"{"step":2}"#,
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_chain",
            timestamp: "1700000001",
            scope: None,
            previous_proof: Some(&first.proof),
        })
        .unwrap();

        assert_eq!(second.proof.len(), 64);
        assert!(!second.chain_hash.is_empty());
        // Chain hash should be SHA-256 of previous proof
        assert_eq!(second.chain_hash.len(), 64);
    }

    // ── Precedence tests ──────────────────────────────────────────────

    #[test]
    fn precedence_bad_nonce_before_bad_timestamp() {
        let input = BuildRequestInput {
            method: "POST",
            path: "/api/test",
            raw_query: "",
            canonical_body: "{}",
            nonce: "short",           // bad nonce
            context_id: "ctx_test",
            timestamp: "not_a_number", // bad timestamp
            scope: None,
            previous_proof: None,
        };

        let err = build_request_proof(&input).unwrap_err();
        // Nonce validation happens before timestamp (step 1 vs step 2)
        assert_eq!(err.reason(), InternalReason::NonceTooShort);
    }

    #[test]
    fn precedence_bad_timestamp_before_bad_path() {
        let input = BuildRequestInput {
            method: "POST",
            path: "no_slash",           // bad path
            raw_query: "",
            canonical_body: "{}",
            nonce: "0123456789abcdef0123456789abcdef",
            context_id: "ctx_test",
            timestamp: "not_a_number",  // bad timestamp
            scope: None,
            previous_proof: None,
        };

        let err = build_request_proof(&input).unwrap_err();
        // Timestamp validation happens before binding (step 2 vs step 3)
        assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
    }
}
