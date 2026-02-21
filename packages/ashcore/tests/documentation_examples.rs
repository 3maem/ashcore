//! Documentation Examples Tests for ASH Rust SDK
//!
//! Tests that all code examples in documentation actually work.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query, ash_canonicalize_urlencoded,
    ash_hash_body, ash_normalize_binding,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_build_proof_unified, ash_verify_proof_unified,
    ash_generate_nonce, ash_generate_context_id,
    ash_validate_timestamp, ash_timing_safe_equal,
};

// =========================================================================
// README QUICK START EXAMPLES
// =========================================================================

mod quick_start {
    use super::*;

    #[test]
    fn test_quick_start_example() {
        // Generate a cryptographic nonce
        let nonce = ash_generate_nonce(32).unwrap();
        assert_eq!(nonce.len(), 64);

        // Generate a context ID
        let context_id = ash_generate_context_id().unwrap();
        assert!(context_id.starts_with("ash_"));

        // Define the request binding
        let binding = ash_normalize_binding("POST", "/api/users", "").unwrap();
        assert_eq!(binding, "POST|/api/users|");

        // Derive the client secret
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
        assert_eq!(secret.len(), 64);

        // Hash the request body
        let body = r#"{"name":"John"}"#;
        let body_hash = ash_hash_body(body);
        assert_eq!(body_hash.len(), 64);

        // Build the proof
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64);

        // Verify the proof (server-side)
        let valid = ash_verify_proof(&nonce, &context_id, &binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }
}

// =========================================================================
// BASIC USAGE EXAMPLES
// =========================================================================

mod basic_usage {
    use super::*;

    #[test]
    fn test_json_canonicalization_example() {
        // Canonicalize JSON (RFC 8785 compliant)
        let json = r#"{"z":1,"a":2,"nested":{"b":3,"a":4}}"#;
        let canonical = ash_canonicalize_json(json).unwrap();

        // Keys are sorted alphabetically
        assert_eq!(canonical, r#"{"a":2,"nested":{"a":4,"b":3},"z":1}"#);
    }

    #[test]
    fn test_query_string_canonicalization_example() {
        // Canonicalize query string
        let query = "z=3&a=1&b=2";
        let canonical = ash_canonicalize_query(query).unwrap();

        // Parameters are sorted by key
        assert_eq!(canonical, "a=1&b=2&z=3");
    }

    #[test]
    fn test_binding_normalization_example() {
        // Normalize request binding
        let binding = ash_normalize_binding("post", "/api/users/", "page=1&limit=10").unwrap();

        // Method is uppercased, trailing slash removed, query sorted
        assert!(binding.starts_with("POST|"));
        assert!(binding.contains("/api/users|"));
    }

    #[test]
    fn test_body_hashing_example() {
        // Hash request body
        let body = r#"{"user":"john","action":"login"}"#;
        let hash = ash_hash_body(body);

        // SHA-256 hash, 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// =========================================================================
// PROOF LIFECYCLE EXAMPLE
// =========================================================================

mod proof_lifecycle {
    use super::*;

    #[test]
    fn test_full_proof_lifecycle_example() {
        // === CLIENT SIDE ===

        // 1. Generate nonce (should be done by server and sent to client)
        let nonce = ash_generate_nonce(32).unwrap();

        // 2. Generate context ID (unique per request context)
        let context_id = ash_generate_context_id().unwrap();

        // 3. Define the request
        let method = "POST";
        let path = "/api/transfer";
        let query = "confirm=true";
        let body = r#"{"from":"acc1","to":"acc2","amount":100}"#;

        // 4. Create binding
        let binding = ash_normalize_binding(method, path, query).unwrap();

        // 5. Derive client secret
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        // 6. Hash body
        let body_hash = ash_hash_body(body);

        // 7. Get current timestamp
        let timestamp = chrono::Utc::now().timestamp().to_string();

        // 8. Build proof
        let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        // === SERVER SIDE ===

        // 1. Receive request with proof, timestamp, context_id headers
        // 2. Look up nonce by context_id from store

        // 3. Validate timestamp freshness
        let ts_valid = ash_validate_timestamp(&timestamp, 300, 60);
        assert!(ts_valid.is_ok());

        // 4. Reconstruct binding from request
        let server_binding = ash_normalize_binding(method, path, query).unwrap();

        // 5. Hash received body
        let server_body_hash = ash_hash_body(body);

        // 6. Verify proof
        let valid = ash_verify_proof(&nonce, &context_id, &server_binding, &timestamp, &server_body_hash, &proof).unwrap();
        assert!(valid);

        // 7. Mark context as consumed (single-use)
        // store.consume(context_id)
    }
}

// =========================================================================
// SCOPED PROOFS EXAMPLE
// =========================================================================

mod scoped_proofs {
    use super::*;

    #[test]
    fn test_scoped_proof_example() {
        // Scoped proofs protect only specified fields
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/payment", "").unwrap();

        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        // Full payload
        let payload = r#"{"amount":100,"currency":"USD","memo":"Payment for order #123"}"#;

        // Only protect amount and currency (memo can change)
        let scope = vec!["amount", "currency"];

        let timestamp = chrono::Utc::now().timestamp().to_string();

        // Build scoped proof
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, &timestamp, &binding, payload, &scope).unwrap();

        // Verify with original payload
        let valid = ash_verify_proof_scoped(&nonce, &context_id, &binding, &timestamp, payload, &scope, &scope_hash, &proof).unwrap();
        assert!(valid);

        // Verify with modified memo (should still pass)
        let modified_payload = r#"{"amount":100,"currency":"USD","memo":"Updated memo"}"#;
        let valid_modified = ash_verify_proof_scoped(&nonce, &context_id, &binding, &timestamp, modified_payload, &scope, &scope_hash, &proof).unwrap();
        assert!(valid_modified, "Modified non-scoped field should verify");

        // Verify with modified amount (should fail)
        let tampered_payload = r#"{"amount":10000,"currency":"USD","memo":"Payment for order #123"}"#;
        let invalid = ash_verify_proof_scoped(&nonce, &context_id, &binding, &timestamp, tampered_payload, &scope, &scope_hash, &proof).unwrap();
        assert!(!invalid, "Modified scoped field should fail");
    }
}

// =========================================================================
// CHAINED PROOFS EXAMPLE
// =========================================================================

mod chained_proofs {
    use super::*;

    #[test]
    fn test_chained_proof_example() {
        // Chained proofs link multiple requests together
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let timestamp = chrono::Utc::now().timestamp().to_string();

        // Step 1: Initiate transfer
        let binding1 = ash_normalize_binding("POST", "/api/transfer/init", "").unwrap();
        let secret1 = ash_derive_client_secret(&nonce, &context_id, &binding1).unwrap();
        let payload1 = r#"{"from":"acc1","to":"acc2","amount":100}"#;

        let result1 = ash_build_proof_unified(&secret1, &timestamp, &binding1, payload1, &["amount"], None).unwrap();

        // Step 2: Confirm transfer (chained to step 1)
        let binding2 = ash_normalize_binding("POST", "/api/transfer/confirm", "").unwrap();
        let secret2 = ash_derive_client_secret(&nonce, &context_id, &binding2).unwrap();
        let payload2 = r#"{"confirmed":true}"#;

        // Chain to previous proof
        let result2 = ash_build_proof_unified(&secret2, &timestamp, &binding2, payload2, &[], Some(&result1.proof)).unwrap();

        // Verify step 2 includes chain to step 1
        assert!(!result2.chain_hash.is_empty());

        // Verify the chain
        let valid = ash_verify_proof_unified(
            &nonce, &context_id, &binding2, &timestamp, payload2,
            &result2.proof, &[], &result2.scope_hash,
            Some(&result1.proof), &result2.chain_hash
        ).unwrap();
        assert!(valid);
    }
}

// =========================================================================
// ERROR HANDLING EXAMPLE
// =========================================================================

mod error_handling {
    use super::*;

    #[test]
    fn test_error_handling_example() {
        // Invalid nonce (too short)
        let result = ash_derive_client_secret("short", "ctx", "GET|/|");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(!error.to_string().is_empty());

        // Invalid JSON
        let result = ash_canonicalize_json("not json");
        assert!(result.is_err());

        // Expired timestamp
        let old_ts = (chrono::Utc::now().timestamp() - 3600).to_string();
        let result = ash_validate_timestamp(&old_ts, 300, 60);
        assert!(result.is_err());
    }
}

// =========================================================================
// URL-ENCODED FORMS EXAMPLE
// =========================================================================

mod urlencoded_forms {
    use super::*;

    #[test]
    fn test_form_data_example() {
        // Handle URL-encoded form data
        let form_data = "username=john&password=secret123&remember=true";
        let canonical = ash_canonicalize_urlencoded(form_data).unwrap();

        // Parameters are sorted
        assert!(canonical.starts_with("password="));
        assert!(canonical.contains("&remember="));
        assert!(canonical.contains("&username="));
    }
}

// =========================================================================
// TIMING SAFE COMPARISON EXAMPLE
// =========================================================================

mod timing_safe {
    use super::*;

    #[test]
    fn test_timing_safe_comparison_example() {
        // Always use timing-safe comparison for secrets
        let secret1 = "a".repeat(64);
        let secret2 = "a".repeat(64);
        let secret3 = "b".repeat(64);

        // Same secrets
        assert!(ash_timing_safe_equal(secret1.as_bytes(), secret2.as_bytes()));

        // Different secrets
        assert!(!ash_timing_safe_equal(secret1.as_bytes(), secret3.as_bytes()));
    }
}

// =========================================================================
// COMPLETE API FLOW EXAMPLE
// =========================================================================

mod complete_flow {
    use super::*;

    #[test]
    fn test_complete_api_flow_example() {
        // This demonstrates a complete real-world flow

        // === SETUP (one-time) ===
        // Server generates and stores nonce, sends to client

        // === CLIENT REQUEST ===
        let nonce = "a".repeat(64);  // Would come from server
        let context_id = "ctx_user123_req456";

        // Request details
        let method = "POST";
        let path = "/api/orders";
        let query = "";
        let body = r#"{"product_id":"prod_abc","quantity":2,"price":29.99}"#;

        // Build binding
        let binding = ash_normalize_binding(method, path, query).unwrap();

        // Derive secret and build proof
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
        let body_hash = ash_hash_body(body);
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        // Client sends:
        // - Headers: X-ASH-Proof, X-ASH-Timestamp, X-ASH-Context-Id
        // - Body: the JSON payload

        // === SERVER VERIFICATION ===

        // 1. Validate timestamp
        let _ = ash_validate_timestamp(&timestamp, 300, 60).unwrap();

        // 2. Lookup nonce by context_id (from secure store)
        // let nonce = store.get_nonce(context_id);

        // 3. Reconstruct binding from request
        let server_binding = ash_normalize_binding(method, path, query).unwrap();

        // 4. Hash received body
        let server_body_hash = ash_hash_body(body);

        // 5. Verify proof
        let valid = ash_verify_proof(&nonce, &context_id, &server_binding, &timestamp, &server_body_hash, &proof).unwrap();

        assert!(valid, "Proof should be valid");

        // 6. Process request if valid
        // 7. Mark context as consumed
    }
}

// =========================================================================
// NESTED FIELD SCOPING EXAMPLE
// =========================================================================

mod nested_scoping {
    use super::*;

    #[test]
    fn test_nested_field_scoping_example() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/user", "").unwrap();
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        // Complex nested payload
        let payload = r#"{
            "user": {
                "name": "John",
                "email": "john@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            },
            "action": "update"
        }"#;

        // Scope nested fields using dot notation
        let scope = vec!["user.email", "action"];

        let (proof, scope_hash) = ash_build_proof_scoped(&secret, &timestamp, &binding, payload, &scope).unwrap();

        // Verify
        let valid = ash_verify_proof_scoped(&nonce, &context_id, &binding, &timestamp, payload, &scope, &scope_hash, &proof).unwrap();
        assert!(valid);
    }
}
