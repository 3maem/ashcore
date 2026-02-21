//! Comprehensive Security Test Suite for ASH Core
//!
//! This test suite covers:
//! - Penetration Testing (PT): Active vulnerability discovery
//! - API Quality (AQ): Boundary conditions, input validation
//! - Security Audit: Cryptographic correctness, protocol compliance
//! - Fuzz Testing: Edge cases and random inputs

use ashcore::*;
use serde_json::json;

// ============================================================================
// PENetration Testing (PT) - Attack Simulation
// ============================================================================

mod penetration_tests {
    use super::*;

    /// PT-001: Replay Attack - Using same proof twice
    #[test]
    fn pt_replay_attack_same_proof() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api/transfer|";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);
        let timestamp = "1704067200";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof1 = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();
        let proof2 = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();

        // Same inputs should produce same proof (deterministic)
        assert_eq!(proof1, proof2);
        
        // Both should verify
        assert!(ash_verify_proof(nonce, context_id, binding, timestamp, &body_hash, &proof1).unwrap());
        assert!(ash_verify_proof(nonce, context_id, binding, timestamp, &body_hash, &proof2).unwrap());
    }

    /// PT-002: Timestamp Manipulation - Future timestamp
    #[test]
    fn pt_timestamp_manipulation_future() {
        let future_ts = "9999999999"; // Year 2286
        let result = ash_validate_timestamp(future_ts, 300, 30);
        assert!(result.is_err());
    }

    /// PT-003: Timestamp Manipulation - Past timestamp
    #[test]
    fn pt_timestamp_manipulation_past() {
        let past_ts = "1000000"; // Very old timestamp
        let result = ash_validate_timestamp(past_ts, 300, 30);
        assert!(result.is_err());
    }

    /// PT-004: Binding Manipulation - Wrong endpoint
    #[test]
    fn pt_binding_manipulation_wrong_endpoint() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api/transfer|";
        let wrong_binding = "POST|/api/admin|";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);
        let timestamp = "1704067200";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();

        // Proof built for /api/transfer should NOT verify against /api/admin
        let is_valid = ash_verify_proof(nonce, context_id, wrong_binding, timestamp, &body_hash, &proof).unwrap();
        assert!(!is_valid);
    }

    /// PT-005: Body Hash Manipulation - Modified payload
    #[test]
    fn pt_body_hash_manipulation() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api/transfer|";
        let original_body = r#"{"amount":100}"#;
        let modified_body = r#"{"amount":999999}"#;
        let body_hash = ash_hash_body(original_body);
        let modified_hash = ash_hash_body(modified_body);
        let timestamp = "1704067200";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();

        // Proof should NOT verify against modified body hash
        let is_valid = ash_verify_proof(nonce, context_id, binding, timestamp, &modified_hash, &proof).unwrap();
        assert!(!is_valid);
    }

    /// PT-006: Nonce Reuse - Same nonce, different context
    #[test]
    fn pt_nonce_reuse_different_context() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id1 = "ctx_user1";
        let context_id2 = "ctx_user2";
        let binding = "POST|/api/transfer|";

        let secret1 = ash_derive_client_secret(nonce, context_id1, binding).unwrap();
        let secret2 = ash_derive_client_secret(nonce, context_id2, binding).unwrap();

        // Same nonce with different context_id should produce DIFFERENT secrets
        assert_ne!(secret1, secret2);
    }

    /// PT-007: Length Extension Attack Attempt
    #[test]
    fn pt_length_extension_attempt() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api/transfer|";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);
        let timestamp = "1704067200";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();

        // Attempt to extend the proof (should fail verification)
        let extended_proof = format!("{}EXTRA", proof);
        let is_valid = ash_verify_proof(nonce, context_id, binding, timestamp, &body_hash, &extended_proof).unwrap();
        assert!(!is_valid);
    }

    /// PT-008: Context ID Injection - Pipe character injection
    #[test]
    fn pt_context_id_injection_pipe() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let malicious_context = "ctx|admin"; // Injection attempt
        let binding = "POST|/api/transfer|";

        let result = ash_derive_client_secret(nonce, malicious_context, binding);
        assert!(result.is_err()); // Should reject pipe in context_id
    }

    /// PT-009: Null Byte Injection
    #[test]
    fn pt_null_byte_injection() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test\x00admin"; // Null byte injection
        let binding = "POST|/api/transfer|";

        let result = ash_derive_client_secret(nonce, context_id, binding);
        assert!(result.is_err()); // Should reject null bytes
    }

    /// PT-010: Unicode Normalization Attack
    #[test]
    fn pt_unicode_normalization_attack() {
        // café in different Unicode forms
        let nfc = "café"; // NFC form
        let nfd = "cafe\u{0301}"; // NFD form (decomposed)

        let hash_nfc = ash_hash_body(&format!("{{\"name\":\"{}\"}}", nfc));
        let hash_nfd = ash_hash_body(&format!("{{\"name\":\"{}\"}}", nfd));

        // After canonicalization, both should produce same hash
        let canonical_nfc = ash_canonicalize_json(&format!("{{\"name\":\"{}\"}}", nfc)).unwrap();
        let canonical_nfd = ash_canonicalize_json(&format!("{{\"name\":\"{}\"}}", nfd)).unwrap();

        let hash_canonical_nfc = ash_hash_body(&canonical_nfc);
        let hash_canonical_nfd = ash_hash_body(&canonical_nfd);

        // Canonicalization should normalize Unicode
        assert_eq!(canonical_nfc, canonical_nfd);
        assert_eq!(hash_canonical_nfc, hash_canonical_nfd);
    }

    /// PT-011: Timing Attack - Statistical timing analysis
    #[test]
    fn pt_timing_attack_constant_time() {
        // This test verifies that timing_safe_equal runs in constant time
        // by checking it doesn't short-circuit on first difference
        let proof1 = "a".repeat(64);
        let proof2 = "b".repeat(64);
        let proof3 = format!("{}{}", "a".repeat(63), "b");

        // All should return false without timing differences
        let start1 = std::time::Instant::now();
        let _ = ash_timing_safe_equal(proof1.as_bytes(), proof2.as_bytes());
        let duration1 = start1.elapsed();

        let start2 = std::time::Instant::now();
        let _ = ash_timing_safe_equal(proof1.as_bytes(), proof3.as_bytes());
        let duration2 = start2.elapsed();

        // Both comparisons should take similar time (within 10x factor)
        let ratio = if duration1 > duration2 {
            duration1.as_nanos() as f64 / duration2.as_nanos() as f64
        } else {
            duration2.as_nanos() as f64 / duration1.as_nanos() as f64
        };

        assert!(ratio < 10.0, "Timing difference too large: {}x", ratio);
    }

    /// PT-012: Proof Forgery - Random proof attempt
    #[test]
    fn pt_proof_forgery_random() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api/transfer|";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);
        let timestamp = "1704067200";

        // Generate random fake proof
        let fake_proof = "deadbeef".repeat(8);

        let is_valid = ash_verify_proof(nonce, context_id, binding, timestamp, &body_hash, &fake_proof).unwrap();
        assert!(!is_valid);
    }

    /// PT-013: DoS via Recursive JSON
    #[test]
    fn pt_dos_recursive_json() {
        // Create deeply nested JSON (65 levels, max is 64)
        let mut nested = "null".to_string();
        for _ in 0..65 {
            nested = format!("{{\"a\":{}}}", nested);
        }

        let result = ash_canonicalize_json(&nested);
        assert!(result.is_err()); // Should reject deep nesting
    }

    /// PT-014: DoS via Large Payload
    #[test]
    fn pt_dos_large_payload() {
        // Create payload larger than 10MB
        let large_payload = format!("{{\"data\":\"{}\"}}", "a".repeat(11 * 1024 * 1024));

        let result = ash_canonicalize_json(&large_payload);
        assert!(result.is_err()); // Should reject oversized payload
    }

    /// PT-015: Header Injection via Context ID
    #[test]
    fn pt_header_injection_context_id() {
        let nonce = "0123456789abcdef0123456789abcdef";
        // Attempt header injection
        let malicious_context = "ctx\r\nX-Custom-Header: evil";
        let binding = "POST|/api/transfer|";

        let result = ash_derive_client_secret(nonce, malicious_context, binding);
        assert!(result.is_err()); // Should reject CRLF
    }
}

// ============================================================================
// API Quality (AQ) Tests - Boundary Conditions
// ============================================================================

mod api_quality_tests {
    use super::*;

    /// AQ-001: Empty String Handling
    #[test]
    fn aq_empty_string_handling() {
        // Empty JSON object should work
        let result = ash_canonicalize_json("{}");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "{}");

        // Empty string in JSON
        let result = ash_canonicalize_json(r#"{"key":""}"#);
        assert!(result.is_ok());
    }

    /// AQ-002: Whitespace Handling
    #[test]
    fn aq_whitespace_handling() {
        // Various whitespace forms
        let inputs = vec![
            r#"{"a":1}"#,
            r#"{ "a" : 1 }"#,
            "{\"a\":\t1}",
            "{\"a\":\n1}",
            r#"{  "a"  :  1  }"#,
        ];

        let expected = r#"{"a":1}"#;
        for input in inputs {
            let result = ash_canonicalize_json(input).unwrap();
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }

    /// AQ-003: Boundary - Minimum Nonce Length
    #[test]
    fn aq_nonce_minimum_length() {
        // 31 hex chars (below minimum of 32)
        let short_nonce = "a".repeat(31);
        let result = ash_derive_client_secret(&short_nonce, "ctx_test", "POST|/api|");
        assert!(result.is_err());

        // Exactly 32 hex chars (minimum)
        let min_nonce = "a".repeat(32);
        let result = ash_derive_client_secret(&min_nonce, "ctx_test", "POST|/api|");
        assert!(result.is_ok());
    }

    /// AQ-004: Boundary - Maximum Nonce Length
    #[test]
    fn aq_nonce_maximum_length() {
        // 513 hex chars (above maximum of 512)
        let long_nonce = "a".repeat(513);
        let result = ash_derive_client_secret(&long_nonce, "ctx_test", "POST|/api|");
        assert!(result.is_err());

        // Exactly 512 hex chars (maximum)
        let max_nonce = "a".repeat(512);
        let result = ash_derive_client_secret(&max_nonce, "ctx_test", "POST|/api|");
        assert!(result.is_ok());
    }

    /// AQ-005: Boundary - Context ID Length
    #[test]
    fn aq_context_id_length() {
        // Empty context ID
        let result = ash_derive_client_secret("0123456789abcdef0123456789abcdef", "", "POST|/api|");
        assert!(result.is_err());

        // Maximum length (256)
        let max_context = "a".repeat(256);
        let result = ash_derive_client_secret("0123456789abcdef0123456789abcdef", &max_context, "POST|/api|");
        assert!(result.is_ok());

        // Over maximum
        let over_context = "a".repeat(257);
        let result = ash_derive_client_secret("0123456789abcdef0123456789abcdef", &over_context, "POST|/api|");
        assert!(result.is_err());
    }

    /// AQ-006: Boundary - Binding Length
    #[test]
    fn aq_binding_length() {
        // Empty binding
        let result = ash_derive_client_secret("0123456789abcdef0123456789abcdef", "ctx_test", "");
        assert!(result.is_err());

        // Maximum binding length (8192)
        let long_path = format!("/api/{}", "a".repeat(8180));
        let result = ash_normalize_binding("GET", &long_path, "");
        // Should succeed or fail based on total binding length
        if result.is_ok() {
            assert!(result.unwrap().len() <= 8192);
        }
    }

    /// AQ-007: Numeric Edge Cases
    #[test]
    fn aq_numeric_edge_cases() {
        // Zero
        let result = ash_canonicalize_json(r#"{"a":0}"#).unwrap();
        assert_eq!(result, r#"{"a":0}"#);

        // Negative zero (should become 0)
        let result = ash_canonicalize_json(r#"{"a":-0.0}"#).unwrap();
        assert_eq!(result, r#"{"a":0}"#);

        // Large number
        let result = ash_canonicalize_json(r#"{"a":9007199254740991}"#).unwrap();
        assert_eq!(result, r#"{"a":9007199254740991}"#);

        // Float
        let result = ash_canonicalize_json(r#"{"a":3.14159}"#).unwrap();
        assert_eq!(result, r#"{"a":3.14159}"#);

        // Whole float (should become int)
        let result = ash_canonicalize_json(r#"{"a":5.0}"#).unwrap();
        assert_eq!(result, r#"{"a":5}"#);
    }

    /// AQ-008: Special Characters in Strings
    #[test]
    fn aq_special_characters() {
        let test_cases = vec![
            (r#"{"a":"\\"}"#, r#"{"a":"\\"}"#),      // Backslash
            (r#"{"a":"\""}"#, r#"{"a":"\""}"#),      // Quote
            (r#"{"a":"\n"}"#, r#"{"a":"\n"}"#),      // Newline
            (r#"{"a":"\t"}"#, r#"{"a":"\t"}"#),      // Tab
            (r#"{"a":"\u0000"}"#, r#"{"a":"\u0000"}"#), // Null
        ];

        for (input, expected) in test_cases {
            let result = ash_canonicalize_json(input).unwrap();
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }

    /// AQ-009: Unicode Edge Cases
    #[test]
    fn aq_unicode_edge_cases() {
        // BMP characters
        let result = ash_canonicalize_json(r#"{"a":"日本語"}"#).unwrap();
        assert!(result.contains("日本語"));

        // Surrogate pairs (emoji)
        let result = ash_canonicalize_json(r#"{"a":"🎉"}"#).unwrap();
        assert!(result.contains("🎉"));

        // Zero-width joiner (family emoji)
        let result = ash_canonicalize_json(r#"{"a":"👨‍👩‍👧‍👦"}"#).unwrap();
        assert!(result.contains("👨‍👩‍👧‍👦"));
    }

    /// AQ-010: Array Handling
    #[test]
    fn aq_array_handling() {
        // Empty array
        let result = ash_canonicalize_json(r#"{"a":[]}"#).unwrap();
        assert_eq!(result, r#"{"a":[]}"#);

        // Nested arrays
        let result = ash_canonicalize_json(r#"{"a":[[1,2],[3,4]]}"#).unwrap();
        assert_eq!(result, r#"{"a":[[1,2],[3,4]]}"#);

        // Array with objects
        let result = ash_canonicalize_json(r#"{"a":[{"b":2},{"c":3}]}"#).unwrap();
        assert_eq!(result, r#"{"a":[{"b":2},{"c":3}]}"#);
    }

    /// AQ-011: Key Ordering
    #[test]
    fn aq_key_ordering() {
        // Keys should be sorted lexicographically
        let result = ash_canonicalize_json(r#"{"z":1,"a":2,"m":3}"#).unwrap();
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);

        // Nested objects
        let result = ash_canonicalize_json(r#"{"z":{"b":2,"a":1},"a":3}"#).unwrap();
        assert_eq!(result, r#"{"a":3,"z":{"a":1,"b":2}}"#);
    }

    /// AQ-012: Query String Edge Cases
    #[test]
    fn aq_query_string_edge_cases() {
        // Empty query
        let result = ash_canonicalize_query("").unwrap();
        assert_eq!(result, "");

        // Single parameter
        let result = ash_canonicalize_query("a=1").unwrap();
        assert_eq!(result, "a=1");

        // Duplicate keys
        let result = ash_canonicalize_query("a=2&a=1").unwrap();
        assert_eq!(result, "a=1&a=2"); // Sorted by value

        // Special characters
        let result = ash_canonicalize_query("a=hello%20world").unwrap();
        assert_eq!(result, "a=hello%20world");

        // Plus as literal
        let result = ash_canonicalize_query("a=b+c").unwrap();
        assert_eq!(result, "a=b%2Bc"); // + encoded as %2B
    }
}

// ============================================================================
// Security Audit Tests
// ============================================================================

mod security_audit_tests {
    use super::*;

    /// SA-001: HMAC Key Derivation Correctness
    #[test]
    fn sa_hmac_key_derivation() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api|";

        let secret1 = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let secret2 = ash_derive_client_secret(nonce, context_id, binding).unwrap();

        // Deterministic
        assert_eq!(secret1, secret2);

        // Different inputs produce different outputs
        let secret3 = ash_derive_client_secret(nonce, "ctx_other", binding).unwrap();
        assert_ne!(secret1, secret3);

        // Hex case shouldn't matter
        let nonce_upper = nonce.to_ascii_uppercase();
        let secret_upper = ash_derive_client_secret(&nonce_upper, context_id, binding).unwrap();
        assert_eq!(secret1, secret_upper);
    }

    /// SA-002: Proof Uniqueness
    #[test]
    fn sa_proof_uniqueness() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let body_hash = ash_hash_body(r#"{"a":1}"#);

        // Different timestamps should produce different proofs
        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let proof1 = ash_build_proof(&client_secret, "1000000000", binding, &body_hash).unwrap();
        let proof2 = ash_build_proof(&client_secret, "1000000001", binding, &body_hash).unwrap();

        assert_ne!(proof1, proof2);
    }

    /// SA-003: Hash Consistency
    #[test]
    fn sa_hash_consistency() {
        let input = r#"{"a":1}"#;
        let hash1 = ash_hash_body(input);
        let hash2 = ash_hash_body(input);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex length
    }

    /// SA-004: Memory Safety - Zeroization Check
    #[test]
    fn sa_memory_safety_zeroization() {
        // Note: This is a conceptual test - actual memory inspection would require more setup
        // The Zeroizing wrapper is used in the code
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api|";

        // Secret derivation uses Zeroizing
        let secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        assert_eq!(secret.len(), 64, "Secret should be 64 hex chars");

        // Proof building uses Zeroizing for message
        let body_hash = ash_hash_body(r#"{"a":1}"#);
        let proof = ash_build_proof(&secret, "1000000000", binding, &body_hash).unwrap();
        assert_eq!(proof.len(), 64, "Proof should be 64 hex chars");
    }

    /// SA-005: Error Message Safety
    #[test]
    fn sa_error_message_safety() {
        // Errors should not leak sensitive information
        let result = ash_canonicalize_json("not valid json");
        let err = result.unwrap_err();
        let msg = err.message();

        // Should not contain the invalid input
        assert!(!msg.contains("not valid json"));
        assert!(!msg.contains("{"));
    }

    /// SA-006: All Error Codes Have Unique HTTP Status
    #[test]
    fn sa_unique_http_status_codes() {
        use std::collections::HashSet;
        use ashcore::AshErrorCode;

        let codes = vec![
            AshErrorCode::CtxNotFound,
            AshErrorCode::CtxExpired,
            AshErrorCode::CtxAlreadyUsed,
            AshErrorCode::ProofInvalid,
            AshErrorCode::BindingMismatch,
            AshErrorCode::ScopeMismatch,
            AshErrorCode::ChainBroken,
            AshErrorCode::ScopedFieldMissing,
            AshErrorCode::TimestampInvalid,
            AshErrorCode::ProofMissing,
            AshErrorCode::CanonicalizationError,
            AshErrorCode::ValidationError,
            AshErrorCode::ModeViolation,
            AshErrorCode::UnsupportedContentType,
            AshErrorCode::InternalError,
        ];

        let mut statuses = HashSet::new();
        for code in codes {
            let status = code.http_status();
            assert!(
                statuses.insert(status),
                "Duplicate HTTP status code: {} for {:?}",
                status, code
            );
        }
    }

    /// SA-007: Protocol Version Constants
    #[test]
    fn sa_protocol_version() {
        assert_eq!(ASH_SDK_VERSION, "1.0.0");
    }

    /// SA-008: Timestamp Validation Strictness
    #[test]
    fn sa_timestamp_validation_strict() {
        // Leading zeros should be rejected (except for "0" itself)
        let result = ash_validate_timestamp_format("0123456789");
        assert!(result.is_err());

        // "0" should be valid
        let result = ash_validate_timestamp_format("0");
        assert!(result.is_ok());

        // Non-digits should be rejected
        let result = ash_validate_timestamp_format("123abc");
        assert!(result.is_err());

        // Empty should be rejected
        let result = ash_validate_timestamp_format("");
        assert!(result.is_err());
    }

    /// SA-009: Binding Normalization Security
    #[test]
    fn sa_binding_normalization_security() {
        // Path must start with /
        let result = ash_normalize_binding("GET", "api/users", "");
        assert!(result.is_err());

        // Path with encoded query delimiter should be rejected
        let result = ash_normalize_binding("GET", "/api/users%3Fid=1", "");
        assert!(result.is_err());

        // Path traversal attempt
        let result = ash_normalize_binding("GET", "/api/../../../etc/passwd", "");
        // Should normalize to /etc/passwd or reject
        if let Ok(binding) = result {
            assert!(!binding.contains(".."));
        }
    }

    /// SA-010: Scope Hash Collision Resistance
    #[test]
    fn sa_scope_collision_resistance() {
        // Different scopes should produce different hashes
        let hash1 = ash_hash_scope(&["a", "b"]).unwrap();
        let hash2 = ash_hash_scope(&["ab"]).unwrap();

        assert_ne!(hash1, hash2);

        // Order shouldn't matter (normalized)
        let hash3 = ash_hash_scope(&["b", "a"]).unwrap();
        assert_eq!(hash1, hash3);
    }
}

// ============================================================================
// Fuzz Testing - Random and Edge Case Inputs
// ============================================================================

mod fuzz_tests {
    use super::*;
    use rand::{Rng, distributions::Alphanumeric};

    fn random_string(len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    fn random_hex(len: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        (0..len)
            .map(|_| HEX[rand::thread_rng().gen_range(0..16)] as char)
            .collect()
    }

    /// FUZZ-001: Random Nonce Handling
    #[test]
    fn fuzz_random_nonces() {
        for _ in 0..100 {
            // Random length between 0 and 600
            let len = rand::thread_rng().gen_range(0..600);
            let nonce = random_hex(len);
            let result = ash_derive_client_secret(&nonce, "ctx_test", "POST|/api|");

            if len >= 32 && len <= 512 {
                assert!(result.is_ok(), "Valid nonce {} rejected", len);
            } else {
                assert!(result.is_err(), "Invalid nonce {} accepted", len);
            }
        }
    }

    /// FUZZ-002: Random Context IDs
    #[test]
    fn fuzz_random_context_ids() {
        let nonce = "0123456789abcdef0123456789abcdef";

        for _ in 0..100 {
            let len = rand::thread_rng().gen_range(0..300);
            let context: String = random_string(len)
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' { c } else { '_' })
                .collect();

            let result = ash_derive_client_secret(nonce, &context, "POST|/api|");

            if len > 0 && len <= 256 {
                assert!(result.is_ok(), "Valid context {} rejected", len);
            } else if len == 0 || len > 256 {
                assert!(result.is_err(), "Invalid context {} accepted", len);
            }
        }
    }

    /// FUZZ-003: Random JSON Payloads
    #[test]
    fn fuzz_random_json_payloads() {
        let payloads = vec![
            r#"{}"#,
            r#"[]"#,
            r#"null"#,
            r#"true"#,
            r#"false"#,
            r#"0"#,
            r#""#,
            r#"{"":null}"#,
            r#"{"a":{"b":{"c":1}}}"#,
            r#"[1,2,3,4,5]"#,
            r#"{"key with spaces":1}"#,
            r#"{"special!@#$%":1}"#,
        ];

        for payload in payloads {
            let result = ash_canonicalize_json(payload);
            // Should either succeed or fail gracefully
            match result {
                Ok(_) => {}, // Valid JSON
                Err(_) => {}, // Invalid JSON, but no panic
            }
        }
    }

    /// FUZZ-004: Random Query Strings
    #[test]
    fn fuzz_random_query_strings() {
        let queries = vec![
            "",
            "a=1",
            "a=1&b=2&c=3",
            "a=1&a=2&a=3",
            "key=value%20with%20spaces",
            "special=%2B%2F%3D",
            "?=??&==",
            "a",
            "a=",
            "=b",
        ];

        for query in queries {
            let result = ash_canonicalize_query(query);
            // Should not panic
            let _ = result;
        }
    }

    /// FUZZ-005: Random Bindings
    #[test]
    fn fuzz_random_bindings() {
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        let long_path = "/very/long/path/".repeat(10);
        let paths = vec![
            "/",
            "/api",
            "/api/users",
            "/api/users/123",
            "/api/users/123/posts",
            &long_path,
        ];

        for method in &methods {
            for path in &paths {
                let result = ash_normalize_binding(method, path, "");
                // Should not panic
                let _ = result;
            }
        }
    }

    /// FUZZ-006: Special Unicode Characters
    #[test]
    fn fuzz_unicode_characters() {
        let test_chars = vec![
            'A',              // ASCII
            'é',              // Latin-1
            '€',              // Euro sign
            '中',             // CJK
            '𐍈',             // Gothic (outside BMP)
            '🎉',             // Emoji
            '\u{0301}',       // Combining acute accent
            '\u{200B}',       // Zero-width space
            '\u{FEFF}',       // BOM
        ];

        for ch in test_chars {
            let json = format!("{{\"char\":\"{}\"}}", ch);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed for char: U+{:04X}", ch as u32);
        }
    }

    /// FUZZ-007: Edge Case Numbers
    #[test]
    fn fuzz_edge_case_numbers() {
        let numbers = vec![
            "0",
            "-0",
            "0.0",
            "-0.0",
            "1e10",
            "1e-10",
            "1E10",
            "0.0000001",
            "9999999999999999",
            "-9999999999999999",
        ];

        for num in numbers {
            let json = format!("{{\"num\":{}}}", num);
            let result = ash_canonicalize_json(&json);
            // Should handle without panic
            let _ = result;
        }
    }

    /// FUZZ-008: Concurrent Access Simulation
    #[test]
    fn fuzz_concurrent_proof_generation() {
        use std::sync::Arc;
        use std::thread;

        let nonce = Arc::new("0123456789abcdef0123456789abcdef".to_string());
        let mut handles = vec![];

        for i in 0..10 {
            let nonce = Arc::clone(&nonce);
            let handle = thread::spawn(move || {
                let context_id = format!("ctx_{}", i);
                let binding = "POST|/api|";
                let body_hash = ash_hash_body(&format!("{{\"id\":{}}}", i));
                let timestamp = format!("{}", 1704067200 + i);

                let client_secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
                ash_build_proof(&client_secret, &timestamp, binding, &body_hash).unwrap()
            });
            handles.push(handle);
        }

        for handle in handles {
            let proof = handle.join().unwrap();
            assert_eq!(proof.len(), 64); // SHA-256 hex length
        }
    }

    /// FUZZ-009: Pathological JSON Structures
    #[test]
    fn fuzz_pathological_json() {
        // Many keys
        let mut many_keys = "{".to_string();
        for i in 0..100 {
            if i > 0 { many_keys.push(','); }
            many_keys.push_str(&format!("\"key{}\":{}", i, i));
        }
        many_keys.push('}');

        let result = ash_canonicalize_json(&many_keys);
        assert!(result.is_ok());

        // Deep nesting (just under limit - 63 levels)
        let mut deep = "null".to_string();
        for _ in 0..63 {
            deep = format!("{{\"a\":{}}}", deep);
        }
        let result = ash_canonicalize_json(&deep);
        assert!(result.is_ok());
    }

    /// FUZZ-010: Malformed Input Resilience
    #[test]
    fn fuzz_malformed_input() {
        let malformed = vec![
            "{",
            "}",
            "[",
            "]",
            "\"",
            "\"\"\"",
            "{}",
            "[]",
            r#"{"a":}"#,
            r#"{"a":1]"#,
            "[1,2,}",
            "not json at all",
            "<xml>not json</xml>",
        ];

        for input in malformed {
            // Must handle gracefully without panicking — the call itself is the test
            let _ = ash_canonicalize_json(input);
        }
    }
}

// ============================================================================
// Integration Tests - Cross-Module Scenarios
// ============================================================================

mod integration_tests {
    use super::*;

    /// INT-001: Full Request Flow
    #[test]
    fn int_full_request_flow() {
        // Server generates nonce and context
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = "ctx_transaction_123";
        let binding = "POST|/api/transfer|";

        // Client canonicalizes payload
        let payload = r#"{"from":"alice","to":"bob","amount":100.00}"#;
        let canonical = ash_canonicalize_json(payload).unwrap();

        // Client derives secret and builds proof
        let client_secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let body_hash = ash_hash_body(&canonical);
        let timestamp = "1704067200";
        let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();

        // Server verifies
        let is_valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(is_valid);

        // Tampered payload should fail
        let tampered = r#"{"from":"alice","to":"bob","amount":999999.00}"#;
        let tampered_canonical = ash_canonicalize_json(tampered).unwrap();
        let tampered_hash = ash_hash_body(&tampered_canonical);
        let is_valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &tampered_hash, &proof).unwrap();
        assert!(!is_valid);
    }

    /// INT-002: Scoped Proof Flow
    #[test]
    fn int_scoped_proof_flow() {
        let nonce = "0123456789abcdef0123456789abcdef";
        let context_id = "ctx_test";
        let binding = "POST|/api/update|";
        let scope = vec!["amount", "recipient"];

        // Full JSON payload as string (the function will extract scoped fields internally)
        let payload_str = r#"{"amount":100,"recipient":"alice","timestamp":"2024-01-01T00:00:00Z","metadata":{"key":"value"}}"#;

        // Build scoped proof - takes the JSON payload string directly
        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
        let timestamp = "1704067200";
        let (proof, scope_hash) = ash_build_proof_scoped(&client_secret, timestamp, binding, payload_str, &scope).unwrap();

        // Verify - pass the original payload string
        let is_valid = ash_verify_proof_scoped(
            nonce, context_id, binding, timestamp, payload_str, &scope, &scope_hash, &proof
        ).unwrap();
        assert!(is_valid);
    }

    /// INT-003: Error Handling Chain
    #[test]
    fn int_error_handling_chain() {
        // Each step should propagate errors correctly
        let invalid_nonce = "short";
        let result = ash_derive_client_secret(invalid_nonce, "ctx", "POST|/api|");
        assert!(result.is_err());

        let invalid_json = "{invalid";
        let result = ash_canonicalize_json(invalid_json);
        assert!(result.is_err());

        // Errors should have proper codes
        let err = result.unwrap_err();
        assert_eq!(err.code(), ashcore::AshErrorCode::CanonicalizationError);
    }

    /// INT-004: Roundtrip Consistency
    #[test]
    fn int_roundtrip_consistency() {
        // Multiple canonicalizations should produce identical output
        let json = r#"{"z":1,"a":{"c":3,"b":2},"arr":[3,1,2]}"#;
        
        let c1 = ash_canonicalize_json(json).unwrap();
        let c2 = ash_canonicalize_json(&c1).unwrap();
        let c3 = ash_canonicalize_json(&c2).unwrap();

        assert_eq!(c1, c2);
        assert_eq!(c2, c3);

        // Hash should be consistent
        let h1 = ash_hash_body(&c1);
        let h2 = ash_hash_body(&c2);
        assert_eq!(h1, h2);
    }
}
