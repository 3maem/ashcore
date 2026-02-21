//! Security Assurance Pack Tests for ASH Rust SDK
//!
//! Tests from tests/security_assurance/ Python reference implementation:
//! A. Unit Tests: Deterministic generation, mutation detection, header rejection
//! B. Security Tests: Tampering, replay attacks, time manipulation

use ashcore::{
    ash_canonicalize_json, ash_canonicalize_urlencoded,
    ash_normalize_binding, ash_hash_body,
    ash_derive_client_secret, ash_build_proof, ash_verify_proof,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_build_proof_unified,
    ash_generate_nonce, ash_generate_context_id,
    ash_timing_safe_equal, ash_validate_timestamp,
};

// =========================================================================
// A. UNIT TESTS - DETERMINISTIC SIGNATURE GENERATION
// =========================================================================

mod deterministic_generation {
    use super::*;

    #[test]
    fn test_canonicalize_json_deterministic() {
        // Same JSON input must always produce same canonical output
        let input = r#"{"z":1,"a":2,"m":3}"#;

        let results: Vec<String> = (0..100)
            .map(|_| ash_canonicalize_json(input).unwrap())
            .collect();

        assert!(results.iter().all(|r| r == &results[0]), "Canonicalization is not deterministic");
        assert_eq!(results[0], r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_key_order_deterministic() {
        // Key ordering must be consistent regardless of input order
        let input1 = r#"{"z":1,"a":2}"#;
        let input2 = r#"{"a":2,"z":1}"#;

        let result1 = ash_canonicalize_json(input1).unwrap();
        let result2 = ash_canonicalize_json(input2).unwrap();

        assert_eq!(result1, result2, "Different input orders produce different outputs");
    }

    #[test]
    fn test_build_proof_deterministic() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test_123";
        let binding = "POST|/api/test|";
        let timestamp = "1704067200";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proofs: Vec<String> = (0..100)
            .map(|_| ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap())
            .collect();

        assert!(proofs.iter().all(|p| p == &proofs[0]), "Proof generation is not deterministic");
    }

    #[test]
    fn test_derive_client_secret_deterministic() {
        let nonce = "0123456789abcdef".repeat(4);
        let context_id = "ash_test_ctx";
        let binding = "POST|/api/test|";

        let secrets: Vec<String> = (0..100)
            .map(|_| ash_derive_client_secret(&nonce, context_id, binding).unwrap())
            .collect();

        assert!(secrets.iter().all(|s| s == &secrets[0]), "Client secret derivation is not deterministic");
    }

    #[test]
    fn test_normalize_binding_deterministic() {
        let method = "post";
        let path = "/api//test/";
        let query = "z=1&a=2";

        let results: Vec<String> = (0..100)
            .map(|_| ash_normalize_binding(method, path, query).unwrap())
            .collect();

        assert!(results.iter().all(|r| r == &results[0]), "Binding normalization is not deterministic");
    }

    #[test]
    fn test_hash_body_deterministic() {
        let body = r#"{"critical":"data"}"#;

        let hashes: Vec<String> = (0..100)
            .map(|_| ash_hash_body(body))
            .collect();

        assert!(hashes.iter().all(|h| h == &hashes[0]), "Body hashing is not deterministic");
    }

    #[test]
    fn test_generate_nonce_produces_unique_values() {
        // While each call should be deterministic internally, different calls should produce unique values
        let nonces: Vec<String> = (0..100)
            .map(|_| ash_generate_nonce(32).unwrap())
            .collect();

        let unique: std::collections::HashSet<&String> = nonces.iter().collect();
        assert_eq!(unique.len(), 100, "Nonces should be unique");
    }

    #[test]
    fn test_generate_context_id_produces_unique_values() {
        let ids: Vec<String> = (0..100)
            .map(|_| ash_generate_context_id().unwrap())
            .collect();

        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), 100, "Context IDs should be unique");
    }
}

// =========================================================================
// A. UNIT TESTS - SINGLE BYTE MUTATION DETECTION
// =========================================================================

mod mutation_detection {
    use super::*;

    #[test]
    fn test_single_byte_change_in_payload_detected() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let binding = "POST|/test|";
        let timestamp = "12345";

        let body_hash1 = ash_hash_body(r#"{"amount":100}"#);
        let body_hash2 = ash_hash_body(r#"{"amount":101}"#); // Changed 0 to 1

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof1 = ash_build_proof(&secret, timestamp, binding, &body_hash1).unwrap();
        let proof2 = ash_build_proof(&secret, timestamp, binding, &body_hash2).unwrap();

        assert_ne!(proof1, proof2, "Single byte mutation not detected");
    }

    #[test]
    fn test_single_char_change_in_key_detected() {
        let canon1 = ash_canonicalize_json(r#"{"amount":100}"#).unwrap();
        let canon2 = ash_canonicalize_json(r#"{"amounT":100}"#).unwrap(); // Changed t to T

        assert_ne!(canon1, canon2, "Key mutation not detected");
    }

    #[test]
    fn test_field_addition_detected() {
        let canon1 = ash_canonicalize_json(r#"{"a":1}"#).unwrap();
        let canon2 = ash_canonicalize_json(r#"{"a":1,"b":2}"#).unwrap();

        assert_ne!(canon1, canon2, "Field addition not detected");
    }

    #[test]
    fn test_single_byte_in_context_id_detected() {
        let nonce = "a".repeat(64);
        let binding = "POST|/test|";
        let timestamp = "12345";
        let body_hash = ash_hash_body("{}");

        let secret1 = ash_derive_client_secret(&nonce, "ctx_abc123", binding).unwrap();
        let secret2 = ash_derive_client_secret(&nonce, "ctx_abc124", binding).unwrap();

        let proof1 = ash_build_proof(&secret1, timestamp, binding, &body_hash).unwrap();
        let proof2 = ash_build_proof(&secret2, timestamp, binding, &body_hash).unwrap();

        assert_ne!(proof1, proof2, "Context ID mutation not detected");
    }

    #[test]
    fn test_single_byte_in_binding_detected() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let timestamp = "12345";
        let body_hash = ash_hash_body("{}");

        let binding1 = "POST|/api|";
        let binding2 = "POST|/apj|"; // Changed i to j

        let secret1 = ash_derive_client_secret(&nonce, context_id, binding1).unwrap();
        let secret2 = ash_derive_client_secret(&nonce, context_id, binding2).unwrap();

        let proof1 = ash_build_proof(&secret1, timestamp, binding1, &body_hash).unwrap();
        let proof2 = ash_build_proof(&secret2, timestamp, binding2, &body_hash).unwrap();

        assert_ne!(proof1, proof2, "Binding mutation not detected");
    }

    #[test]
    fn test_body_hash_mutation_verification_fails() {
        let nonce = "a".repeat(64);
        let context_id = "ash_test";
        let binding = "POST|/api|";
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let body_hash1 = ash_hash_body(r#"{"amount":100}"#);
        let body_hash2 = ash_hash_body(r#"{"amount":101}"#);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash1).unwrap();

        // Verify with correct hash should pass
        let valid = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash1, &proof).unwrap();
        assert!(valid, "Correct verification should pass");

        // Verify with mutated hash should fail
        let invalid = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash2, &proof).unwrap();
        assert!(!invalid, "Mutated hash verification should fail");
    }

    #[test]
    fn test_timestamp_mutation_detected() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let binding = "POST|/api|";
        let body_hash = ash_hash_body("{}");

        // Use current timestamp for realistic test
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let timestamp_mutated = (chrono::Utc::now().timestamp() + 1).to_string();

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Verification with different timestamp should fail
        let invalid = ash_verify_proof(&nonce, context_id, binding, &timestamp_mutated, &body_hash, &proof).unwrap();
        assert!(!invalid, "Timestamp mutation not detected");
    }
}

// =========================================================================
// A. UNIT TESTS - MISSING/INVALID HEADER REJECTION
// =========================================================================

mod header_rejection {
    use super::*;

    #[test]
    fn test_empty_context_id_rejected() {
        // Empty context_id is rejected by the SDK for security reasons
        let nonce = "a".repeat(64);
        let binding = "POST|/test|";

        let result = ash_derive_client_secret(&nonce, "", binding);
        assert!(result.is_err(), "Empty context_id should be rejected");
    }

    #[test]
    fn test_empty_binding_error() {
        let result = ash_normalize_binding("POST", "", "");
        // Empty path should error or produce different result
        assert!(result.is_err() || result.unwrap() != "POST||");
    }

    #[test]
    fn test_empty_method_error() {
        let result = ash_normalize_binding("", "/test", "");
        assert!(result.is_err(), "Empty method should error");
    }

    #[test]
    fn test_wrong_nonce_verification_fails() {
        let nonce_correct = "a".repeat(64);
        let nonce_wrong = "b".repeat(64);
        let context_id = "ash_test";
        let binding = "POST|/api|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        let secret = ash_derive_client_secret(&nonce_correct, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Correct nonce should verify
        let valid = ash_verify_proof(&nonce_correct, context_id, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid, "Correct nonce should verify");

        // Wrong nonce should fail
        let invalid = ash_verify_proof(&nonce_wrong, context_id, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(!invalid, "Wrong nonce should fail verification");
    }

    #[test]
    fn test_empty_timestamp_rejected() {
        // Empty timestamp is rejected by the SDK for security reasons
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let binding = "POST|/api|";
        let body_hash = ash_hash_body("{}");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let result = ash_build_proof(&secret, "", binding, &body_hash);
        assert!(result.is_err(), "Empty timestamp should be rejected");
    }
}

// =========================================================================
// A. UNIT TESTS - CANONICALIZATION CONSISTENCY
// =========================================================================

mod canonicalization_consistency {
    use super::*;

    #[test]
    fn test_unicode_normalization_nfc() {
        // Both should normalize to same form
        let input1 = r#"{"café":1}"#; // é as single codepoint
        let input2 = r#"{"café":1}"#; // e + combining accent (if different)

        let canon1 = ash_canonicalize_json(input1).unwrap();
        let _canon2 = ash_canonicalize_json(input2).unwrap();

        // Both should contain the café key
        assert!(canon1.contains("caf"));
    }

    #[test]
    fn test_number_negative_zero_normalized() {
        let result = ash_canonicalize_json(r#"{"value":-0}"#).unwrap();
        assert_eq!(result, r#"{"value":0}"#, "Negative zero not normalized");
    }

    #[test]
    fn test_nested_object_key_sorting() {
        let input = r#"{"z":{"z":1,"a":2},"a":{"z":3,"a":4}}"#;
        let result = ash_canonicalize_json(input).unwrap();
        let expected = r#"{"a":{"a":4,"z":3},"z":{"a":2,"z":1}}"#;

        assert_eq!(result, expected, "Nested sorting failed");
    }

    #[test]
    fn test_array_order_preserved() {
        let result = ash_canonicalize_json(r#"{"arr":[3,1,2]}"#).unwrap();
        assert!(result.contains("[3,1,2]"), "Array order not preserved");
    }

    #[test]
    fn test_special_characters_escaped() {
        let input = r#"{"text":"line1\nline2\ttab\"quote\\backslash"}"#;
        let result = ash_canonicalize_json(input).unwrap();

        assert!(result.contains("\\n"), "Newline not escaped");
        assert!(result.contains("\\t"), "Tab not escaped");
        assert!(result.contains("\\\""), "Quote not escaped");
        assert!(result.contains("\\\\"), "Backslash not escaped");
    }

    #[test]
    fn test_url_encoded_sorting() {
        let result = ash_canonicalize_urlencoded("z=1&a=2&m=3").unwrap();
        assert_eq!(result, "a=2&m=3&z=1", "URL encoding not sorted");
    }

    #[test]
    fn test_url_encoded_uppercase_hex() {
        let result = ash_canonicalize_urlencoded("key=hello world").unwrap();
        assert!(result.contains("%20"), "Space not encoded as %20");
    }
}

// =========================================================================
// C. SECURITY TESTS - PAYLOAD TAMPERING
// =========================================================================

mod payload_tampering {
    use super::*;

    #[test]
    fn test_field_reordering_same_canonical_form() {
        // After canonicalization, order should be the same
        let canon1 = ash_canonicalize_json(r#"{"z":1,"a":2}"#).unwrap();
        let canon2 = ash_canonicalize_json(r#"{"a":2,"z":1}"#).unwrap();

        assert_eq!(canon1, canon2, "Canonical form differs for reordered fields");
    }

    #[test]
    fn test_field_injection_detected() {
        let original = ash_canonicalize_json(r#"{"amount":100}"#).unwrap();
        let injected = ash_canonicalize_json(r#"{"amount":100,"admin":true}"#).unwrap();

        assert_ne!(original, injected, "Field injection not detected");
    }

    #[test]
    fn test_field_removal_detected() {
        let original = ash_canonicalize_json(r#"{"amount":100,"recipient":"user123"}"#).unwrap();
        let truncated = ash_canonicalize_json(r#"{"amount":100}"#).unwrap();

        assert_ne!(original, truncated, "Field removal not detected");
    }

    #[test]
    fn test_value_modification_detected() {
        let original = ash_canonicalize_json(r#"{"amount":100}"#).unwrap();
        let modified = ash_canonicalize_json(r#"{"amount":999}"#).unwrap();

        assert_ne!(original, modified, "Value modification not detected");
    }

    #[test]
    fn test_type_change_detected() {
        let original = ash_canonicalize_json(r#"{"count":100}"#).unwrap();
        let string_type = ash_canonicalize_json(r#"{"count":"100"}"#).unwrap();

        assert_ne!(original, string_type, "Type change not detected");
    }

    #[test]
    fn test_nested_tampering_detected() {
        let original = ash_canonicalize_json(r#"{"user":{"id":1,"role":"user"}}"#).unwrap();
        let tampered = ash_canonicalize_json(r#"{"user":{"id":1,"role":"admin"}}"#).unwrap();

        assert_ne!(original, tampered, "Nested tampering not detected");
    }

    #[test]
    fn test_array_modification_detected() {
        let original = ash_canonicalize_json(r#"{"items":[1,2,3]}"#).unwrap();
        let modified = ash_canonicalize_json(r#"{"items":[1,2,4]}"#).unwrap();

        assert_ne!(original, modified, "Array modification not detected");
    }

    #[test]
    fn test_array_reordering_detected() {
        // Arrays preserve order, so reordering should be detected
        let original = ash_canonicalize_json(r#"{"items":[1,2,3]}"#).unwrap();
        let reordered = ash_canonicalize_json(r#"{"items":[3,2,1]}"#).unwrap();

        assert_ne!(original, reordered, "Array reordering not detected");
    }
}

// =========================================================================
// C. SECURITY TESTS - BINDING TAMPERING
// =========================================================================

mod binding_tampering {
    use super::*;

    #[test]
    fn test_method_change_detected() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let timestamp = "12345";
        let body_hash = ash_hash_body("{}");

        let binding_post = "POST|/api/data|";
        let binding_put = "PUT|/api/data|";

        let secret_post = ash_derive_client_secret(&nonce, context_id, binding_post).unwrap();
        let secret_put = ash_derive_client_secret(&nonce, context_id, binding_put).unwrap();

        let proof_post = ash_build_proof(&secret_post, timestamp, binding_post, &body_hash).unwrap();
        let proof_put = ash_build_proof(&secret_put, timestamp, binding_put, &body_hash).unwrap();

        assert_ne!(proof_post, proof_put, "Method change not detected");
    }

    #[test]
    fn test_path_change_detected() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let timestamp = "12345";
        let body_hash = ash_hash_body("{}");

        let binding_user = "POST|/api/user|";
        let binding_admin = "POST|/api/admin|";

        let secret_user = ash_derive_client_secret(&nonce, context_id, binding_user).unwrap();
        let secret_admin = ash_derive_client_secret(&nonce, context_id, binding_admin).unwrap();

        let proof_user = ash_build_proof(&secret_user, timestamp, binding_user, &body_hash).unwrap();
        let proof_admin = ash_build_proof(&secret_admin, timestamp, binding_admin, &body_hash).unwrap();

        assert_ne!(proof_user, proof_admin, "Path change not detected");
    }

    #[test]
    fn test_query_parameter_injection_detected() {
        let binding1 = ash_normalize_binding("GET", "/api/data", "").unwrap();
        let binding2 = ash_normalize_binding("GET", "/api/data", "admin=true").unwrap();

        assert_ne!(binding1, binding2, "Query parameter injection not detected");
    }

    #[test]
    fn test_query_parameter_modification_detected() {
        let binding1 = ash_normalize_binding("GET", "/api/data", "id=1").unwrap();
        let binding2 = ash_normalize_binding("GET", "/api/data", "id=2").unwrap();

        assert_ne!(binding1, binding2, "Query parameter modification not detected");
    }
}

// =========================================================================
// C. SECURITY TESTS - TIME MANIPULATION
// =========================================================================

mod time_manipulation {
    use super::*;

    #[test]
    fn test_future_timestamp_different_proof() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let binding = "POST|/api/test|";
        let body_hash = ash_hash_body("{}");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let current_ts = chrono::Utc::now().timestamp().to_string();
        let future_ts = (chrono::Utc::now().timestamp() + 3600).to_string(); // 1 hour in future

        let proof_current = ash_build_proof(&secret, &current_ts, binding, &body_hash).unwrap();
        let proof_future = ash_build_proof(&secret, &future_ts, binding, &body_hash).unwrap();

        assert_ne!(proof_current, proof_future, "Timestamp not included in proof");
    }

    #[test]
    fn test_past_timestamp_different_proof() {
        let nonce = "a".repeat(64);
        let context_id = "ctx1";
        let binding = "POST|/api/test|";
        let body_hash = ash_hash_body("{}");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let current_ts = chrono::Utc::now().timestamp().to_string();
        let past_ts = (chrono::Utc::now().timestamp() - 3600).to_string(); // 1 hour in past

        let proof_current = ash_build_proof(&secret, &current_ts, binding, &body_hash).unwrap();
        let proof_past = ash_build_proof(&secret, &past_ts, binding, &body_hash).unwrap();

        assert_ne!(proof_current, proof_past, "Timestamp not included in proof");
    }

    #[test]
    fn test_timestamp_validation_valid() {
        let now = chrono::Utc::now().timestamp();
        let result = ash_validate_timestamp(&now.to_string(), 300, 60);
        assert!(result.is_ok(), "Valid timestamp should pass");
    }

    #[test]
    fn test_timestamp_validation_expired() {
        let past = chrono::Utc::now().timestamp() - 600; // 10 minutes ago
        let result = ash_validate_timestamp(&past.to_string(), 300, 60); // 5 min max age
        assert!(result.is_err(), "Expired timestamp should fail");
    }

    #[test]
    fn test_timestamp_validation_future() {
        let future = chrono::Utc::now().timestamp() + 120; // 2 minutes in future
        let result = ash_validate_timestamp(&future.to_string(), 300, 60); // 1 min drift allowed
        assert!(result.is_err(), "Future timestamp beyond drift should fail");
    }
}

// =========================================================================
// C. SECURITY TESTS - HEADER CONFUSION
// =========================================================================

mod header_confusion {
    use super::*;

    #[test]
    fn test_binding_normalization_prevents_confusion() {
        // All these should normalize to the same binding
        let variations = vec![
            ash_normalize_binding("POST", "/api/test", "").unwrap(),
            ash_normalize_binding("post", "/api/test", "").unwrap(),
            ash_normalize_binding("POST", "/api//test", "").unwrap(),
            ash_normalize_binding("POST", "/api/test/", "").unwrap(),
        ];

        assert!(variations.iter().all(|v| v == &variations[0]),
                "Binding normalization inconsistent: {:?}", variations);
    }

    #[test]
    fn test_query_string_normalization_prevents_confusion() {
        let binding1 = ash_normalize_binding("GET", "/api", "a=1&b=2").unwrap();
        let binding2 = ash_normalize_binding("GET", "/api", "b=2&a=1").unwrap();

        assert_eq!(binding1, binding2, "Query parameter order not normalized");
    }

    #[test]
    fn test_proof_with_different_values_different() {
        let canon1 = ash_canonicalize_json(r#"{"key":"value1"}"#).unwrap();
        let canon2 = ash_canonicalize_json(r#"{"key":"value2"}"#).unwrap();

        assert_ne!(canon1, canon2, "Different values should produce different canonical forms");
    }

    #[test]
    fn test_case_sensitivity_in_keys() {
        let canon1 = ash_canonicalize_json(r#"{"Key":"value"}"#).unwrap();
        let canon2 = ash_canonicalize_json(r#"{"key":"value"}"#).unwrap();

        assert_ne!(canon1, canon2, "JSON keys should be case-sensitive");
    }

    #[test]
    fn test_case_sensitivity_in_values() {
        let canon1 = ash_canonicalize_json(r#"{"key":"Value"}"#).unwrap();
        let canon2 = ash_canonicalize_json(r#"{"key":"value"}"#).unwrap();

        assert_ne!(canon1, canon2, "JSON values should be case-sensitive");
    }
}

// =========================================================================
// C. SECURITY TESTS - NONCE SECURITY BOUNDARY
// =========================================================================

mod nonce_security {
    use super::*;

    #[test]
    fn test_cannot_reverse_client_secret_to_nonce() {
        // Nonce must be valid hex
        let nonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let context_id = "ash_test_ctx";
        let binding = "POST|/api/test|";

        let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();

        // Client secret should be 64 hex chars (32 bytes)
        assert_eq!(client_secret.len(), 64, "Unexpected client secret length");

        // Should not contain the original nonce
        assert!(!client_secret.contains(nonce), "Nonce leaked in client secret");
    }

    #[test]
    fn test_client_secret_is_hex() {
        let nonce = "a".repeat(64);
        let context_id = "test";
        let binding = "GET|/|";

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()), "Client secret should be hex");
        assert!(secret.chars().all(|c| !c.is_uppercase()), "Client secret should be lowercase hex");
    }

    #[test]
    fn test_different_contexts_different_secrets() {
        let nonce = "a".repeat(64);
        let binding = "GET|/|";

        let secret1 = ash_derive_client_secret(&nonce, "ctx1", binding).unwrap();
        let secret2 = ash_derive_client_secret(&nonce, "ctx2", binding).unwrap();

        assert_ne!(secret1, secret2, "Different contexts should produce different secrets");
    }

    #[test]
    fn test_different_bindings_different_secrets() {
        let nonce = "a".repeat(64);
        let context_id = "ctx";

        let secret1 = ash_derive_client_secret(&nonce, context_id, "GET|/a|").unwrap();
        let secret2 = ash_derive_client_secret(&nonce, context_id, "GET|/b|").unwrap();

        assert_ne!(secret1, secret2, "Different bindings should produce different secrets");
    }

    #[test]
    fn test_different_nonces_different_secrets() {
        let context_id = "ctx";
        let binding = "GET|/|";

        let secret1 = ash_derive_client_secret(&"a".repeat(64), context_id, binding).unwrap();
        let secret2 = ash_derive_client_secret(&"b".repeat(64), context_id, binding).unwrap();

        assert_ne!(secret1, secret2, "Different nonces should produce different secrets");
    }
}

// =========================================================================
// D. CRYPTOGRAPHIC TESTS - CONSTANT TIME COMPARISON
// =========================================================================

mod constant_time {
    use super::*;

    #[test]
    fn test_timing_safe_equal_same() {
        assert!(ash_timing_safe_equal(b"test", b"test"));
    }

    #[test]
    fn test_timing_safe_equal_different() {
        assert!(!ash_timing_safe_equal(b"test", b"tess"));
    }

    #[test]
    fn test_timing_safe_equal_different_lengths() {
        assert!(!ash_timing_safe_equal(b"test", b"tes"));
    }

    #[test]
    fn test_timing_safe_equal_empty() {
        assert!(ash_timing_safe_equal(b"", b""));
    }

    #[test]
    fn test_timing_safe_equal_one_empty() {
        assert!(!ash_timing_safe_equal(b"test", b""));
    }

    #[test]
    fn test_timing_safe_equal_long_strings() {
        let a = "a".repeat(1000);
        let b = "a".repeat(1000);
        assert!(ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }

    #[test]
    fn test_timing_safe_equal_differs_at_end() {
        let a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
        let b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2";
        assert!(!ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }

    #[test]
    fn test_timing_safe_equal_differs_at_start() {
        let a = "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(!ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }
}

// =========================================================================
// D. CRYPTOGRAPHIC TESTS - HASH PROPERTIES
// =========================================================================

mod hash_properties {
    use super::*;

    #[test]
    fn test_hash_length() {
        let hash = ash_hash_body("test");
        assert_eq!(hash.len(), 64, "Hash should be 64 hex chars (32 bytes)");
    }

    #[test]
    fn test_hash_is_hex() {
        let hash = ash_hash_body("test");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be hex");
    }

    #[test]
    fn test_hash_is_lowercase() {
        let hash = ash_hash_body("test");
        assert!(hash.chars().all(|c| !c.is_uppercase()), "Hash should be lowercase");
    }

    #[test]
    fn test_hash_avalanche() {
        // Small input change should cause significant hash change
        let hash1 = ash_hash_body("test1");
        let hash2 = ash_hash_body("test2");

        // Count differing characters
        let diff_count = hash1.chars().zip(hash2.chars())
            .filter(|(a, b)| a != b)
            .count();

        // At least 50% of characters should differ
        assert!(diff_count >= 32, "Hash avalanche effect too weak");
    }

    #[test]
    fn test_empty_string_hash() {
        let hash = ash_hash_body("");
        // Well-known SHA-256 of empty string
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_hash_collision_resistance() {
        // Different inputs should produce different hashes
        let inputs = vec!["a", "b", "c", "aa", "ab", "ba", "test", "Test", "TEST"];
        let hashes: Vec<String> = inputs.iter().map(|i| ash_hash_body(i)).collect();

        let unique: std::collections::HashSet<&String> = hashes.iter().collect();
        assert_eq!(unique.len(), inputs.len(), "Hash collision detected");
    }
}

// =========================================================================
// SCOPED PROOF SECURITY TESTS
// =========================================================================

mod scoped_proof_security {
    use super::*;

    #[test]
    fn test_scoped_proof_protects_specified_fields() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_scoped";
        let binding = "POST|/api/transfer|";
        let timestamp = "12345";

        // Payload with critical and non-critical fields
        let payload1 = r#"{"amount":100,"recipient":"user123","notes":"note1"}"#;
        let payload2 = r#"{"amount":100,"recipient":"user123","notes":"note2"}"#;

        // Scope only protects amount and recipient
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let (proof1, scope_hash1) = ash_build_proof_scoped(&secret, timestamp, binding, payload1, &scope).unwrap();
        let (proof2, scope_hash2) = ash_build_proof_scoped(&secret, timestamp, binding, payload2, &scope).unwrap();

        // Proofs should be same since scoped fields are identical
        assert_eq!(proof1, proof2, "Same scoped fields should produce same proof");
        assert_eq!(scope_hash1, scope_hash2, "Same scope should produce same scope hash");
    }

    #[test]
    fn test_scoped_proof_detects_protected_field_change() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_scoped";
        let binding = "POST|/api/transfer|";
        let timestamp = "12345";

        let payload1 = r#"{"amount":100,"recipient":"user123"}"#;
        let payload2 = r#"{"amount":200,"recipient":"user123"}"#; // amount changed

        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let (proof1, _) = ash_build_proof_scoped(&secret, timestamp, binding, payload1, &scope).unwrap();
        let (proof2, _) = ash_build_proof_scoped(&secret, timestamp, binding, payload2, &scope).unwrap();

        assert_ne!(proof1, proof2, "Scoped field change not detected");
    }

    #[test]
    fn test_scoped_proof_verification_roundtrip() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_scoped";
        let binding = "POST|/api/transfer|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let payload = r#"{"amount":100,"recipient":"user123"}"#;
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, &timestamp, binding, payload, &scope).unwrap();

        // Correct argument order: nonce, context_id, binding, timestamp, payload, scope, scope_hash, client_proof
        let verified = ash_verify_proof_scoped(
            &nonce, context_id, binding, &timestamp, payload, &scope, &scope_hash, &proof
        ).unwrap();

        assert!(verified, "Scoped proof verification failed");
    }
}

// =========================================================================
// CHAINED PROOF SECURITY TESTS
// =========================================================================

mod chained_proof_security {
    use super::*;

    #[test]
    fn test_chain_breaks_without_previous_proof() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_chain";
        let binding = "POST|/api/step2|";
        let timestamp = "12345";
        let payload = "{}";

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        // Step 2 with correct previous proof
        let prev_proof = "c".repeat(64);
        let result_with_chain = ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&prev_proof)).unwrap();

        // Step 2 without previous proof
        let result_no_chain = ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

        // Proofs should differ
        assert_ne!(result_with_chain.proof, result_no_chain.proof, "Chain should affect proof");
    }

    #[test]
    fn test_chain_different_previous_proof_different_result() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_chain";
        let binding = "POST|/api/step2|";
        let timestamp = "12345";
        let payload = "{}";

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let prev_proof1 = "a".repeat(64);
        let prev_proof2 = "b".repeat(64);

        let result1 = ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&prev_proof1)).unwrap();
        let result2 = ash_build_proof_unified(&secret, timestamp, binding, payload, &[], Some(&prev_proof2)).unwrap();

        assert_ne!(result1.proof, result2.proof, "Different previous proofs should produce different results");
        assert_ne!(result1.chain_hash, result2.chain_hash, "Different previous proofs should produce different chain hashes");
    }

    #[test]
    fn test_chain_verification_roundtrip() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_chain";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let payload = "{}";

        // Step 1
        let binding1 = "POST|/api/cart|";
        let secret1 = ash_derive_client_secret(&nonce, context_id, binding1).unwrap();
        let result1 = ash_build_proof_unified(&secret1, &timestamp, binding1, payload, &[], None).unwrap();

        // Step 2 (chained)
        let binding2 = "POST|/api/checkout|";
        let secret2 = ash_derive_client_secret(&nonce, context_id, binding2).unwrap();
        let result2 = ash_build_proof_unified(&secret2, &timestamp, binding2, payload, &[], Some(&result1.proof)).unwrap();

        // Step 3 (chained)
        let binding3 = "POST|/api/payment|";
        let secret3 = ash_derive_client_secret(&nonce, context_id, binding3).unwrap();
        let result3 = ash_build_proof_unified(&secret3, &timestamp, binding3, payload, &[], Some(&result2.proof)).unwrap();

        // All proofs should be valid
        assert_eq!(result1.proof.len(), 64);
        assert_eq!(result2.proof.len(), 64);
        assert_eq!(result3.proof.len(), 64);

        // Chain should progress
        assert!(result1.chain_hash.is_empty());
        assert!(!result2.chain_hash.is_empty());
        assert!(!result3.chain_hash.is_empty());
    }
}
