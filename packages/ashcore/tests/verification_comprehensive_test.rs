//! Comprehensive Verification Tests
//!
//! These tests cover proof verification scenarios including:
//! - Valid proof verification
//! - Invalid proof detection
//! - Tampering detection
//! - Concurrent verification

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_hash_body, ash_timing_safe_equal,
};

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// =========================================================================
// VALID PROOF VERIFICATION
// =========================================================================

mod valid_proofs {
    use super::*;

    #[test]
    fn test_basic_proof_verification() {
        let context_id = "ctx_basic_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verification_with_query_string() {
        let context_id = "ctx_query_001";
        let binding = "GET|/api/search|q=test&page=1";
        let timestamp = "1700000001";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verification_with_json_body() {
        let context_id = "ctx_json_001";
        let binding = "POST|/api/users|";
        let timestamp = "1700000002";
        let body = r#"{"name":"John","age":30}"#;
        let body_hash = ash_hash_body(body);

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verification_different_methods() {
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

        for method in methods {
            let context_id = format!("ctx_{}", method.to_lowercase());
            let binding = format!("{}|/api/resource|", method);
            let timestamp = "1700000003";

            let secret = ash_derive_client_secret(TEST_NONCE, &context_id, &binding).unwrap();
            let proof = ash_build_proof(&secret, timestamp, &binding, TEST_BODY_HASH).unwrap();

            let valid = ash_verify_proof(TEST_NONCE, &context_id, &binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
            assert!(valid, "Failed for method {}", method);
        }
    }

    #[test]
    fn test_verification_with_empty_body() {
        let context_id = "ctx_empty_001";
        let binding = "GET|/api/health|";
        let timestamp = "1700000004";
        let body_hash = ash_hash_body("");

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verification_multiple_times() {
        let context_id = "ctx_multi_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000005";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        // Verify multiple times - should always succeed
        for _ in 0..10 {
            let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
            assert!(valid);
        }
    }
}

// =========================================================================
// INVALID PROOF DETECTION
// =========================================================================

mod invalid_proofs {
    use super::*;

    #[test]
    fn test_wrong_proof_rejected() {
        let context_id = "ctx_wrong_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000010";
        let wrong_proof = "0".repeat(64);

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &wrong_proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_random_proof_rejected() {
        let context_id = "ctx_random_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000011";
        let random_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &random_proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_truncated_proof_rejected() {
        let context_id = "ctx_truncated_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000012";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let full_proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();
        let truncated = &full_proof[..32]; // Only half

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, truncated).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_extended_proof_rejected() {
        let context_id = "ctx_extended_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000013";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let full_proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();
        let extended = format!("{}extra", full_proof);

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &extended).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_empty_proof_rejected() {
        let context_id = "ctx_empty_proof_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000014";

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, "").unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_case_sensitive_proof() {
        let context_id = "ctx_case_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000015";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();
        let upper_proof = proof.to_uppercase();

        // If proof was originally lowercase, uppercase should fail
        if proof != upper_proof {
            let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &upper_proof).unwrap();
            assert!(!valid);
        }
    }
}

// =========================================================================
// TAMPERING DETECTION
// =========================================================================

mod tampering_detection {
    use super::*;

    #[test]
    fn test_tampered_body_detected() {
        let context_id = "ctx_tamper_body_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000020";

        let original_body = r#"{"amount":100}"#;
        let tampered_body = r#"{"amount":1000}"#;
        let original_hash = ash_hash_body(original_body);
        let tampered_hash = ash_hash_body(tampered_body);

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &original_hash).unwrap();

        // Original should verify
        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, &original_hash, &proof).unwrap();
        assert!(valid);

        // Tampered should fail
        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, &tampered_hash, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_tampered_binding_detected() {
        let context_id = "ctx_tamper_binding_001";
        let original_binding = "POST|/api/users|";
        let tampered_binding = "POST|/api/admin|";
        let timestamp = "1700000021";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, original_binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, original_binding, TEST_BODY_HASH).unwrap();

        // Original should verify
        let valid = ash_verify_proof(TEST_NONCE, context_id, original_binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(valid);

        // Tampered binding should fail
        let valid = ash_verify_proof(TEST_NONCE, context_id, tampered_binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_tampered_timestamp_detected() {
        let context_id = "ctx_tamper_ts_001";
        let binding = "POST|/api/test|";
        let original_timestamp = "1700000022";
        let tampered_timestamp = "1700000023";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, original_timestamp, binding, TEST_BODY_HASH).unwrap();

        // Original should verify
        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, original_timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(valid);

        // Tampered timestamp should fail
        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, tampered_timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_tampered_context_id_detected() {
        let original_context = "ctx_tamper_ctx_001";
        let tampered_context = "ctx_tamper_ctx_002";
        let binding = "POST|/api/test|";
        let timestamp = "1700000024";

        let secret = ash_derive_client_secret(TEST_NONCE, original_context, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        // Original should verify
        let valid = ash_verify_proof(TEST_NONCE, original_context, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(valid);

        // Different context should fail
        let valid = ash_verify_proof(TEST_NONCE, tampered_context, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_tampered_nonce_detected() {
        let context_id = "ctx_tamper_nonce_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000025";
        let different_nonce = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        // Original should verify
        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(valid);

        // Different nonce should fail
        let valid = ash_verify_proof(different_nonce, context_id, binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_single_bit_change_in_proof_detected() {
        let context_id = "ctx_bit_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000026";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        // Change one character in the proof
        let mut modified = proof.clone();
        let first_char = modified.chars().next().unwrap();
        let new_char = if first_char == '0' { '1' } else { '0' };
        modified.replace_range(0..1, &new_char.to_string());

        let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &modified).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_method_case_tampering() {
        let context_id = "ctx_method_case_001";
        let original_binding = "POST|/api/test|";
        let tampered_binding = "post|/api/test|"; // lowercase method
        let timestamp = "1700000027";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, original_binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, original_binding, TEST_BODY_HASH).unwrap();

        // Tampered (lowercase) binding should fail
        let valid = ash_verify_proof(TEST_NONCE, context_id, tampered_binding, timestamp, TEST_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }
}

// =========================================================================
// CONCURRENT VERIFICATION
// =========================================================================

mod concurrent_verification {
    use super::*;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_concurrent_verification_same_proof() {
        let context_id = "ctx_concurrent_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000030";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        let proof = Arc::new(proof);
        let mut handles = vec![];

        for _ in 0..10 {
            let proof = Arc::clone(&proof);
            let handle = thread::spawn(move || {
                let valid = ash_verify_proof(
                    TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof
                ).unwrap();
                assert!(valid);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_verification_different_proofs() {
        let binding = "POST|/api/test|";
        let base_timestamp = 1700000040u64;

        let mut handles = vec![];

        for i in 0..10 {
            let context_id = format!("ctx_concurrent_{}", i);
            let timestamp = (base_timestamp + i as u64).to_string();

            let handle = thread::spawn(move || {
                let secret = ash_derive_client_secret(TEST_NONCE, &context_id, binding).unwrap();
                let proof = ash_build_proof(&secret, &timestamp, binding, TEST_BODY_HASH).unwrap();

                let valid = ash_verify_proof(
                    TEST_NONCE, &context_id, binding, &timestamp, TEST_BODY_HASH, &proof
                ).unwrap();
                assert!(valid);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_hash_computation() {
        let mut handles = vec![];

        for i in 0..20 {
            let handle = thread::spawn(move || {
                let body = format!("body content {}", i);
                let hash = ash_hash_body(&body);
                assert_eq!(hash.len(), 64);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

// =========================================================================
// TIMING SAFE COMPARISON TESTS
// =========================================================================

mod timing_safe {
    use super::*;

    #[test]
    fn test_timing_safe_equal_strings() {
        let a = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let b = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert!(ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }

    #[test]
    fn test_timing_safe_different_strings() {
        let a = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let b = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

        assert!(!ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }

    #[test]
    fn test_timing_safe_different_lengths() {
        let a = "short";
        let b = "much longer string";

        assert!(!ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }

    #[test]
    fn test_timing_safe_empty_strings() {
        assert!(ash_timing_safe_equal(b"", b""));
    }

    #[test]
    fn test_timing_safe_one_empty() {
        assert!(!ash_timing_safe_equal(b"", b"not empty"));
        assert!(!ash_timing_safe_equal(b"not empty", b""));
    }

    #[test]
    fn test_timing_safe_single_char_difference() {
        let a = "abcdefghij";
        let b = "abcdefghik";

        assert!(!ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }
}

// =========================================================================
// ERROR HANDLING TESTS
// =========================================================================

mod error_handling {
    use super::*;

    #[test]
    fn test_invalid_timestamp_format() {
        let context_id = "ctx_err_001";
        let binding = "POST|/api/test|";
        let invalid_timestamp = "not_a_number";

        let result = ash_verify_proof(TEST_NONCE, context_id, binding, invalid_timestamp, TEST_BODY_HASH, "x".repeat(64).as_str());
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamp_with_leading_zeros_rejected() {
        let context_id = "ctx_err_002";
        let binding = "POST|/api/test|";
        let timestamp = "0123456789";

        let result = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, "x".repeat(64).as_str());
        assert!(result.is_err());
    }

    #[test]
    fn test_short_nonce_rejected() {
        let short_nonce = "abc123";
        let context_id = "ctx_err_003";
        let binding = "POST|/api/test|";

        let result = ash_derive_client_secret(short_nonce, context_id, binding);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_hex_nonce_rejected() {
        let non_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let context_id = "ctx_err_004";
        let binding = "POST|/api/test|";

        let result = ash_derive_client_secret(non_hex, context_id, binding);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_context_id_rejected() {
        let binding = "POST|/api/test|";

        let result = ash_derive_client_secret(TEST_NONCE, "", binding);
        assert!(result.is_err());
    }
}
