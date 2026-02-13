//! Comprehensive Scoped and Chained Proof Tests
//!
//! These tests cover:
//! - Field extraction for scoped proofs
//! - Scope hash computation
//! - Chain verification
//! - Combined scoping and chaining

use ashcore::{
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_extract_scoped_fields, ash_extract_scoped_fields_strict,
    ash_hash_scope, ash_hash_scoped_body, ash_hash_scoped_body_strict,
    ash_derive_client_secret, ash_hash_proof,
    ash_build_proof_unified, ash_verify_proof_unified,
};
use serde_json::json;

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// =========================================================================
// FIELD EXTRACTION TESTS
// =========================================================================

mod field_extraction {
    use super::*;

    #[test]
    fn test_extract_single_top_level_field() {
        let payload = json!({"amount": 100, "note": "test"});
        let scope = vec!["amount"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, json!({"amount": 100}));
    }

    #[test]
    fn test_extract_multiple_top_level_fields() {
        let payload = json!({"amount": 100, "recipient": "alice", "note": "test"});
        let scope = vec!["amount", "recipient"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, json!({"amount": 100, "recipient": "alice"}));
    }

    #[test]
    fn test_extract_nested_field() {
        let payload = json!({
            "user": {"name": "John", "email": "john@example.com"},
            "action": "update"
        });
        let scope = vec!["user.name"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, json!({"user": {"name": "John"}}));
    }

    #[test]
    fn test_extract_deeply_nested_field() {
        let payload = json!({
            "data": {
                "user": {
                    "profile": {
                        "name": "John"
                    }
                }
            }
        });
        let scope = vec!["data.user.profile.name"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, json!({"data": {"user": {"profile": {"name": "John"}}}}));
    }

    #[test]
    fn test_extract_array_element() {
        let payload = json!({
            "items": [10, 20, 30]
        });
        let scope = vec!["items[0]"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, json!({"items": [10]}));
    }

    #[test]
    fn test_extract_array_object_field() {
        let payload = json!({
            "users": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"}
            ]
        });
        let scope = vec!["users[0].name"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, json!({"users": [{"name": "Alice"}]}));
    }

    #[test]
    fn test_extract_missing_field_non_strict() {
        let payload = json!({"amount": 100});
        let scope = vec!["amount", "nonexistent"];

        // Non-strict mode should succeed
        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();
        assert_eq!(result, json!({"amount": 100}));
    }

    #[test]
    fn test_extract_missing_field_strict() {
        let payload = json!({"amount": 100});
        let scope = vec!["amount", "nonexistent"];

        // Strict mode should fail
        let result = ash_extract_scoped_fields_strict(&payload, &scope, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_empty_scope_returns_full_payload() {
        let payload = json!({"amount": 100, "note": "test"});
        let scope: Vec<&str> = vec![];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result, payload);
    }

    #[test]
    fn test_extract_preserves_value_types() {
        let payload = json!({
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": true,
            "null": null,
            "array": [1, 2, 3],
            "object": {"nested": "value"}
        });
        let scope = vec!["string", "number", "float", "bool", "null", "array", "object"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result["string"], "hello");
        assert_eq!(result["number"], 42);
        assert_eq!(result["float"], 3.14);
        assert_eq!(result["bool"], true);
        assert_eq!(result["null"], json!(null));
        assert_eq!(result["array"], json!([1, 2, 3]));
        assert_eq!(result["object"], json!({"nested": "value"}));
    }

    #[test]
    fn test_extract_with_special_characters_in_values() {
        let payload = json!({
            "text": "Hello\nWorld\t!",
            "unicode": "café"
        });
        let scope = vec!["text", "unicode"];

        let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

        assert_eq!(result["text"], "Hello\nWorld\t!");
        assert_eq!(result["unicode"], "café");
    }
}

// =========================================================================
// SCOPE HASH TESTS
// =========================================================================

mod scope_hash {
    use super::*;

    #[test]
    fn test_empty_scope_returns_empty_hash() {
        let scope: Vec<&str> = vec![];
        let result = ash_hash_scope(&scope).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_field_scope_hash() {
        let scope = vec!["amount"];
        let result = ash_hash_scope(&scope).unwrap();

        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_multiple_fields_scope_hash() {
        let scope = vec!["amount", "recipient"];
        let result = ash_hash_scope(&scope).unwrap();

        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_scope_hash_deterministic() {
        let scope = vec!["amount", "recipient"];

        let hash1 = ash_hash_scope(&scope).unwrap();
        let hash2 = ash_hash_scope(&scope).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_scope_hash_order_independent() {
        // BUG-023: Scope should be auto-sorted
        let scope1 = vec!["recipient", "amount"];
        let scope2 = vec!["amount", "recipient"];

        let hash1 = ash_hash_scope(&scope1).unwrap();
        let hash2 = ash_hash_scope(&scope2).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_scope_hash_deduplicates() {
        let scope1 = vec!["amount"];
        let scope2 = vec!["amount", "amount"];

        let hash1 = ash_hash_scope(&scope1).unwrap();
        let hash2 = ash_hash_scope(&scope2).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_scope_hash_different_for_different_fields() {
        let scope1 = vec!["amount"];
        let scope2 = vec!["recipient"];

        let hash1 = ash_hash_scope(&scope1).unwrap();
        let hash2 = ash_hash_scope(&scope2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_scope_rejects_empty_field_names() {
        let scope = vec!["amount", ""];
        let result = ash_hash_scope(&scope);

        assert!(result.is_err());
    }

    #[test]
    fn test_scope_rejects_delimiter_character() {
        let scope = vec!["field\x1Fname"];
        let result = ash_hash_scope(&scope);

        assert!(result.is_err());
    }
}

// =========================================================================
// SCOPED BODY HASH TESTS
// =========================================================================

mod scoped_body_hash {
    use super::*;

    #[test]
    fn test_scoped_body_hash_single_field() {
        let payload = r#"{"amount":100,"note":"test"}"#;
        let scope = vec!["amount"];

        let result = ash_hash_scoped_body(payload, &scope).unwrap();

        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_scoped_body_hash_deterministic() {
        let payload = r#"{"amount":100,"note":"test"}"#;
        let scope = vec!["amount"];

        let hash1 = ash_hash_scoped_body(payload, &scope).unwrap();
        let hash2 = ash_hash_scoped_body(payload, &scope).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_scoped_body_hash_different_values() {
        let payload1 = r#"{"amount":100}"#;
        let payload2 = r#"{"amount":200}"#;
        let scope = vec!["amount"];

        let hash1 = ash_hash_scoped_body(payload1, &scope).unwrap();
        let hash2 = ash_hash_scoped_body(payload2, &scope).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_scoped_body_hash_ignores_unscoped_changes() {
        let payload1 = r#"{"amount":100,"note":"first"}"#;
        let payload2 = r#"{"amount":100,"note":"second"}"#;
        let scope = vec!["amount"];

        let hash1 = ash_hash_scoped_body(payload1, &scope).unwrap();
        let hash2 = ash_hash_scoped_body(payload2, &scope).unwrap();

        // Same scoped fields should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_scoped_body_hash_strict_mode() {
        let payload = r#"{"amount":100}"#;
        let scope = vec!["amount", "recipient"];

        // Strict mode should fail for missing field
        let result = ash_hash_scoped_body_strict(payload, &scope);
        assert!(result.is_err());
    }
}

// =========================================================================
// SCOPED PROOF TESTS
// =========================================================================

mod scoped_proofs {
    use super::*;

    #[test]
    fn test_build_scoped_proof() {
        let context_id = "ctx_scoped_001";
        let binding = "POST|/api/transfer|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100,"note":"test","recipient":"alice"}"#;
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        assert_eq!(proof.len(), 64);
        assert_eq!(scope_hash.len(), 64);
    }

    #[test]
    fn test_verify_scoped_proof() {
        let context_id = "ctx_scoped_002";
        let binding = "POST|/api/transfer|";
        let timestamp = "1700000001";
        let payload = r#"{"amount":100,"note":"test","recipient":"alice"}"#;
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        let valid = ash_verify_proof_scoped(
            TEST_NONCE, context_id, binding, timestamp, payload, &scope, &scope_hash, &proof
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_scoped_proof_allows_unscoped_field_change() {
        let context_id = "ctx_scoped_003";
        let binding = "POST|/api/transfer|";
        let timestamp = "1700000002";
        let payload1 = r#"{"amount":100,"note":"first","recipient":"alice"}"#;
        let payload2 = r#"{"amount":100,"note":"second","recipient":"alice"}"#;  // note changed
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload1, &scope).unwrap();

        // Verification with modified payload should still succeed
        let valid = ash_verify_proof_scoped(
            TEST_NONCE, context_id, binding, timestamp, payload2, &scope, &scope_hash, &proof
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_scoped_proof_detects_scoped_field_change() {
        let context_id = "ctx_scoped_004";
        let binding = "POST|/api/transfer|";
        let timestamp = "1700000003";
        let payload1 = r#"{"amount":100,"note":"test","recipient":"alice"}"#;
        let payload2 = r#"{"amount":999,"note":"test","recipient":"alice"}"#;  // amount changed
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload1, &scope).unwrap();

        // Verification should fail because scoped field was modified
        let valid = ash_verify_proof_scoped(
            TEST_NONCE, context_id, binding, timestamp, payload2, &scope, &scope_hash, &proof
        ).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_scoped_proof_with_empty_scope() {
        let context_id = "ctx_scoped_005";
        let binding = "POST|/api/test|";
        let timestamp = "1700000004";
        let payload = r#"{"data":"test"}"#;
        let scope: Vec<&str> = vec![];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        // Empty scope should produce empty scope_hash
        assert!(scope_hash.is_empty());

        let valid = ash_verify_proof_scoped(
            TEST_NONCE, context_id, binding, timestamp, payload, &scope, &scope_hash, &proof
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_scoped_proof_with_empty_payload() {
        let context_id = "ctx_scoped_006";
        let binding = "POST|/api/test|";
        let timestamp = "1700000005";
        let payload = "";
        let scope: Vec<&str> = vec![];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let (proof, _scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        assert_eq!(proof.len(), 64);
    }
}

// =========================================================================
// CHAIN VERIFICATION TESTS
// =========================================================================

mod chain_verification {
    use super::*;

    #[test]
    fn test_hash_proof_function() {
        let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let hash = ash_hash_proof(proof).unwrap();

        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_proof_deterministic() {
        let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let hash1 = ash_hash_proof(proof).unwrap();
        let hash2 = ash_hash_proof(proof).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_proof_different_inputs() {
        let proof1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let proof2 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let hash1 = ash_hash_proof(proof1).unwrap();
        let hash2 = ash_hash_proof(proof2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_proof_rejects_empty() {
        let result = ash_hash_proof("");
        assert!(result.is_err());
    }
}

// =========================================================================
// UNIFIED PROOF TESTS (SCOPING + CHAINING)
// =========================================================================

mod unified_proofs {
    use super::*;

    #[test]
    fn test_unified_basic_no_scope_no_chain() {
        let context_id = "ctx_unified_001";
        let binding = "POST|/api/test|";
        let timestamp = "1700000010";
        let payload = r#"{"data":"test"}"#;

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let result = ash_build_proof_unified(&secret, timestamp, binding, payload, &[], None).unwrap();

        assert_eq!(result.proof.len(), 64);
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let valid = ash_verify_proof_unified(
            TEST_NONCE, context_id, binding, timestamp, payload,
            &result.proof, &[], "", None, ""
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_unified_with_scope() {
        let context_id = "ctx_unified_002";
        let binding = "POST|/api/transfer|";
        let timestamp = "1700000011";
        let payload = r#"{"amount":100,"note":"test"}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let result = ash_build_proof_unified(&secret, timestamp, binding, payload, &scope, None).unwrap();

        assert!(!result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let valid = ash_verify_proof_unified(
            TEST_NONCE, context_id, binding, timestamp, payload,
            &result.proof, &scope, &result.scope_hash, None, ""
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_unified_with_chain() {
        let context_id = "ctx_unified_003";
        let binding = "POST|/api/confirm|";
        let timestamp = "1700000012";
        let payload = r#"{"confirmed":true}"#;
        let previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &secret, timestamp, binding, payload, &[], Some(previous_proof)
        ).unwrap();

        assert!(result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());

        // Chain hash should be SHA256 of previous proof
        let expected_chain = ash_hash_proof(previous_proof).unwrap();
        assert_eq!(result.chain_hash, expected_chain);

        let valid = ash_verify_proof_unified(
            TEST_NONCE, context_id, binding, timestamp, payload,
            &result.proof, &[], "", Some(previous_proof), &result.chain_hash
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_unified_with_scope_and_chain() {
        let context_id = "ctx_unified_004";
        let binding = "POST|/api/finalize|";
        let timestamp = "1700000013";
        let payload = r#"{"amount":500,"approved":true,"note":"final"}"#;
        let previous_proof = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let scope = vec!["amount", "approved"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &secret, timestamp, binding, payload, &scope, Some(previous_proof)
        ).unwrap();

        assert!(!result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());

        let valid = ash_verify_proof_unified(
            TEST_NONCE, context_id, binding, timestamp, payload,
            &result.proof, &scope, &result.scope_hash, Some(previous_proof), &result.chain_hash
        ).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_unified_wrong_scope_hash_fails() {
        let context_id = "ctx_unified_005";
        let binding = "POST|/api/test|";
        let timestamp = "1700000014";
        let payload = r#"{"amount":100}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let result = ash_build_proof_unified(&secret, timestamp, binding, payload, &scope, None).unwrap();

        let wrong_scope_hash = "0".repeat(64);
        let valid = ash_verify_proof_unified(
            TEST_NONCE, context_id, binding, timestamp, payload,
            &result.proof, &scope, &wrong_scope_hash, None, ""
        ).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_unified_wrong_chain_hash_fails() {
        let context_id = "ctx_unified_006";
        let binding = "POST|/api/test|";
        let timestamp = "1700000015";
        let payload = r#"{"confirmed":true}"#;
        let previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let result = ash_build_proof_unified(
            &secret, timestamp, binding, payload, &[], Some(previous_proof)
        ).unwrap();

        let wrong_chain_hash = "1".repeat(64);
        let valid = ash_verify_proof_unified(
            TEST_NONCE, context_id, binding, timestamp, payload,
            &result.proof, &[], "", Some(previous_proof), &wrong_chain_hash
        ).unwrap();

        assert!(!valid);
    }
}

// =========================================================================
// MULTI-STEP CHAIN TESTS
// =========================================================================

mod multi_step_chain {
    use super::*;

    #[test]
    fn test_three_step_chain() {
        let binding = "POST|/api/step|";

        // Step 1: Initial request
        let ctx1 = "ctx_chain_step1";
        let ts1 = "1700000020";
        let payload1 = r#"{"step":1}"#;

        let secret1 = ash_derive_client_secret(TEST_NONCE, ctx1, binding).unwrap();
        let result1 = ash_build_proof_unified(&secret1, ts1, binding, payload1, &[], None).unwrap();

        let valid1 = ash_verify_proof_unified(
            TEST_NONCE, ctx1, binding, ts1, payload1, &result1.proof, &[], "", None, ""
        ).unwrap();
        assert!(valid1);

        // Step 2: Chain to step 1
        let ctx2 = "ctx_chain_step2";
        let ts2 = "1700000021";
        let payload2 = r#"{"step":2}"#;

        let secret2 = ash_derive_client_secret(TEST_NONCE, ctx2, binding).unwrap();
        let result2 = ash_build_proof_unified(
            &secret2, ts2, binding, payload2, &[], Some(&result1.proof)
        ).unwrap();

        let valid2 = ash_verify_proof_unified(
            TEST_NONCE, ctx2, binding, ts2, payload2, &result2.proof,
            &[], "", Some(&result1.proof), &result2.chain_hash
        ).unwrap();
        assert!(valid2);

        // Step 3: Chain to step 2
        let ctx3 = "ctx_chain_step3";
        let ts3 = "1700000022";
        let payload3 = r#"{"step":3}"#;

        let secret3 = ash_derive_client_secret(TEST_NONCE, ctx3, binding).unwrap();
        let result3 = ash_build_proof_unified(
            &secret3, ts3, binding, payload3, &[], Some(&result2.proof)
        ).unwrap();

        let valid3 = ash_verify_proof_unified(
            TEST_NONCE, ctx3, binding, ts3, payload3, &result3.proof,
            &[], "", Some(&result2.proof), &result3.chain_hash
        ).unwrap();
        assert!(valid3);

        // Verify chain integrity: step 3 should NOT verify with step 1's proof
        let invalid = ash_verify_proof_unified(
            TEST_NONCE, ctx3, binding, ts3, payload3, &result3.proof,
            &[], "", Some(&result1.proof), &result3.chain_hash  // Wrong previous proof
        ).unwrap();
        assert!(!invalid);
    }
}
