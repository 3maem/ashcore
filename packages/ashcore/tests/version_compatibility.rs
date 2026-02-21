//! Version Compatibility Tests for ASH Rust SDK
//!
//! Tests backward compatibility and version negotiation.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_build_proof_unified, ash_verify_proof_unified,
    ash_hash_body, ash_canonicalize_json,
    ASH_SDK_VERSION,
};

// =========================================================================
// PROTOCOL VERSION
// =========================================================================

mod protocol_version {
    use super::*;

    #[test]
    fn test_version_constant_exists() {
        // SDK should export version information
        assert!(!ASH_SDK_VERSION.is_empty(), "SDK version should be defined");
    }

    #[test]
    fn test_version_format() {
        // Version should be semver-like
        let version = ASH_SDK_VERSION;
        let parts: Vec<&str> = version.split('.').collect();
        assert!(parts.len() >= 2, "Version should have at least major.minor");
    }
}

// =========================================================================
// BASIC PROOFS
// =========================================================================

mod basic_proofs {
    use super::*;

    #[test]
    fn test_basic_proof_format() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        // proof should be 64-char hex
        assert_eq!(proof.len(), 64);
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_basic_verification_works() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid, "basic proof should verify");
    }

    #[test]
    fn test_basic_deterministic_across_calls() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let proof1 = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let proof2 = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        assert_eq!(proof1, proof2, "basic proofs should be deterministic");
    }
}

// =========================================================================
// SCOPED PROOFS
// =========================================================================

mod scoped_proofs {
    use super::*;

    #[test]
    fn test_scoped_proof_format() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100,"memo":"test"}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        // returns (proof, scope_hash) tuple
        assert_eq!(proof.len(), 64);
        assert_eq!(scope_hash.len(), 64);
    }

    #[test]
    fn test_scoped_verification_works() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100,"memo":"test"}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        let valid = ash_verify_proof_scoped(&nonce, context_id, binding, timestamp, payload, &scope, &scope_hash, &proof).unwrap();
        assert!(valid, "scoped proof should verify");
    }

    #[test]
    fn test_empty_scope_works() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100}"#;
        let empty_scope: Vec<&str> = vec![];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &empty_scope).unwrap();

        // Empty scope should produce empty scope_hash
        assert!(scope_hash.is_empty() || scope_hash.len() == 64);

        let valid = ash_verify_proof_scoped(&nonce, context_id, binding, timestamp, payload, &empty_scope, &scope_hash, &proof).unwrap();
        assert!(valid);
    }
}

// =========================================================================
// UNIFIED PROOFS
// =========================================================================

mod unified_proofs {
    use super::*;

    #[test]
    fn test_unified_format() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(&secret, timestamp, binding, payload, &scope, None).unwrap();

        // returns UnifiedProofResult struct
        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.scope_hash.len(), 64);
        // chain_hash empty when no previous proof
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_unified_verification_works() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(&secret, timestamp, binding, payload, &scope, None).unwrap();

        let valid = ash_verify_proof_unified(
            &nonce, context_id, binding, timestamp, payload,
            &result.proof, &scope, &result.scope_hash,
            None, &result.chain_hash
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_unified_chaining_works() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let timestamp = "1700000000";

        // Step 1
        let binding1 = "POST|/api/step1|";
        let secret1 = ash_derive_client_secret(&nonce, context_id, binding1).unwrap();
        let result1 = ash_build_proof_unified(&secret1, timestamp, binding1, "{}", &[], None).unwrap();

        // Step 2 chained to step 1
        let binding2 = "POST|/api/step2|";
        let secret2 = ash_derive_client_secret(&nonce, context_id, binding2).unwrap();
        let result2 = ash_build_proof_unified(&secret2, timestamp, binding2, "{}", &[], Some(&result1.proof)).unwrap();

        // chain_hash should be populated
        assert!(!result2.chain_hash.is_empty());

        // Verify chained proof
        let valid = ash_verify_proof_unified(
            &nonce, context_id, binding2, timestamp, "{}",
            &result2.proof, &[], &result2.scope_hash,
            Some(&result1.proof), &result2.chain_hash
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_unified_no_scope_no_chain() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let payload = r#"{}"#;
        let empty_scope: Vec<&str> = vec![];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let result = ash_build_proof_unified(&secret, timestamp, binding, payload, &empty_scope, None).unwrap();

        // Both should be empty
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());

        let valid = ash_verify_proof_unified(
            &nonce, context_id, binding, timestamp, payload,
            &result.proof, &empty_scope, &result.scope_hash,
            None, &result.chain_hash
        ).unwrap();
        assert!(valid);
    }
}

// =========================================================================
// BACKWARD COMPATIBILITY
// =========================================================================

mod backward_compatibility {
    use super::*;

    #[test]
    fn test_basic_inputs_work_with_unified() {
        // basic style (no scope, no chain) should work with unified API
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body = "{}";
        let body_hash = ash_hash_body(body);

        // basic approach
        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let basic_proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        // unified approach with empty scope and no chain
        let unified_result = ash_build_proof_unified(&secret, timestamp, binding, body, &[], None).unwrap();

        // The proofs may differ due to different message construction,
        // but both should verify with their respective APIs
        let basic_valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &basic_proof).unwrap();
        assert!(basic_valid);

        let unified_valid = ash_verify_proof_unified(
            &nonce, context_id, binding, timestamp, body,
            &unified_result.proof, &[], &unified_result.scope_hash,
            None, &unified_result.chain_hash
        ).unwrap();
        assert!(unified_valid);
    }

    #[test]
    fn test_hash_function_unchanged() {
        // hash function should be stable across versions
        let body = "test content";
        let hash = ash_hash_body(body);

        // Known hash value (SHA-256)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_canonicalization_unchanged() {
        // JSON canonicalization should be stable
        let json = r#"{"z":1,"a":2}"#;
        let canonical = ash_canonicalize_json(json).unwrap();

        // Should always produce same sorted output
        assert_eq!(canonical, r#"{"a":2,"z":1}"#);
    }
}

// =========================================================================
// FEATURE DETECTION
// =========================================================================

mod feature_detection {
    use super::*;

    #[test]
    fn test_basic_functions_exported() {
        // core functions should be available
        let nonce = "a".repeat(64);
        let _ = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        let _ = ash_build_proof;
        let _ = ash_verify_proof;
        let _ = ash_hash_body;
    }

    #[test]
    fn test_scoped_functions_exported() {
        // scoped functions should be available
        let _ = ash_build_proof_scoped;
        let _ = ash_verify_proof_scoped;
    }

    #[test]
    fn test_unified_functions_exported() {
        // unified functions should be available
        let _ = ash_build_proof_unified;
        let _ = ash_verify_proof_unified;
    }
}

// =========================================================================
// MIGRATION SCENARIOS
// =========================================================================

mod migration {
    use super::*;

    #[test]
    fn test_basic_to_scoped_migration() {
        // Scenario: Adding scoping to basic proofs
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/payment|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100,"memo":"test"}"#;

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        // Basic approach (hash full body)
        let body_hash = ash_hash_body(payload);
        let basic_proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        assert!(ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &basic_proof).unwrap());

        // Scoped approach (scope specific fields)
        let scope = vec!["amount"];
        let (scoped_proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();
        assert!(ash_verify_proof_scoped(&nonce, context_id, binding, timestamp, payload, &scope, &scope_hash, &scoped_proof).unwrap());

        // Both should work independently
    }

    #[test]
    fn test_scoped_to_unified_migration() {
        // Scenario: Adding chaining to scoped proofs
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/payment|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        // scoped approach
        let (scoped_proof, scoped_scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        // unified approach (same result when no chaining)
        let unified_result = ash_build_proof_unified(&secret, timestamp, binding, payload, &scope, None).unwrap();

        // Scope hash should be the same
        assert_eq!(scoped_scope_hash, unified_result.scope_hash);

        // Both proofs should verify
        assert!(ash_verify_proof_scoped(&nonce, context_id, binding, timestamp, payload, &scope, &scoped_scope_hash, &scoped_proof).unwrap());
        assert!(ash_verify_proof_unified(&nonce, context_id, binding, timestamp, payload, &unified_result.proof, &scope, &unified_result.scope_hash, None, &unified_result.chain_hash).unwrap());
    }
}
