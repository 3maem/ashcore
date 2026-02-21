//! Property-Based Tests for ASH Rust SDK
//!
//! Tests mathematical invariants and properties that should always hold.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_timing_safe_equal,
    ash_build_proof_scoped,
};
use std::collections::HashSet;

// =========================================================================
// HASH PROPERTIES
// =========================================================================

mod hash_properties {
    use super::*;

    #[test]
    fn test_hash_determinism() {
        // Property: hash(x) == hash(x) for all x
        let long_input = "x".repeat(10000);
        let inputs = [
            "",
            "a",
            "hello world",
            r#"{"key":"value"}"#,
            long_input.as_str(),
        ];

        for input in inputs {
            let hash1 = ash_hash_body(input);
            let hash2 = ash_hash_body(input);
            assert_eq!(hash1, hash2, "Hash should be deterministic for: {}", input);
        }
    }

    #[test]
    fn test_hash_avalanche_effect() {
        // Property: Small change in input -> significant change in output
        let base = "test input string";
        let base_hash = ash_hash_body(base);

        let variations = [
            "Test input string",  // Capital T
            "test input string ", // Added space
            "test input strings", // Added s
            "test input strinG",  // Capital G
        ];

        for var in variations {
            let var_hash = ash_hash_body(var);

            // Count differing characters
            let differences: usize = base_hash.chars()
                .zip(var_hash.chars())
                .filter(|(a, b)| a != b)
                .count();

            // Should differ in many positions (avalanche effect)
            assert!(differences > 20, "Avalanche effect not seen for: {}", var);
        }
    }

    #[test]
    fn test_hash_length_consistency() {
        // Property: |hash(x)| = 64 for all x
        let inputs = vec![
            "".to_string(),
            "a".to_string(),
            "ab".to_string(),
            "abc".to_string(),
            "x".repeat(100),
            "x".repeat(1000),
            "x".repeat(10000),
        ];

        for input in &inputs {
            let hash = ash_hash_body(input);
            assert_eq!(hash.len(), 64, "Hash length should always be 64");
        }
    }

    #[test]
    fn test_hash_uniqueness() {
        // Property: hash(x) != hash(y) for x != y (with overwhelming probability)
        let inputs: Vec<String> = (0..1000).map(|i| format!("input_{}", i)).collect();
        let hashes: HashSet<String> = inputs.iter().map(|s| ash_hash_body(s)).collect();

        assert_eq!(hashes.len(), inputs.len(), "All hashes should be unique");
    }

    #[test]
    fn test_hash_hex_format() {
        // Property: hash output is valid lowercase hex
        for i in 0..100 {
            let hash = ash_hash_body(&format!("test_{}", i));
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }
}

// =========================================================================
// PROOF PROPERTIES
// =========================================================================

mod proof_properties {
    use super::*;

    #[test]
    fn test_proof_soundness() {
        // Property: Valid proof always verifies
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        for _ in 0..100 {
            let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
            assert!(valid, "Valid proof should always verify");
        }
    }

    #[test]
    fn test_proof_completeness() {
        // Property: Only correct proof verifies
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let correct_proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        // Generate many wrong proofs
        for i in 0..100 {
            let wrong_proof = format!("{:064x}", i);
            if wrong_proof != correct_proof {
                let result = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &wrong_proof);
                match result {
                    Ok(valid) => assert!(!valid, "Wrong proof should not verify"),
                    Err(_) => {} // Error is also acceptable
                }
            }
        }
    }

    #[test]
    fn test_proof_determinism() {
        // Property: Same inputs produce same proof
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let proofs: HashSet<String> = (0..100)
            .map(|_| ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap())
            .collect();

        assert_eq!(proofs.len(), 1, "Same inputs should produce same proof");
    }

    #[test]
    fn test_proof_sensitivity_to_timestamp() {
        // Property: Different timestamps -> different proofs
        let nonce = "a".repeat(64);
        let binding = "POST|/api|";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, "ctx", binding).unwrap();

        let proofs: HashSet<String> = (0..100)
            .map(|i| {
                let ts = format!("{}", 1700000000 + i);
                ash_build_proof(&secret, &ts, binding, &body_hash).unwrap()
            })
            .collect();

        assert_eq!(proofs.len(), 100, "Different timestamps should produce different proofs");
    }

    #[test]
    fn test_proof_sensitivity_to_body() {
        // Property: Different bodies -> different proofs
        let nonce = "a".repeat(64);
        let binding = "POST|/api|";
        let timestamp = "1700000000";

        let secret = ash_derive_client_secret(&nonce, "ctx", binding).unwrap();

        let proofs: HashSet<String> = (0..100)
            .map(|i| {
                let body_hash = ash_hash_body(&format!("body_{}", i));
                ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap()
            })
            .collect();

        assert_eq!(proofs.len(), 100, "Different bodies should produce different proofs");
    }
}

// =========================================================================
// CANONICALIZATION PROPERTIES
// =========================================================================

mod canonicalization_properties {
    use super::*;

    #[test]
    fn test_json_idempotence() {
        // Property: canon(canon(x)) == canon(x)
        let inputs = [
            r#"{"a":1}"#,
            r#"{"z":1,"a":2}"#,
            r#"{"nested":{"z":1,"a":2}}"#,
            r#"{"arr":[3,1,4]}"#,
            r#"{"mixed":{"arr":[1,2],"val":true}}"#,
        ];

        for input in inputs {
            let once = ash_canonicalize_json(input).unwrap();
            let twice = ash_canonicalize_json(&once).unwrap();
            assert_eq!(once, twice, "Canonicalization should be idempotent for: {}", input);
        }
    }

    #[test]
    fn test_json_determinism() {
        // Property: Same input -> same output
        let input = r#"{"z":1,"a":2,"m":{"b":3,"a":4}}"#;

        let results: HashSet<String> = (0..100)
            .map(|_| ash_canonicalize_json(input).unwrap())
            .collect();

        assert_eq!(results.len(), 1, "Canonicalization should be deterministic");
    }

    #[test]
    fn test_json_semantic_preservation() {
        // Property: Canonicalization preserves JSON semantics
        let input = r#"{"z":1,"a":[3,1,4],"m":{"x":true,"y":null}}"#;
        let canonical = ash_canonicalize_json(input).unwrap();

        let original: serde_json::Value = serde_json::from_str(input).unwrap();
        let canonicalized: serde_json::Value = serde_json::from_str(&canonical).unwrap();

        assert_eq!(original, canonicalized, "Semantics should be preserved");
    }

    #[test]
    fn test_query_idempotence() {
        // Property: canon(canon(x)) == canon(x)
        let inputs = [
            "a=1&b=2",
            "z=3&a=1&m=2",
            "key=value",
            "a=1&a=2&a=3",
        ];

        for input in inputs {
            let once = ash_canonicalize_query(input).unwrap();
            let twice = ash_canonicalize_query(&once).unwrap();
            assert_eq!(once, twice, "Query canonicalization should be idempotent");
        }
    }

    #[test]
    fn test_query_determinism() {
        // Property: Same input -> same output
        let input = "z=3&a=1&m=2&b=4";

        let results: HashSet<String> = (0..100)
            .map(|_| ash_canonicalize_query(input).unwrap())
            .collect();

        assert_eq!(results.len(), 1, "Query canonicalization should be deterministic");
    }

    #[test]
    fn test_query_order_independence() {
        // Property: Different orders of same params -> same output
        let orderings = [
            "a=1&b=2&c=3",
            "b=2&a=1&c=3",
            "c=3&a=1&b=2",
            "c=3&b=2&a=1",
        ];

        let results: HashSet<String> = orderings
            .iter()
            .map(|q| ash_canonicalize_query(q).unwrap())
            .collect();

        assert_eq!(results.len(), 1, "Different orderings should produce same output");
    }
}

// =========================================================================
// SCOPE PROPERTIES
// =========================================================================

mod scope_properties {
    use super::*;

    #[test]
    fn test_scope_order_independence() {
        // Property: Scope order doesn't affect result
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let payload = r#"{"a":1,"b":2,"c":3}"#;

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let scope1 = vec!["a", "b", "c"];
        let scope2 = vec!["c", "b", "a"];
        let scope3 = vec!["b", "a", "c"];

        let result1 = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope1).unwrap();
        let result2 = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope2).unwrap();
        let result3 = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope3).unwrap();

        assert_eq!(result1, result2, "Scope order should not affect result");
        assert_eq!(result2, result3, "Scope order should not affect result");
    }

    #[test]
    fn test_scope_deduplication() {
        // Property: Duplicate scope fields are deduplicated
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let payload = r#"{"a":1,"b":2}"#;

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let scope_single = vec!["a"];
        let scope_dup = vec!["a", "a", "a"];

        let result_single = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope_single).unwrap();
        let result_dup = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope_dup).unwrap();

        assert_eq!(result_single, result_dup, "Duplicates should be deduplicated");
    }

    #[test]
    fn test_empty_scope_consistency() {
        // Property: Empty scope produces consistent result
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let payload = r#"{"a":1}"#;

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let empty_scope: Vec<&str> = vec![];

        let results: HashSet<(String, String)> = (0..100)
            .map(|_| ash_build_proof_scoped(&secret, timestamp, binding, payload, &empty_scope).unwrap())
            .collect();

        assert_eq!(results.len(), 1, "Empty scope should produce consistent result");
    }
}

// =========================================================================
// TIMING SAFE EQUALITY PROPERTIES
// =========================================================================

mod timing_properties {
    use super::*;

    #[test]
    fn test_equality_reflexivity() {
        // Property: x == x for all x
        let values = [
            b"".to_vec(),
            b"a".to_vec(),
            b"abc".to_vec(),
            b"x".repeat(100),
        ];

        for v in values {
            assert!(ash_timing_safe_equal(&v, &v), "Reflexivity failed");
        }
    }

    #[test]
    fn test_equality_symmetry() {
        // Property: x == y implies y == x
        let pairs = [
            (b"abc".to_vec(), b"abc".to_vec()),
            (b"abc".to_vec(), b"abd".to_vec()),
            (b"short".to_vec(), b"longer".to_vec()),
        ];

        for (a, b) in pairs {
            let ab = ash_timing_safe_equal(&a, &b);
            let ba = ash_timing_safe_equal(&b, &a);
            assert_eq!(ab, ba, "Symmetry failed for {:?} and {:?}", a, b);
        }
    }

    #[test]
    fn test_equality_transitivity() {
        // Property: x == y and y == z implies x == z
        let a = b"test";
        let b = b"test";
        let c = b"test";

        assert!(ash_timing_safe_equal(a, b));
        assert!(ash_timing_safe_equal(b, c));
        assert!(ash_timing_safe_equal(a, c), "Transitivity failed");
    }

    #[test]
    fn test_inequality_for_different() {
        // Property: x != y when x and y differ
        let pairs: Vec<(&[u8], &[u8])> = vec![
            (b"abc", b"abd"),
            (b"abc", b"ABC"),
            (b"abc", b"abcd"),
            (b"", b"a"),
        ];

        for (a, b) in pairs {
            assert!(!ash_timing_safe_equal(a, b), "Should be unequal: {:?} vs {:?}", a, b);
        }
    }
}

// =========================================================================
// MATHEMATICAL INVARIANTS
// =========================================================================

mod mathematical_invariants {
    use super::*;

    #[test]
    fn test_secret_derivation_is_function() {
        // Property: Same inputs always produce same output (function property)
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";

        let secrets: HashSet<String> = (0..100)
            .map(|_| ash_derive_client_secret(&nonce, context_id, binding).unwrap())
            .collect();

        assert_eq!(secrets.len(), 1, "Secret derivation should be a function");
    }

    #[test]
    fn test_hash_is_function() {
        // Property: hash is a function (same input -> same output)
        let input = "test content";

        let hashes: HashSet<String> = (0..100)
            .map(|_| ash_hash_body(input))
            .collect();

        assert_eq!(hashes.len(), 1, "Hash should be a function");
    }

    #[test]
    fn test_proof_build_verify_inverse() {
        // Property: verify(build(x)) == true (build and verify are inverses for valid input)
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        for i in 0..100 {
            let timestamp = format!("{}", 1700000000 + i);
            let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
            let valid = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &proof).unwrap();
            assert!(valid, "Build and verify should be inverses");
        }
    }
}
