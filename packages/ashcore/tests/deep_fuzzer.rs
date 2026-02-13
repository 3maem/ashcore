//! Deep Fuzzer Tests for ASH Rust SDK
//!
//! High-iteration fuzzing tests with randomized inputs across all API surfaces.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query, ash_canonicalize_urlencoded,
    ash_hash_body, ash_normalize_binding,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_timing_safe_equal,
};
use rand::Rng;
use std::collections::HashSet;

// High iteration counts for deep fuzzing
const FUZZ_RUNS: usize = 1000;
const CRYPTO_RUNS: usize = 500;

fn random_hex(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| format!("{:x}", rng.gen::<u8>() % 16)).collect()
}

fn random_alphanumeric(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    (0..len).map(|_| chars[rng.gen::<usize>() % chars.len()]).collect()
}

fn random_method() -> &'static str {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    methods[rand::thread_rng().gen::<usize>() % methods.len()]
}

fn random_path() -> String {
    let mut rng = rand::thread_rng();
    let depth = rng.gen_range(1..=5);
    let parts: Vec<String> = (0..depth).map(|_| random_alphanumeric(rng.gen_range(1..=10))).collect();
    format!("/{}", parts.join("/"))
}

fn random_query() -> String {
    let mut rng = rand::thread_rng();
    let count = rng.gen_range(0..=5);
    let params: Vec<String> = (0..count)
        .map(|_| format!("{}={}", random_alphanumeric(rng.gen_range(1..=10)), random_alphanumeric(rng.gen_range(0..=20))))
        .collect();
    params.join("&")
}

// =========================================================================
// PROOF GENERATION/VERIFICATION FUZZING
// =========================================================================

mod proof_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_proof_roundtrip() {
        // Property: verify(build(inputs)) === true
        for _ in 0..FUZZ_RUNS {
            let nonce = random_hex(64);
            let context_id = format!("ctx_{}", random_alphanumeric(20));
            let method = random_method();
            let path = random_path();
            let query = random_query();
            let body_hash = random_hex(64);
            let timestamp = chrono::Utc::now().timestamp().to_string();

            let binding = ash_normalize_binding(method, &path, &query).unwrap();
            let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
            let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

            let is_valid = ash_verify_proof(&nonce, &context_id, &binding, &timestamp, &body_hash, &proof).unwrap();
            assert!(is_valid, "Valid proof should always verify");
        }
    }

    #[test]
    fn test_fuzz_wrong_nonce_never_verifies() {
        for _ in 0..CRYPTO_RUNS {
            let nonce = random_hex(64);
            let wrong_nonce = random_hex(64);
            let context_id = format!("ctx_{}", random_alphanumeric(20));
            let binding = "POST|/api/test|";
            let body_hash = random_hex(64);
            let timestamp = chrono::Utc::now().timestamp().to_string();

            let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
            let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

            if nonce != wrong_nonce {
                let is_valid = ash_verify_proof(&wrong_nonce, &context_id, binding, &timestamp, &body_hash, &proof).unwrap();
                assert!(!is_valid, "Wrong nonce should never verify");
            }
        }
    }

    #[test]
    fn test_fuzz_wrong_context_never_verifies() {
        for _ in 0..CRYPTO_RUNS {
            let nonce = random_hex(64);
            let context_id = format!("ctx_{}", random_alphanumeric(20));
            let wrong_context = format!("ctx_{}", random_alphanumeric(20));
            let binding = "POST|/api/test|";
            let body_hash = random_hex(64);
            let timestamp = chrono::Utc::now().timestamp().to_string();

            let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
            let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

            if context_id != wrong_context {
                let is_valid = ash_verify_proof(&nonce, &wrong_context, binding, &timestamp, &body_hash, &proof).unwrap();
                assert!(!is_valid, "Wrong context should never verify");
            }
        }
    }

    #[test]
    fn test_fuzz_wrong_body_never_verifies() {
        for _ in 0..CRYPTO_RUNS {
            let nonce = random_hex(64);
            let context_id = format!("ctx_{}", random_alphanumeric(20));
            let binding = "POST|/api/test|";
            let body_hash = random_hex(64);
            let wrong_body_hash = random_hex(64);
            let timestamp = chrono::Utc::now().timestamp().to_string();

            let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
            let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

            if body_hash != wrong_body_hash {
                let is_valid = ash_verify_proof(&nonce, &context_id, binding, &timestamp, &wrong_body_hash, &proof).unwrap();
                assert!(!is_valid, "Wrong body hash should never verify");
            }
        }
    }

    #[test]
    fn test_fuzz_all_proofs_unique() {
        let mut proofs = HashSet::new();
        let nonce = random_hex(64);

        for i in 0..FUZZ_RUNS {
            let context_id = format!("ctx_{}", i);
            let binding = "POST|/api/test|";
            let body_hash = random_hex(64);
            let timestamp = (chrono::Utc::now().timestamp() + i as i64).to_string();

            let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
            let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

            proofs.insert(proof);
        }

        assert_eq!(proofs.len(), FUZZ_RUNS, "All proofs should be unique");
    }
}

// =========================================================================
// JSON CANONICALIZATION FUZZING
// =========================================================================

mod json_fuzzing {
    use super::*;

    fn random_json_value(depth: usize) -> String {
        let mut rng = rand::thread_rng();
        if depth == 0 {
            match rng.gen_range(0..4) {
                0 => format!("\"{}\"", random_alphanumeric(rng.gen_range(1..=20))),
                1 => rng.gen_range(-1000..1000).to_string(),
                2 => (rng.gen::<bool>()).to_string(),
                _ => "null".to_string(),
            }
        } else {
            match rng.gen_range(0..6) {
                0 => format!("\"{}\"", random_alphanumeric(rng.gen_range(1..=20))),
                1 => rng.gen_range(-1000..1000).to_string(),
                2 => (rng.gen::<bool>()).to_string(),
                3 => "null".to_string(),
                4 => {
                    let count = rng.gen_range(0..=3);
                    let items: Vec<String> = (0..count).map(|_| random_json_value(depth - 1)).collect();
                    format!("[{}]", items.join(","))
                }
                _ => {
                    let count = rng.gen_range(1..=3);
                    let pairs: Vec<String> = (0..count)
                        .map(|_| format!("\"{}\":{}", random_alphanumeric(rng.gen_range(1..=10)), random_json_value(depth - 1)))
                        .collect();
                    format!("{{{}}}", pairs.join(","))
                }
            }
        }
    }

    #[test]
    fn test_fuzz_json_canonicalization_idempotent() {
        for _ in 0..FUZZ_RUNS {
            let json = random_json_value(3);
            if let Ok(canonical) = ash_canonicalize_json(&json) {
                let double_canonical = ash_canonicalize_json(&canonical).unwrap();
                assert_eq!(canonical, double_canonical, "Canonicalization should be idempotent");
            }
        }
    }

    #[test]
    fn test_fuzz_json_reordering_produces_same_hash() {
        for _ in 0..CRYPTO_RUNS {
            let keys: Vec<String> = (0..5).map(|_| random_alphanumeric(5)).collect();
            let values: Vec<i32> = (0..5).map(|_| rand::thread_rng().gen_range(0..100)).collect();

            // Create JSON with keys in random orders
            let mut pairs: Vec<(String, i32)> = keys.iter().cloned().zip(values.iter().cloned()).collect();
            let json1 = format!("{{{}}}", pairs.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect::<Vec<_>>().join(","));

            pairs.reverse();
            let json2 = format!("{{{}}}", pairs.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect::<Vec<_>>().join(","));

            let canonical1 = ash_canonicalize_json(&json1).unwrap();
            let canonical2 = ash_canonicalize_json(&json2).unwrap();

            assert_eq!(canonical1, canonical2, "Different key orders should produce same canonical form");
        }
    }

    #[test]
    fn test_fuzz_json_never_crashes() {
        for _ in 0..FUZZ_RUNS {
            let random_str: String = (0..100).map(|_| rand::thread_rng().gen::<char>()).collect();
            // Should not panic, just return Ok or Err
            let _ = ash_canonicalize_json(&random_str);
        }
    }
}

// =========================================================================
// QUERY STRING FUZZING
// =========================================================================

mod query_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_query_canonicalization_idempotent() {
        for _ in 0..FUZZ_RUNS {
            let query = random_query();
            if !query.is_empty() {
                let canonical = ash_canonicalize_query(&query).unwrap();
                let double_canonical = ash_canonicalize_query(&canonical).unwrap();
                assert_eq!(canonical, double_canonical, "Query canonicalization should be idempotent");
            }
        }
    }

    #[test]
    fn test_fuzz_query_order_independence() {
        for _ in 0..CRYPTO_RUNS {
            let mut rng = rand::thread_rng();
            let params: Vec<(String, String)> = (0..rng.gen_range(2..=5))
                .map(|_| (random_alphanumeric(5), random_alphanumeric(10)))
                .collect();

            let query1: String = params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");

            let mut reversed = params.clone();
            reversed.reverse();
            let query2: String = reversed.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");

            let canonical1 = ash_canonicalize_query(&query1).unwrap();
            let canonical2 = ash_canonicalize_query(&query2).unwrap();

            assert_eq!(canonical1, canonical2, "Different param orders should produce same canonical form");
        }
    }

    #[test]
    fn test_fuzz_query_never_crashes() {
        for _ in 0..FUZZ_RUNS {
            let random_str: String = (0..50).map(|_| rand::thread_rng().gen::<char>()).collect();
            let _ = ash_canonicalize_query(&random_str);
        }
    }
}

// =========================================================================
// BINDING NORMALIZATION FUZZING
// =========================================================================

mod binding_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_binding_normalization_idempotent() {
        for _ in 0..FUZZ_RUNS {
            let method = random_method();
            let path = random_path();
            let query = random_query();

            if let Ok(binding) = ash_normalize_binding(method, &path, &query) {
                // Parse the binding and re-normalize
                let parts: Vec<&str> = binding.split('|').collect();
                if parts.len() >= 3 {
                    let re_normalized = ash_normalize_binding(parts[0], parts[1], parts[2]).unwrap();
                    assert_eq!(binding, re_normalized, "Binding normalization should be idempotent");
                }
            }
        }
    }

    #[test]
    fn test_fuzz_binding_case_insensitive_method() {
        let methods = ["get", "GET", "Get", "gEt"];

        for _ in 0..CRYPTO_RUNS {
            let path = random_path();
            let query = random_query();

            let bindings: Vec<String> = methods
                .iter()
                .filter_map(|m| ash_normalize_binding(m, &path, &query).ok())
                .collect();

            // All should produce the same result
            let first = &bindings[0];
            for binding in &bindings {
                assert_eq!(binding, first, "Method case should not affect binding");
            }
        }
    }

    #[test]
    fn test_fuzz_binding_never_crashes() {
        for _ in 0..FUZZ_RUNS {
            let random_method: String = (0..10).map(|_| rand::thread_rng().gen::<char>()).collect();
            let random_path: String = (0..50).map(|_| rand::thread_rng().gen::<char>()).collect();
            let random_query: String = (0..30).map(|_| rand::thread_rng().gen::<char>()).collect();
            let _ = ash_normalize_binding(&random_method, &random_path, &random_query);
        }
    }
}

// =========================================================================
// HASH FUNCTION FUZZING
// =========================================================================

mod hash_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_hash_deterministic() {
        for _ in 0..FUZZ_RUNS {
            let body: String = (0..rand::thread_rng().gen_range(0..=1000))
                .map(|_| rand::thread_rng().gen::<char>())
                .collect();

            let hash1 = ash_hash_body(&body);
            let hash2 = ash_hash_body(&body);

            assert_eq!(hash1, hash2, "Hash should be deterministic");
        }
    }

    #[test]
    fn test_fuzz_hash_unique() {
        let mut hashes = HashSet::new();

        for i in 0..FUZZ_RUNS {
            let body = format!("unique_body_{}", i);
            let hash = ash_hash_body(&body);
            hashes.insert(hash);
        }

        assert_eq!(hashes.len(), FUZZ_RUNS, "All hashes should be unique");
    }

    #[test]
    fn test_fuzz_hash_length_constant() {
        for _ in 0..FUZZ_RUNS {
            let len = rand::thread_rng().gen_range(0..=10000);
            let body: String = (0..len).map(|_| rand::thread_rng().gen::<char>()).collect();
            let hash = ash_hash_body(&body);
            assert_eq!(hash.len(), 64, "Hash length should always be 64");
        }
    }

    #[test]
    fn test_fuzz_hash_hex_format() {
        for _ in 0..FUZZ_RUNS {
            let body = random_alphanumeric(rand::thread_rng().gen_range(1..=100));
            let hash = ash_hash_body(&body);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
                    "Hash should be lowercase hex");
        }
    }
}

// =========================================================================
// SCOPED PROOF FUZZING
// =========================================================================

mod scoped_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_scoped_proof_roundtrip() {
        for _ in 0..CRYPTO_RUNS {
            let nonce = random_hex(64);
            let context_id = format!("ctx_{}", random_alphanumeric(20));
            let binding = "POST|/api/test|";
            let timestamp = chrono::Utc::now().timestamp().to_string();

            // Generate random payload with known fields
            let fields: Vec<String> = (0..rand::thread_rng().gen_range(2..=5))
                .map(|_| random_alphanumeric(10))
                .collect();

            let payload = format!("{{{}}}",
                fields.iter()
                    .map(|f| format!("\"{}\":{}", f, rand::thread_rng().gen_range(0..1000)))
                    .collect::<Vec<_>>()
                    .join(",")
            );

            // Use subset of fields as scope
            let scope_count = rand::thread_rng().gen_range(1..=fields.len());
            let scope: Vec<&str> = fields.iter().take(scope_count).map(|s| s.as_str()).collect();

            let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
            let (proof, scope_hash) = ash_build_proof_scoped(&secret, &timestamp, binding, &payload, &scope).unwrap();

            let is_valid = ash_verify_proof_scoped(&nonce, &context_id, binding, &timestamp, &payload, &scope, &scope_hash, &proof).unwrap();
            assert!(is_valid, "Scoped proof should verify");
        }
    }
}

// =========================================================================
// TIMING SAFE COMPARISON FUZZING
// =========================================================================

mod timing_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_timing_safe_reflexive() {
        for _ in 0..FUZZ_RUNS {
            let len = rand::thread_rng().gen_range(1..=100);
            let data: Vec<u8> = (0..len).map(|_| rand::thread_rng().gen()).collect();
            assert!(ash_timing_safe_equal(&data, &data), "Value should equal itself");
        }
    }

    #[test]
    fn test_fuzz_timing_safe_symmetric() {
        for _ in 0..FUZZ_RUNS {
            let len = rand::thread_rng().gen_range(1..=100);
            let a: Vec<u8> = (0..len).map(|_| rand::thread_rng().gen()).collect();
            let b: Vec<u8> = (0..len).map(|_| rand::thread_rng().gen()).collect();

            let ab = ash_timing_safe_equal(&a, &b);
            let ba = ash_timing_safe_equal(&b, &a);
            assert_eq!(ab, ba, "Comparison should be symmetric");
        }
    }

    #[test]
    fn test_fuzz_timing_safe_different_lengths() {
        for _ in 0..FUZZ_RUNS {
            let len1 = rand::thread_rng().gen_range(1..=50);
            let len2 = rand::thread_rng().gen_range(51..=100);
            let a: Vec<u8> = (0..len1).map(|_| rand::thread_rng().gen()).collect();
            let b: Vec<u8> = (0..len2).map(|_| rand::thread_rng().gen()).collect();

            assert!(!ash_timing_safe_equal(&a, &b), "Different lengths should not be equal");
        }
    }
}

// =========================================================================
// URL-ENCODED FORM FUZZING
// =========================================================================

mod urlencoded_fuzzing {
    use super::*;

    #[test]
    fn test_fuzz_urlencoded_canonicalization_idempotent() {
        for _ in 0..FUZZ_RUNS {
            let params: Vec<String> = (0..rand::thread_rng().gen_range(1..=5))
                .map(|_| format!("{}={}", random_alphanumeric(10), random_alphanumeric(20)))
                .collect();
            let form_data = params.join("&");

            let canonical = ash_canonicalize_urlencoded(&form_data).unwrap();
            let double_canonical = ash_canonicalize_urlencoded(&canonical).unwrap();
            assert_eq!(canonical, double_canonical, "URL-encoded canonicalization should be idempotent");
        }
    }

    #[test]
    fn test_fuzz_urlencoded_never_crashes() {
        for _ in 0..FUZZ_RUNS {
            let random_str: String = (0..100).map(|_| rand::thread_rng().gen::<char>()).collect();
            let _ = ash_canonicalize_urlencoded(&random_str);
        }
    }
}
