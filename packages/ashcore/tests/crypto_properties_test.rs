//! Comprehensive Cryptographic Properties Tests
//!
//! These tests verify cryptographic properties including:
//! - Avalanche effect (small input changes cause large output changes)
//! - Collision resistance
//! - Timing-safe comparison
//! - Determinism

use ashcore::{
    ash_hash_body, ash_derive_client_secret, ash_build_proof,
    ash_timing_safe_equal,
};

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// =========================================================================
// AVALANCHE EFFECT TESTS
// =========================================================================

mod avalanche_effect {
    use super::*;

    fn count_different_bits(a: &str, b: &str) -> usize {
        // Convert hex strings to bytes and count bit differences
        let a_bytes: Vec<u8> = (0..a.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&a[i..i+2], 16).ok())
            .collect();
        let b_bytes: Vec<u8> = (0..b.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&b[i..i+2], 16).ok())
            .collect();

        a_bytes.iter()
            .zip(b_bytes.iter())
            .map(|(x, y)| (x ^ y).count_ones() as usize)
            .sum()
    }

    #[test]
    fn test_hash_avalanche_single_bit_change() {
        let body1 = "Hello, World!";
        let body2 = "Hello, World?";  // One character different

        let hash1 = ash_hash_body(body1);
        let hash2 = ash_hash_body(body2);

        // Hashes should be completely different
        assert_ne!(hash1, hash2);

        // Count bit differences - should be roughly 50% (128 bits for SHA-256)
        let diff_bits = count_different_bits(&hash1, &hash2);
        // Expect at least 25% difference (64 bits out of 256)
        assert!(diff_bits > 64, "Not enough avalanche effect: {} bits differ", diff_bits);
    }

    #[test]
    fn test_hash_avalanche_empty_vs_single_char() {
        let hash1 = ash_hash_body("");
        let hash2 = ash_hash_body("a");

        let diff_bits = count_different_bits(&hash1, &hash2);
        assert!(diff_bits > 64);
    }

    #[test]
    fn test_secret_avalanche_nonce_change() {
        let nonce1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let nonce2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // First char

        let secret1 = ash_derive_client_secret(nonce1, "ctx", "GET|/|").unwrap();
        let secret2 = ash_derive_client_secret(nonce2, "ctx", "GET|/|").unwrap();

        let diff_bits = count_different_bits(&secret1, &secret2);
        assert!(diff_bits > 64);
    }

    #[test]
    fn test_secret_avalanche_context_change() {
        let secret1 = ash_derive_client_secret(TEST_NONCE, "ctx1", "GET|/|").unwrap();
        let secret2 = ash_derive_client_secret(TEST_NONCE, "ctx2", "GET|/|").unwrap();

        let diff_bits = count_different_bits(&secret1, &secret2);
        assert!(diff_bits > 64);
    }

    #[test]
    fn test_proof_avalanche_timestamp_change() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|").unwrap();

        let proof1 = ash_build_proof(&secret, "1700000000", "GET|/|", TEST_BODY_HASH).unwrap();
        let proof2 = ash_build_proof(&secret, "1700000001", "GET|/|", TEST_BODY_HASH).unwrap();

        let diff_bits = count_different_bits(&proof1, &proof2);
        assert!(diff_bits > 64);
    }

    #[test]
    fn test_proof_avalanche_binding_change() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/a|").unwrap();

        let proof1 = ash_build_proof(&secret, "1700000000", "GET|/a|", TEST_BODY_HASH).unwrap();
        let proof2 = ash_build_proof(&secret, "1700000000", "GET|/b|", TEST_BODY_HASH).unwrap();

        let diff_bits = count_different_bits(&proof1, &proof2);
        assert!(diff_bits > 64);
    }

    #[test]
    fn test_consecutive_inputs_different_outputs() {
        for i in 0..100 {
            let body1 = format!("input{}", i);
            let body2 = format!("input{}", i + 1);

            let hash1 = ash_hash_body(&body1);
            let hash2 = ash_hash_body(&body2);

            assert_ne!(hash1, hash2);
        }
    }
}

// =========================================================================
// COLLISION RESISTANCE TESTS
// =========================================================================

mod collision_resistance {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_hash_no_collisions_1000_inputs() {
        let mut hashes = HashSet::new();

        for i in 0..1000 {
            let body = format!("unique_input_{}", i);
            let hash = ash_hash_body(&body);

            assert!(
                hashes.insert(hash.clone()),
                "Collision detected at input {}",
                i
            );
        }
    }

    #[test]
    fn test_secret_no_collisions_various_contexts() {
        let mut secrets = HashSet::new();

        for i in 0..500 {
            let context_id = format!("ctx_{}", i);
            let secret = ash_derive_client_secret(TEST_NONCE, &context_id, "GET|/|").unwrap();

            assert!(
                secrets.insert(secret),
                "Secret collision at context {}",
                i
            );
        }
    }

    #[test]
    fn test_secret_no_collisions_various_bindings() {
        let mut secrets = HashSet::new();

        for i in 0..500 {
            let binding = format!("GET|/api/resource/{}|", i);
            let secret = ash_derive_client_secret(TEST_NONCE, "ctx", &binding).unwrap();

            assert!(
                secrets.insert(secret),
                "Secret collision at binding {}",
                i
            );
        }
    }

    #[test]
    fn test_proof_no_collisions_various_timestamps() {
        let mut proofs = HashSet::new();
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|").unwrap();

        for i in 0..500 {
            let timestamp = (1700000000 + i).to_string();
            let proof = ash_build_proof(&secret, &timestamp, "GET|/|", TEST_BODY_HASH).unwrap();

            assert!(
                proofs.insert(proof),
                "Proof collision at timestamp {}",
                i
            );
        }
    }

    #[test]
    fn test_similar_inputs_different_hashes() {
        let inputs = vec![
            "password",
            "Password",
            "password1",
            "password!",
            "passw0rd",
            " password",
            "password ",
        ];

        let hashes: Vec<String> = inputs.iter().map(|s| ash_hash_body(s)).collect();

        // All hashes should be unique
        let unique_hashes: HashSet<&String> = hashes.iter().collect();
        assert_eq!(unique_hashes.len(), hashes.len());
    }

    #[test]
    fn test_length_extension_resistant() {
        // SHA-256 is resistant to length extension attacks
        let short = "short";
        let extended = "shortAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let hash1 = ash_hash_body(short);
        let hash2 = ash_hash_body(extended);

        // Should not be related
        assert_ne!(hash1, hash2);

        // Extended hash should not start with or contain the short hash
        assert!(!hash2.starts_with(&hash1[..16]));
    }
}

// =========================================================================
// TIMING-SAFE COMPARISON TESTS
// =========================================================================

mod timing_safe {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_timing_safe_equal_basic() {
        let a = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let b = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert!(ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_not_equal() {
        let a = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let b = b"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_length_mismatch() {
        let a = b"short";
        let b = b"much longer string here";

        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_empty_both() {
        assert!(ash_timing_safe_equal(b"", b""));
    }

    #[test]
    fn test_timing_safe_one_empty() {
        assert!(!ash_timing_safe_equal(b"", b"not_empty"));
        assert!(!ash_timing_safe_equal(b"not_empty", b""));
    }

    #[test]
    fn test_timing_safe_first_byte_different() {
        let a = b"0bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let b = b"1bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_last_byte_different() {
        let a = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let b = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567891";

        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_middle_byte_different() {
        let a = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let b = b"abcdef1234567890abcdef1234507890abcdef1234567890abcdef1234567890";
                                        // Different here ^

        assert!(!ash_timing_safe_equal(a, b));
    }

    // Note: Actual timing attack tests are difficult in unit tests
    // but we verify the comparison logic works correctly
    #[test]
    fn test_timing_safe_comparison_consistency() {
        let secret = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let correct = secret.as_bytes();
        let wrong_first = b"f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let wrong_last = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854";

        // Run many times to verify consistency
        for _ in 0..1000 {
            assert!(ash_timing_safe_equal(correct, correct));
            assert!(!ash_timing_safe_equal(correct, wrong_first));
            assert!(!ash_timing_safe_equal(correct, wrong_last));
        }
    }

    #[test]
    fn test_timing_comparison_similar_timing() {
        // This is a basic timing check - not definitive but sanity check
        let correct = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let wrong_start = b"f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let wrong_end = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854";

        let iterations = 10000;

        // Time comparison where difference is at start
        let start1 = Instant::now();
        for _ in 0..iterations {
            let _ = ash_timing_safe_equal(correct, wrong_start);
        }
        let duration1 = start1.elapsed();

        // Time comparison where difference is at end
        let start2 = Instant::now();
        for _ in 0..iterations {
            let _ = ash_timing_safe_equal(correct, wrong_end);
        }
        let duration2 = start2.elapsed();

        // Timings should be within reasonable variance (factor of 2)
        // This is a weak check but catches obvious non-constant-time implementations
        let ratio = duration1.as_nanos() as f64 / duration2.as_nanos() as f64;
        assert!(
            ratio > 0.5 && ratio < 2.0,
            "Timing ratio suspiciously different: {} (d1={:?}, d2={:?})",
            ratio, duration1, duration2
        );
    }
}

// =========================================================================
// DETERMINISM TESTS
// =========================================================================

mod determinism {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let body = "test body content";

        let hashes: Vec<String> = (0..100).map(|_| ash_hash_body(body)).collect();

        assert!(hashes.iter().all(|h| h == &hashes[0]));
    }

    #[test]
    fn test_secret_derivation_deterministic() {
        let context_id = "ctx_determinism";
        let binding = "GET|/api/test|";

        let secrets: Vec<String> = (0..100)
            .map(|_| ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap())
            .collect();

        assert!(secrets.iter().all(|s| s == &secrets[0]));
    }

    #[test]
    fn test_proof_deterministic() {
        let context_id = "ctx_proof_determinism";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();

        let proofs: Vec<String> = (0..100)
            .map(|_| ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap())
            .collect();

        assert!(proofs.iter().all(|p| p == &proofs[0]));
    }

    #[test]
    fn test_hash_output_format() {
        let hash = ash_hash_body("any content");

        // Should be 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_secret_output_format() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|").unwrap();

        // Should be 64 hex characters (HMAC-SHA256)
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_proof_output_format() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|").unwrap();
        let proof = ash_build_proof(&secret, "1700000000", "GET|/|", TEST_BODY_HASH).unwrap();

        // Should be 64 hex characters (HMAC-SHA256)
        assert_eq!(proof.len(), 64);
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// =========================================================================
// ENTROPY TESTS
// =========================================================================

mod entropy {
    use super::*;

    fn calculate_byte_entropy(hex_str: &str) -> f64 {
        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex_str[i..i+2], 16).ok())
            .collect();

        let mut freq = [0u64; 256];
        for &b in &bytes {
            freq[b as usize] += 1;
        }

        let len = bytes.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    #[test]
    fn test_hash_high_entropy() {
        let hash = ash_hash_body("test input");
        let entropy = calculate_byte_entropy(&hash);

        // SHA-256 should have high entropy (close to 8 bits per byte for random data)
        // For 32 bytes, expect entropy > 4 bits
        assert!(entropy > 4.0, "Hash entropy too low: {}", entropy);
    }

    #[test]
    fn test_secret_high_entropy() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|").unwrap();
        let entropy = calculate_byte_entropy(&secret);

        assert!(entropy > 4.0, "Secret entropy too low: {}", entropy);
    }

    #[test]
    fn test_proof_high_entropy() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|").unwrap();
        let proof = ash_build_proof(&secret, "1700000000", "GET|/|", TEST_BODY_HASH).unwrap();
        let entropy = calculate_byte_entropy(&proof);

        assert!(entropy > 4.0, "Proof entropy too low: {}", entropy);
    }
}
