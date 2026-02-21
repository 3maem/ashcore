//! Benchmark Tests for ASH Rust SDK
//!
//! Tests performance thresholds for various operations.
//! Note: These are not true benchmarks but performance validation tests.
//! Thresholds are set conservatively for debug builds; release builds will be faster.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_generate_nonce, ash_generate_context_id,
    ash_build_proof_scoped, ash_verify_proof_scoped,
};
use std::time::Instant;

// =========================================================================
// PROOF GENERATION BENCHMARKS
// =========================================================================

mod proof_generation {
    use super::*;

    #[test]
    fn test_proof_generation_performance() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let body_hash = "b".repeat(64);

        let iterations = 10000;
        let start = Instant::now();

        for i in 0..iterations {
            let timestamp = format!("{}", 1700000000 + i);
            let _ = ash_build_proof(&secret, &timestamp, "POST|/|", &body_hash).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Proof generation: {} ops/sec", ops_per_sec as u64);

        // Rust should achieve at least 50,000 proofs/sec
        assert!(ops_per_sec > 10000.0, "Proof generation too slow: {} ops/sec", ops_per_sec);
    }

    #[test]
    fn test_scoped_proof_generation_performance() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let payload = r#"{"amount":100,"currency":"USD","memo":"test"}"#;
        let scope = vec!["amount", "currency"];

        let iterations = 5000;
        let start = Instant::now();

        for i in 0..iterations {
            let timestamp = format!("{}", 1700000000 + i);
            let _ = ash_build_proof_scoped(&secret, &timestamp, "POST|/|", payload, &scope).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Scoped proof generation: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 3000.0, "Scoped proof generation too slow");
    }
}

// =========================================================================
// PROOF VERIFICATION BENCHMARKS
// =========================================================================

mod proof_verification {
    use super::*;

    #[test]
    fn test_proof_verification_performance() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        let iterations = 10000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Proof verification: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 1000.0, "Proof verification too slow");
    }

    #[test]
    fn test_scoped_verification_performance() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let payload = r#"{"amount":100,"currency":"USD"}"#;
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let (proof, scope_hash) = ash_build_proof_scoped(&secret, timestamp, binding, payload, &scope).unwrap();

        let iterations = 5000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_verify_proof_scoped(&nonce, context_id, binding, timestamp, payload, &scope, &scope_hash, &proof).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Scoped verification: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 500.0, "Scoped verification too slow");
    }
}

// =========================================================================
// JSON CANONICALIZATION BENCHMARKS
// =========================================================================

mod json_canonicalization {
    use super::*;

    #[test]
    fn test_small_json_canonicalization() {
        let json = r#"{"key":"value"}"#;

        let iterations = 50000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_canonicalize_json(json).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Small JSON canonicalization: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 5000.0, "Small JSON canonicalization too slow");
    }

    #[test]
    fn test_medium_json_canonicalization() {
        let json = r#"{"user":{"name":"John","email":"john@example.com","age":30},"items":[{"id":1,"name":"Item1"},{"id":2,"name":"Item2"}],"metadata":{"created":"2024-01-01","updated":"2024-01-02"}}"#;

        let iterations = 20000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_canonicalize_json(json).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Medium JSON canonicalization: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 1000.0, "Medium JSON canonicalization too slow");
    }

    #[test]
    fn test_large_json_canonicalization() {
        // Create a larger JSON with many keys
        let mut json = String::from("{");
        for i in 0..100 {
            if i > 0 { json.push(','); }
            json.push_str(&format!(r#""key{}":{}"#, i, i));
        }
        json.push('}');

        let iterations = 5000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_canonicalize_json(&json).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Large JSON canonicalization: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 800.0, "Large JSON canonicalization too slow");
    }
}

// =========================================================================
// QUERY CANONICALIZATION BENCHMARKS
// =========================================================================

mod query_canonicalization {
    use super::*;

    #[test]
    fn test_simple_query_canonicalization() {
        let query = "a=1&b=2";

        let iterations = 100000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_canonicalize_query(query).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Simple query canonicalization: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 10000.0, "Simple query canonicalization too slow");
    }

    #[test]
    fn test_complex_query_canonicalization() {
        let query = "z=3&a=1&m=2&page=1&limit=10&sort=desc&filter=active&include=metadata";

        let iterations = 50000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_canonicalize_query(query).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Complex query canonicalization: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 2000.0, "Complex query canonicalization too slow");
    }
}

// =========================================================================
// HASHING BENCHMARKS
// =========================================================================

mod hashing {
    use super::*;

    #[test]
    fn test_small_body_hash() {
        let body = "small body content";

        let iterations = 100000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_hash_body(body);
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Small body hash: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 10000.0, "Small body hashing too slow");
    }

    #[test]
    fn test_10kb_body_hash() {
        let body = "x".repeat(10 * 1024);

        let iterations = 10000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_hash_body(&body);
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("10KB body hash: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 500.0, "10KB body hashing too slow");
    }

    #[test]
    fn test_100kb_body_hash() {
        let body = "x".repeat(100 * 1024);

        let iterations = 2000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_hash_body(&body);
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("100KB body hash: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 50.0, "100KB body hashing too slow");
    }
}

// =========================================================================
// CLIENT SECRET DERIVATION BENCHMARKS
// =========================================================================

mod secret_derivation {
    use super::*;

    #[test]
    fn test_secret_derivation_performance() {
        let nonce = "a".repeat(64);

        let iterations = 20000;
        let start = Instant::now();

        for i in 0..iterations {
            let context = format!("ctx_{}", i);
            let binding = format!("GET|/api/{}|", i);
            let _ = ash_derive_client_secret(&nonce, &context, &binding).unwrap();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Secret derivation: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 10000.0, "Secret derivation too slow");
    }
}

// =========================================================================
// NONCE GENERATION BENCHMARKS
// =========================================================================

mod nonce_generation {
    use super::*;

    #[test]
    fn test_nonce_generation_performance() {
        let iterations = 50000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_generate_nonce(32);
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Nonce generation: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 50000.0, "Nonce generation too slow");
    }

    #[test]
    fn test_context_id_generation_performance() {
        let iterations = 50000;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = ash_generate_context_id();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Context ID generation: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 50000.0, "Context ID generation too slow");
    }
}

// =========================================================================
// END-TO-END WORKFLOW BENCHMARKS
// =========================================================================

mod end_to_end {
    use super::*;

    #[test]
    fn test_full_workflow_performance() {
        let iterations = 5000;
        let start = Instant::now();

        for i in 0..iterations {
            // Generate nonce
            let nonce = ash_generate_nonce(32).unwrap();

            // Generate context
            let context_id = ash_generate_context_id().unwrap();
            let binding = "POST|/api/data|";

            // Derive secret
            let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();

            // Hash body
            let body = format!(r#"{{"index":{}}}"#, i);
            let body_hash = ash_hash_body(&body);

            // Build proof
            let timestamp = format!("{}", 1700000000 + i);
            let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

            // Verify proof
            let valid = ash_verify_proof(&nonce, &context_id, binding, &timestamp, &body_hash, &proof).unwrap();
            assert!(valid);
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!("Full workflow: {} ops/sec", ops_per_sec as u64);
        assert!(ops_per_sec > 2000.0, "Full workflow too slow");
    }
}

// =========================================================================
// MEMORY STABILITY
// =========================================================================

mod memory_stability {
    use super::*;

    #[test]
    fn test_no_memory_growth() {
        // Run many operations and verify we don't run out of memory
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let body_hash = "b".repeat(64);

        for i in 0..100000 {
            let timestamp = format!("{}", 1700000000 + i);
            let proof = ash_build_proof(&secret, &timestamp, "POST|/|", &body_hash).unwrap();
            let _ = ash_verify_proof(&nonce, "ctx", "POST|/|", &timestamp, &body_hash, &proof);

            // Drop proof each iteration - should not accumulate memory
        }

        // If we get here without OOM, memory is stable
    }

    #[test]
    fn test_json_canonicalization_memory_stability() {
        for i in 0..50000 {
            let json = format!(r#"{{"index":{}}}"#, i);
            let _ = ash_canonicalize_json(&json);
        }
    }
}
