//! Comprehensive Stress and Performance Tests
//!
//! These tests verify system behavior under load:
//! - High volume operations
//! - Concurrent operations
//! - Memory safety
//! - Large payload handling

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_normalize_binding,
};
use std::thread;
use std::sync::Arc;

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// =========================================================================
// HIGH VOLUME TESTS
// =========================================================================

mod high_volume {
    use super::*;

    #[test]
    fn test_10000_canonicalizations() {
        for i in 0..10000 {
            let json = format!(r#"{{"index":{},"value":"test_{}" }}"#, i, i);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed at iteration {}", i);
        }
    }

    #[test]
    fn test_10000_hash_operations() {
        for i in 0..10000 {
            let body = format!("body_content_{}_with_some_data", i);
            let hash = ash_hash_body(&body);
            assert_eq!(hash.len(), 64, "Invalid hash at iteration {}", i);
        }
    }

    #[test]
    fn test_5000_secret_derivations() {
        for i in 0..5000 {
            let context_id = format!("ctx_{}", i);
            let secret = ash_derive_client_secret(TEST_NONCE, &context_id, "GET|/|");
            assert!(secret.is_ok(), "Failed at iteration {}", i);
        }
    }

    #[test]
    fn test_5000_proof_generations() {
        let secret = ash_derive_client_secret(TEST_NONCE, "ctx_volume", "POST|/|").unwrap();

        for i in 0..5000 {
            let timestamp = (1700000000 + i).to_string();
            let proof = ash_build_proof(&secret, &timestamp, "POST|/|", TEST_BODY_HASH);
            assert!(proof.is_ok(), "Failed at iteration {}", i);
        }
    }

    #[test]
    fn test_5000_verifications() {
        let context_id = "ctx_verify_volume";
        let binding = "POST|/api|";
        let timestamp = "1700000000";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap();

        for i in 0..5000 {
            let valid = ash_verify_proof(TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof);
            assert!(valid.is_ok() && valid.unwrap(), "Failed at iteration {}", i);
        }
    }

    #[test]
    fn test_10000_binding_normalizations() {
        for i in 0..10000 {
            let path = format!("/api/resource/{}", i);
            let result = ash_normalize_binding("GET", &path, "");
            assert!(result.is_ok(), "Failed at iteration {}", i);
        }
    }

    #[test]
    fn test_10000_query_canonicalizations() {
        for i in 0..10000 {
            let query = format!("page={}&limit=10&sort=name", i);
            let result = ash_canonicalize_query(&query);
            assert!(result.is_ok(), "Failed at iteration {}", i);
        }
    }
}

// =========================================================================
// CONCURRENT OPERATION TESTS
// =========================================================================

mod concurrent {
    use super::*;

    #[test]
    fn test_concurrent_hashing_20_threads() {
        let mut handles = vec![];

        for thread_id in 0..20 {
            let handle = thread::spawn(move || {
                for i in 0..500 {
                    let body = format!("thread_{}_iteration_{}", thread_id, i);
                    let hash = ash_hash_body(&body);
                    assert_eq!(hash.len(), 64);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_concurrent_canonicalization_20_threads() {
        let mut handles = vec![];

        for thread_id in 0..20 {
            let handle = thread::spawn(move || {
                for i in 0..500 {
                    let json = format!(r#"{{"thread":{},"iter":{}}}"#, thread_id, i);
                    let result = ash_canonicalize_json(&json);
                    assert!(result.is_ok());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_concurrent_proof_generation_10_threads() {
        let mut handles = vec![];

        for thread_id in 0..10 {
            let handle = thread::spawn(move || {
                let context_id = format!("ctx_concurrent_{}", thread_id);
                let binding = "POST|/api/test|";
                let secret = ash_derive_client_secret(TEST_NONCE, &context_id, binding).unwrap();

                for i in 0..500 {
                    let timestamp = (1700000000 + thread_id * 1000 + i).to_string();
                    let proof = ash_build_proof(&secret, &timestamp, binding, TEST_BODY_HASH);
                    assert!(proof.is_ok());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_concurrent_verification_shared_proof() {
        let context_id = "ctx_shared_verify";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";

        let secret = ash_derive_client_secret(TEST_NONCE, context_id, binding).unwrap();
        let proof = Arc::new(ash_build_proof(&secret, timestamp, binding, TEST_BODY_HASH).unwrap());

        let mut handles = vec![];

        for _ in 0..10 {
            let proof_clone = Arc::clone(&proof);
            let handle = thread::spawn(move || {
                for _ in 0..500 {
                    let valid = ash_verify_proof(
                        TEST_NONCE, context_id, binding, timestamp, TEST_BODY_HASH, &proof_clone
                    ).unwrap();
                    assert!(valid);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }

    #[test]
    fn test_concurrent_mixed_operations() {
        let mut handles = vec![];

        // Hash threads
        for i in 0..5 {
            let handle = thread::spawn(move || {
                for j in 0..200 {
                    let body = format!("hash_thread_{}_iter_{}", i, j);
                    let _ = ash_hash_body(&body);
                }
            });
            handles.push(handle);
        }

        // Canonicalize threads
        for i in 0..5 {
            let handle = thread::spawn(move || {
                for j in 0..200 {
                    let json = format!(r#"{{"t":{},"i":{}}}"#, i, j);
                    let _ = ash_canonicalize_json(&json);
                }
            });
            handles.push(handle);
        }

        // Proof threads
        for i in 0..5 {
            let handle = thread::spawn(move || {
                let ctx = format!("ctx_mixed_{}", i);
                let secret = ash_derive_client_secret(TEST_NONCE, &ctx, "GET|/|").unwrap();
                for j in 0..200 {
                    let ts = (1700000000 + j).to_string();
                    let _ = ash_build_proof(&secret, &ts, "GET|/|", TEST_BODY_HASH);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }
}

// =========================================================================
// LARGE PAYLOAD TESTS
// =========================================================================

mod large_payloads {
    use super::*;

    #[test]
    fn test_1kb_json_payload() {
        let large_value = "x".repeat(1000);
        let json = format!(r#"{{"data":"{}"}}"#, large_value);

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());

        let hash = ash_hash_body(&result.unwrap());
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_100kb_json_payload() {
        let large_value = "x".repeat(100_000);
        let json = format!(r#"{{"data":"{}"}}"#, large_value);

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_1mb_json_payload() {
        let large_value = "x".repeat(1_000_000);
        let json = format!(r#"{{"data":"{}"}}"#, large_value);

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_many_keys_object() {
        let mut json = String::from("{");
        for i in 0..1000 {
            if i > 0 { json.push(','); }
            json.push_str(&format!(r#""key{}":{}"#, i, i));
        }
        json.push('}');

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deeply_nested_but_valid() {
        // 50 levels of nesting (within limit)
        let mut json = String::new();
        for _ in 0..50 {
            json.push_str(r#"{"a":"#);
        }
        json.push_str("1");
        for _ in 0..50 {
            json.push('}');
        }

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_array() {
        let mut json = String::from("[");
        for i in 0..10000 {
            if i > 0 { json.push(','); }
            json.push_str(&i.to_string());
        }
        json.push(']');

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_long_query_string() {
        let params: String = (0..500)
            .map(|i| format!("param{}=value{}", i, i))
            .collect::<Vec<_>>()
            .join("&");

        let result = ash_canonicalize_query(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_path() {
        let long_segment = "a".repeat(1000);
        let path = format!("/api/{}/resource", long_segment);

        let result = ash_normalize_binding("GET", &path, "");
        assert!(result.is_ok());
    }
}

// =========================================================================
// MEMORY SAFETY TESTS
// =========================================================================

mod memory_safety {
    use super::*;

    #[test]
    fn test_repeated_allocation_and_release() {
        for _ in 0..1000 {
            let large_value = "x".repeat(10_000);
            let json = format!(r#"{{"data":"{}"}}"#, large_value);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok());
            // Result goes out of scope and is freed
        }
    }

    #[test]
    fn test_interleaved_allocations() {
        let mut results = Vec::new();

        for i in 0..100 {
            let json = format!(r#"{{"iteration":{}}}"#, i);
            results.push(ash_canonicalize_json(&json).unwrap());
        }

        // All results should still be valid
        for (i, result) in results.iter().enumerate() {
            assert!(result.contains(&format!("\"iteration\":{}", i)));
        }
    }

    #[test]
    fn test_string_with_special_allocation_sizes() {
        // Test various sizes that might trigger different allocation strategies
        let sizes = [0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024];

        for size in sizes {
            let value = "x".repeat(size);
            let json = format!(r#"{{"data":"{}"}}"#, value);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed for size {}", size);
        }
    }

    #[test]
    fn test_hash_many_unique_inputs() {
        // Generate many unique inputs to test hash table behavior
        let mut hashes = Vec::with_capacity(10000);

        for i in 0..10000 {
            let body = format!("unique_body_content_{}_with_extra_data", i);
            hashes.push(ash_hash_body(&body));
        }

        // Verify all hashes are present
        assert_eq!(hashes.len(), 10000);
    }
}

// =========================================================================
// PERFORMANCE CONSISTENCY TESTS
// =========================================================================

mod performance_consistency {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_consistent_canonicalization_time() {
        let json = r#"{"z":26,"a":1,"m":13,"nested":{"x":24,"y":25}}"#;

        let mut times = Vec::new();

        for _ in 0..100 {
            let start = Instant::now();
            for _ in 0..1000 {
                let _ = ash_canonicalize_json(json);
            }
            times.push(start.elapsed());
        }

        // Check that times are relatively consistent (within 5x of median)
        // Note: Using 5x threshold to accommodate CI environment variability
        times.sort();
        let median = times[times.len() / 2];
        let min = times[0];
        let max = times[times.len() - 1];

        assert!(
            max <= median * 5,
            "Performance inconsistent: median={:?}, max={:?}",
            median, max
        );
        assert!(
            min >= median / 5,
            "Performance inconsistent: median={:?}, min={:?}",
            median, min
        );
    }

    #[test]
    fn test_consistent_hashing_time() {
        let body = "test body for hashing performance";

        let mut times = Vec::new();

        for _ in 0..100 {
            let start = Instant::now();
            for _ in 0..1000 {
                let _ = ash_hash_body(body);
            }
            times.push(start.elapsed());
        }

        times.sort();
        let median = times[times.len() / 2];
        let max = times[times.len() - 1];

        // Note: Using 5x threshold to accommodate CI environment variability
        assert!(
            max <= median * 5,
            "Hash performance inconsistent: median={:?}, max={:?}",
            median, max
        );
    }

    #[test]
    fn test_scaling_with_input_size() {
        let sizes = [100, 1000, 10000];
        let mut timings = Vec::new();

        for size in sizes {
            let body = "x".repeat(size);
            let start = Instant::now();
            for _ in 0..100 {
                let _ = ash_hash_body(&body);
            }
            timings.push((size, start.elapsed()));
        }

        // Verify roughly linear scaling (10x size should be < 20x time)
        let (s1, t1) = timings[0];
        let (s3, t3) = timings[2];

        let size_ratio = s3 as f64 / s1 as f64;
        let time_ratio = t3.as_nanos() as f64 / t1.as_nanos() as f64;

        assert!(
            time_ratio < size_ratio * 2.0,
            "Scaling worse than expected: size {}x, time {}x",
            size_ratio, time_ratio
        );
    }
}

// =========================================================================
// ERROR RECOVERY TESTS
// =========================================================================

mod error_recovery {
    use super::*;

    #[test]
    fn test_continue_after_invalid_json() {
        // Process invalid JSON
        let result = ash_canonicalize_json("invalid{json");
        assert!(result.is_err());

        // Should still be able to process valid JSON after error
        let result = ash_canonicalize_json(r#"{"valid":"json"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_continue_after_invalid_nonce() {
        // Try invalid nonce
        let result = ash_derive_client_secret("short", "ctx", "GET|/|");
        assert!(result.is_err());

        // Should still work with valid nonce
        let result = ash_derive_client_secret(TEST_NONCE, "ctx", "GET|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_interleaved_valid_invalid() {
        for i in 0..100 {
            // Alternate between valid and invalid inputs
            if i % 2 == 0 {
                let json = format!(r#"{{"index":{}}}"#, i);
                let result = ash_canonicalize_json(&json);
                assert!(result.is_ok());
            } else {
                let invalid = format!("invalid_json_{}", i);
                let result = ash_canonicalize_json(&invalid);
                assert!(result.is_err());
            }
        }
    }
}
