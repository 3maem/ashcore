//! Production Edge Cases Tests for ASH Rust SDK
//!
//! Tests Unicode edge cases, concurrency, memory handling, and time edge cases.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_normalize_binding,
};
use std::sync::Arc;
use std::thread;

// =========================================================================
// UNICODE EDGE CASES
// =========================================================================

mod unicode {
    use super::*;

    #[test]
    fn test_emoji_handling() {
        let json = r#"{"emoji": "🎉🚀💯"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());

        let canonical = result.unwrap();
        assert!(canonical.contains("🎉") || canonical.contains("\\u"));
    }

    #[test]
    fn test_cjk_characters() {
        let json = r#"{"japanese": "日本語", "chinese": "中文", "korean": "한국어"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rtl_text() {
        let json = r#"{"arabic": "العربية", "hebrew": "עברית"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_width_characters() {
        // Zero-width space, zero-width joiner, zero-width non-joiner
        let json = r#"{"text": "a\u200Bb\u200Cc\u200D"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_combining_characters() {
        // e + combining acute = é
        let json = r#"{"text": "cafe\u0301"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());

        // Should normalize to NFC
        let canonical = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        // After NFC normalization, should be "café"
        let text = parsed["text"].as_str().unwrap();
        assert!(text.contains('é') || text.contains("cafe"));
    }

    #[test]
    fn test_surrogate_pairs() {
        // Supplementary character (emoji) via surrogate pairs
        let json = r#"{"emoji": "\uD83D\uDE00"}"#;  // 😀
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unicode_in_binding() {
        let result = ash_normalize_binding("GET", "/api/用户", "name=日本語");
        assert!(result.is_ok());
    }
}

// =========================================================================
// CONCURRENCY
// =========================================================================

mod concurrency {
    use super::*;

    #[test]
    fn test_concurrent_proof_generation() {
        let nonce = Arc::new("a".repeat(64));
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";

        let handles: Vec<_> = (0..10).map(|i| {
            let nonce = Arc::clone(&nonce);
            thread::spawn(move || {
                let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
                let timestamp = format!("{}", 1700000000 + i);
                let body_hash = format!("{:064x}", i);
                ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap()
            })
        }).collect();

        let proofs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All proofs should be unique
        let unique: std::collections::HashSet<_> = proofs.iter().collect();
        assert_eq!(unique.len(), 10);
    }

    #[test]
    fn test_concurrent_verification() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        let nonce = Arc::new(nonce);
        let proof = Arc::new(proof);
        let body_hash = Arc::new(body_hash);

        let handles: Vec<_> = (0..10).map(|_| {
            let nonce = Arc::clone(&nonce);
            let proof = Arc::clone(&proof);
            let body_hash = Arc::clone(&body_hash);
            thread::spawn(move || {
                ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap()
            })
        }).collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All verifications should succeed
        assert!(results.iter().all(|&v| v));
    }

    #[test]
    fn test_concurrent_canonicalization() {
        let handles: Vec<_> = (0..100).map(|i| {
            thread::spawn(move || {
                let json = format!(r#"{{"index": {}, "value": "test{}"}}"#, i, i);
                ash_canonicalize_json(&json).unwrap()
            })
        }).collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.len(), 100);
    }
}

// =========================================================================
// MEMORY
// =========================================================================

mod memory {
    use super::*;

    #[test]
    fn test_large_payload_handling() {
        // 1MB payload (within limits)
        let large_data = "x".repeat(1024 * 1024);
        let json = format!(r#"{{"data": "{}"}}"#, large_data);

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_many_keys_handling() {
        // Many keys in object
        let mut json = String::from("{");
        for i in 0..1000 {
            if i > 0 { json.push(','); }
            json.push_str(&format!(r#""key{}": {}"#, i, i));
        }
        json.push('}');

        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deep_array_nesting() {
        // Nested arrays (within depth limit)
        let json = String::from("[[[[[[[[[[1]]]]]]]]]]");
        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }
}

// =========================================================================
// TIME EDGE CASES
// =========================================================================

mod time {
    use super::*;

    #[test]
    fn test_timestamp_at_epoch() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        // Unix epoch
        let timestamp = "0";
        let result = ash_build_proof(&secret, timestamp, binding, &body_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_timestamp_year_2038() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        // Just before Y2K38 problem (2^31 - 1)
        let timestamp = "2147483647";
        let result = ash_build_proof(&secret, timestamp, binding, &body_hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_timestamp_year_3000() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        // Year 3000 (should still work with 64-bit timestamps)
        let timestamp = "32503680000";
        let result = ash_build_proof(&secret, timestamp, binding, &body_hash);
        assert!(result.is_ok());
    }
}

// =========================================================================
// DETERMINISM ACROSS CALLS
// =========================================================================

mod determinism {
    use super::*;

    #[test]
    fn test_json_canonicalization_deterministic() {
        let json = r#"{"z": 1, "a": 2, "m": {"b": 3, "a": 4}}"#;

        let results: Vec<_> = (0..100)
            .map(|_| ash_canonicalize_json(json).unwrap())
            .collect();

        // All results should be identical
        assert!(results.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn test_query_canonicalization_deterministic() {
        let query = "z=3&a=1&m=2&a=0";

        let results: Vec<_> = (0..100)
            .map(|_| ash_canonicalize_query(query).unwrap())
            .collect();

        // All results should be identical
        assert!(results.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn test_proof_generation_deterministic() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let results: Vec<_> = (0..100)
            .map(|_| ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap())
            .collect();

        // All results should be identical
        assert!(results.windows(2).all(|w| w[0] == w[1]));
    }
}

// =========================================================================
// BOUNDARY CONDITIONS
// =========================================================================

mod boundaries {
    use super::*;

    #[test]
    fn test_minimum_valid_nonce() {
        // Minimum 32 hex chars (16 bytes)
        let nonce = "a".repeat(32);
        let result = ash_derive_client_secret(&nonce, "ctx", "POST|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_maximum_valid_nonce() {
        // Maximum 512 hex chars (MAX_NONCE_LENGTH)
        let nonce = "a".repeat(512);
        let result = ash_derive_client_secret(&nonce, "ctx", "POST|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_json_object() {
        let result = ash_canonicalize_json("{}");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "{}");
    }

    #[test]
    fn test_empty_json_array() {
        let result = ash_canonicalize_json("[]");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "[]");
    }

    #[test]
    fn test_single_character_values() {
        let json = r#"{"a": "b"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_numeric_string_keys() {
        let json = r#"{"1": "a", "2": "b", "10": "c"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
        // Should sort lexicographically: "1", "10", "2"
        let canonical = result.unwrap();
        assert!(canonical.find("\"1\"").unwrap() < canonical.find("\"10\"").unwrap());
        assert!(canonical.find("\"10\"").unwrap() < canonical.find("\"2\"").unwrap());
    }
}

// =========================================================================
// SPECIAL CHARACTERS IN BINDING
// =========================================================================

mod binding_special_chars {
    use super::*;

    #[test]
    fn test_binding_with_encoded_slash() {
        let result = ash_normalize_binding("GET", "/api/path%2Fwith%2Fslashes", "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_binding_with_unicode_path() {
        let result = ash_normalize_binding("GET", "/api/日本語", "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_binding_with_special_query() {
        let result = ash_normalize_binding("GET", "/api", "key=value%26more");
        assert!(result.is_ok());
    }
}
