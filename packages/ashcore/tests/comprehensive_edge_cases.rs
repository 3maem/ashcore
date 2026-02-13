//! Comprehensive Edge Cases Test Suite for ASH Core

use ashcore::*;
use rand::{Rng, thread_rng, seq::SliceRandom};
use std::collections::HashSet;

// ============================================================================
// SECTION 1: EXTREME NONCE TESTS
// ============================================================================

mod nonce_edge_cases {
    use super::*;

    #[test]
    fn test_nonce_length_0() {
        assert!(ash_derive_client_secret("", "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_length_1() {
        assert!(ash_derive_client_secret("a", "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_length_31() {
        let nonce = "a".repeat(31);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_length_32() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_length_64() {
        let nonce = "a".repeat(64);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_length_128() {
        let nonce = "a".repeat(128);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_length_256() {
        let nonce = "a".repeat(256);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_length_512() {
        let nonce = "a".repeat(512);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_length_513() {
        let nonce = "a".repeat(513);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_all_hex_lowercase() {
        let nonce = "0123456789abcdef".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_all_hex_uppercase() {
        let nonce = "0123456789ABCDEF".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_mixed_case() {
        let nonce = "0123456789aBcDeF".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_ok());
    }

    #[test]
    fn test_nonce_with_space() {
        let nonce = "a".repeat(16) + " " + &"a".repeat(16);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_with_null_byte() {
        let nonce = "a".repeat(16) + "\0" + &"a".repeat(16);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_with_newline() {
        let nonce = "a".repeat(16) + "\n" + &"a".repeat(16);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_with_g() {
        let nonce = "g".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_with_x() {
        let nonce = "x".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_nonce_with_z() {
        let nonce = "z".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "GET|/|").is_err());
    }

    #[test]
    fn test_generate_nonce_16_bytes() {
        let nonce = ash_generate_nonce(16).unwrap();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_nonce_32_bytes() {
        let nonce = ash_generate_nonce(32).unwrap();
        assert_eq!(nonce.len(), 64);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_nonce_64_bytes() {
        let nonce = ash_generate_nonce(64).unwrap();
        assert_eq!(nonce.len(), 128);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_nonce_rejects_15_bytes() {
        assert!(ash_generate_nonce(15).is_err());
    }

    #[test]
    fn test_generate_nonce_rejects_0_bytes() {
        assert!(ash_generate_nonce(0).is_err());
    }

    #[test]
    fn test_generated_nonces_are_unique() {
        let mut nonces = HashSet::new();
        for _ in 0..1000 {
            let nonce = ash_generate_nonce(32).unwrap();
            assert!(nonces.insert(nonce), "Duplicate nonce generated");
        }
    }

    #[test]
    fn test_context_id_generation() {
        let ctx = ash_generate_context_id().unwrap();
        assert!(ctx.starts_with("ash_"));
        assert!(ctx.len() > 4);
    }

    #[test]
    fn test_context_id_256_generation() {
        let ctx = ash_generate_context_id_256().unwrap();
        assert!(ctx.starts_with("ash_"));
        assert_eq!(ctx.len(), 4 + 64);
    }
}

// ============================================================================
// SECTION 2: CONTEXT ID EDGE CASES
// ============================================================================

mod context_id_edge_cases {
    use super::*;

    #[test]
    fn test_context_id_empty() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "", "GET|/|").is_err());
    }

    #[test]
    fn test_context_id_single_char() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "x", "GET|/|").is_ok());
    }

    #[test]
    fn test_context_id_max_length_256() {
        let nonce = "a".repeat(32);
        let ctx = "a".repeat(256);
        assert!(ash_derive_client_secret(&nonce, &ctx, "GET|/|").is_ok());
    }

    #[test]
    fn test_context_id_over_max_length() {
        let nonce = "a".repeat(32);
        let ctx = "a".repeat(257);
        assert!(ash_derive_client_secret(&nonce, &ctx, "GET|/|").is_err());
    }

    #[test]
    fn test_context_id_with_pipe() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx|test", "GET|/|").is_err());
    }

    #[test]
    fn test_context_id_with_space() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx test", "GET|/|").is_err());
    }

    #[test]
    fn test_context_id_with_null() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx\0test", "GET|/|").is_err());
    }

    #[test]
    fn test_context_id_valid_chars() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "abcABC123_-.", "GET|/|").is_ok());
    }

    #[test]
    fn test_context_id_special_chars_rejected() {
        let nonce = "a".repeat(32);
        let special_chars = ["!", "$", "%", "^", "&", "*", "(", ")", "+", "=", "[", "]", "{", "}", ":", ";", "'", "\"", ",", "<", ">", "?", "/", "\\"];
        for ch in &special_chars {
            let ctx = format!("ctx{}test", ch);
            assert!(ash_derive_client_secret(&nonce, &ctx, "GET|/|").is_err(), "Context with '{}' should fail", ch);
        }
    }
}

// ============================================================================
// SECTION 3: BINDING EDGE CASES
// ============================================================================

mod binding_edge_cases {
    use super::*;

    #[test]
    fn test_binding_empty() {
        let nonce = "a".repeat(32);
        assert!(ash_derive_client_secret(&nonce, "ctx", "").is_err());
    }

    #[test]
    fn test_binding_method_empty() {
        assert!(ash_normalize_binding("", "/api", "").is_err());
    }

    #[test]
    fn test_binding_method_whitespace_only() {
        assert!(ash_normalize_binding("   ", "/api", "").is_err());
    }

    #[test]
    fn test_binding_method_unicode() {
        assert!(ash_normalize_binding("GET", "/api", "").is_ok());
    }

    #[test]
    fn test_binding_path_no_leading_slash() {
        assert!(ash_normalize_binding("GET", "api/users", "").is_err());
    }

    #[test]
    fn test_binding_path_single_slash() {
        let result = ash_normalize_binding("GET", "/", "").unwrap();
        assert_eq!(result, "GET|/|");
    }

    #[test]
    fn test_binding_path_double_slash() {
        let result = ash_normalize_binding("GET", "//", "").unwrap();
        assert_eq!(result, "GET|/|");
    }

    #[test]
    fn test_binding_path_many_slashes() {
        let path = "/".repeat(100);
        let result = ash_normalize_binding("GET", &path, "").unwrap();
        assert_eq!(result, "GET|/|");
    }

    #[test]
    fn test_binding_path_traversal_attempt() {
        let result = ash_normalize_binding("GET", "/api/../../../etc/passwd", "").unwrap();
        assert_eq!(result, "GET|/etc/passwd|");
    }

    #[test]
    fn test_binding_path_traversal_at_root() {
        let result = ash_normalize_binding("GET", "/../api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_binding_path_with_encoded_slash() {
        let result = ash_normalize_binding("GET", "/api%2Fusers", "").unwrap();
        assert_eq!(result, "GET|/api/users|");
    }

    #[test]
    fn test_binding_query_empty() {
        let result = ash_normalize_binding("GET", "/api", "").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_binding_query_whitespace_only() {
        let result = ash_normalize_binding("GET", "/api", "   ").unwrap();
        assert_eq!(result, "GET|/api|");
    }

    #[test]
    fn test_binding_query_single_param() {
        let result = ash_normalize_binding("GET", "/api", "a=1").unwrap();
        assert_eq!(result, "GET|/api|a=1");
    }

    #[test]
    fn test_binding_query_many_params() {
        let params: Vec<String> = (0..100).map(|i| format!("key{}=value{}", i, i)).collect();
        let query = params.join("&");
        let result = ash_normalize_binding("GET", "/api", &query).unwrap();
        assert!(result.starts_with("GET|/api|"));
    }

    #[test]
    fn test_binding_query_plus_sign() {
        let result = ash_normalize_binding("GET", "/api", "q=a+b").unwrap();
        assert!(result.contains("%2B"));
    }

    #[test]
    fn test_binding_all_http_methods() {
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"];
        for method in &methods {
            let result = ash_normalize_binding(method, "/api", "").unwrap();
            assert!(result.starts_with(&format!("{}|/api|", method)));
        }
    }

    #[test]
    fn test_binding_method_case_normalization() {
        let methods = ["get", "Get", "gEt", "GET", "geT"];
        for method in &methods {
            let result = ash_normalize_binding(method, "/api", "").unwrap();
            assert!(result.starts_with("GET|/api|"));
        }
    }

    #[test]
    fn test_binding_extremely_long_path() {
        let path = format!("/api/{}", &"a/".repeat(1000));
        let result = ash_normalize_binding("GET", &path, "");
        assert!(result.is_ok());
    }
}

// ============================================================================
// SECTION 4: TIMESTAMP EDGE CASES
// ============================================================================

mod timestamp_edge_cases {
    use super::*;

    #[test]
    fn test_timestamp_empty() {
        assert!(ash_validate_timestamp_format("").is_err());
    }

    #[test]
    fn test_timestamp_zero() {
        assert!(ash_validate_timestamp_format("0").is_ok());
    }

    #[test]
    fn test_timestamp_one() {
        assert!(ash_validate_timestamp_format("1").is_ok());
    }

    #[test]
    fn test_timestamp_leading_zero() {
        assert!(ash_validate_timestamp_format("01").is_err());
    }

    #[test]
    fn test_timestamp_negative() {
        assert!(ash_validate_timestamp_format("-1").is_err());
    }

    #[test]
    fn test_timestamp_decimal() {
        assert!(ash_validate_timestamp_format("123.456").is_err());
    }

    #[test]
    fn test_timestamp_max_value() {
        assert!(ash_validate_timestamp_format("32503680000").is_ok());
    }

    #[test]
    fn test_timestamp_over_max() {
        assert!(ash_validate_timestamp_format("32503680001").is_err());
    }

    #[test]
    fn test_timestamp_year_2038() {
        assert!(ash_validate_timestamp_format("2147483648").is_ok());
    }

    #[test]
    fn test_timestamp_current() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        assert!(ash_validate_timestamp_format(&now).is_ok());
    }
}

// ============================================================================
// SECTION 5: PROOF EDGE CASES
// ============================================================================

mod proof_edge_cases {
    use super::*;

    #[test]
    fn test_proof_empty_client_secret() {
        let result = ash_build_proof("", "1234567890", "GET|/|", &"a".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_empty_timestamp() {
        let result = ash_build_proof("secret", "", "GET|/|", &"a".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_empty_binding() {
        let result = ash_build_proof("secret", "1234567890", "", &"a".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_empty_body_hash() {
        let result = ash_build_proof("secret", "1234567890", "GET|/|", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_body_hash_too_short() {
        let result = ash_build_proof("secret", "1234567890", "GET|/|", "abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_body_hash_non_hex() {
        let result = ash_build_proof("secret", "1234567890", "GET|/|", &"g".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_valid() {
        let body_hash = ash_hash_body("test");
        let result = ash_build_proof("secret_key", "1700000000", "POST|/api|", &body_hash);
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.len(), 64);
    }

    #[test]
    fn test_proof_deterministic() {
        let body_hash = ash_hash_body("test");
        let proof1 = ash_build_proof("secret", "1700000000", "POST|/api|", &body_hash).unwrap();
        let proof2 = ash_build_proof("secret", "1700000000", "POST|/api|", &body_hash).unwrap();
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_proof_different_secrets() {
        let body_hash = ash_hash_body("test");
        let proof1 = ash_build_proof("secret1", "1700000000", "POST|/api|", &body_hash).unwrap();
        let proof2 = ash_build_proof("secret2", "1700000000", "POST|/api|", &body_hash).unwrap();
        assert_ne!(proof1, proof2);
    }
}

// ============================================================================
// SECTION 6: VERIFICATION EDGE CASES
// ============================================================================

mod verification_edge_cases {
    use super::*;

    #[test]
    fn test_verify_valid_proof() {
        let nonce = "a".repeat(32);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let body_hash = ash_hash_body("test");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_nonce() {
        let nonce = "a".repeat(32);
        let wrong_nonce = "b".repeat(32);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let body_hash = ash_hash_body("test");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&wrong_nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_context() {
        let nonce = "a".repeat(32);
        let context_id = "ctx_test";
        let wrong_context = "ctx_wrong";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let body_hash = ash_hash_body("test");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&nonce, wrong_context, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_binding() {
        let nonce = "a".repeat(32);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let wrong_binding = "POST|/wrong|";
        let timestamp = "1700000000";
        let body_hash = ash_hash_body("test");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&nonce, context_id, wrong_binding, timestamp, &body_hash, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_tampered_proof() {
        let nonce = "a".repeat(32);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let timestamp = "1700000000";
        let body_hash = ash_hash_body("test");

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        
        let tampered = format!("{}a", &proof[..63]);
        let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &tampered).unwrap();
        assert!(!valid);
    }
}

// ============================================================================
// SECTION 7: JSON CANONICALIZATION EDGE CASES
// ============================================================================

mod json_canonicalization_edge_cases {
    use super::*;

    #[test]
    fn test_json_empty_object() {
        assert_eq!(ash_canonicalize_json("{}").unwrap(), "{}");
    }

    #[test]
    fn test_json_empty_array() {
        assert_eq!(ash_canonicalize_json("[]").unwrap(), "[]");
    }

    #[test]
    fn test_json_null() {
        assert_eq!(ash_canonicalize_json("null").unwrap(), "null");
    }

    #[test]
    fn test_json_true() {
        assert_eq!(ash_canonicalize_json("true").unwrap(), "true");
    }

    #[test]
    fn test_json_false() {
        assert_eq!(ash_canonicalize_json("false").unwrap(), "false");
    }

    #[test]
    fn test_json_number_zero() {
        assert_eq!(ash_canonicalize_json("0").unwrap(), "0");
    }

    #[test]
    fn test_json_number_negative_zero() {
        assert_eq!(ash_canonicalize_json("-0").unwrap(), "0");
    }

    #[test]
    fn test_json_number_whole_float() {
        assert_eq!(ash_canonicalize_json("42.0").unwrap(), "42");
    }

    #[test]
    fn test_json_key_sorting() {
        assert_eq!(ash_canonicalize_json(r#"{"z":1,"a":2}"#).unwrap(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_json_deep_nesting() {
        // BUG-095: MAX_RECURSION_DEPTH=64, check is `depth >= 64`, so valid
        // depths are 0..63 (64 levels). 63 wraps = leaf at depth 63 = OK.
        let mut json = String::from("1");
        for _ in 0..63 {
            json = format!(r#"{{"a":{}}}"#, json);
        }
        assert!(ash_canonicalize_json(&json).is_ok());

        // 64 wraps = leaf at depth 64 = rejected
        let mut json_too_deep = String::from("1");
        for _ in 0..64 {
            json_too_deep = format!(r#"{{"a":{}}}"#, json_too_deep);
        }
        assert!(ash_canonicalize_json(&json_too_deep).is_err());
    }

    #[test]
    fn test_json_too_deep_nesting() {
        let mut json = String::from("1");
        for _ in 0..100 {
            json = format!(r#"{{"a":{}}}"#, json);
        }
        assert!(ash_canonicalize_json(&json).is_err());
    }

    #[test]
    fn test_json_many_keys() {
        let keys: Vec<String> = (0..1000).map(|i| format!("\"key{}\":{}", i, i)).collect();
        let json = format!("{{{}}}", keys.join(","));
        assert!(ash_canonicalize_json(&json).is_ok());
    }

    #[test]
    fn test_json_emoji() {
        let json = r#"{"a":"smile","b":"party"}"#;
        assert!(ash_canonicalize_json(json).is_ok());
    }
}

// ============================================================================
// SECTION 8: SCOPE EDGE CASES
// ============================================================================

mod scope_edge_cases {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_scope_empty() {
        let payload = json!({"a": 1, "b": 2});
        let result = ash_extract_scoped_fields(&payload, &[]).unwrap();
        // Empty scope returns the full payload (no filtering)
        assert_eq!(result, payload, "Empty scope should return full payload");
    }

    #[test]
    fn test_scope_single_field() {
        let payload = json!({"a": 1, "b": 2});
        let result = ash_extract_scoped_fields(&payload, &["a"]).unwrap();
        assert_eq!(result, json!({"a": 1}));
    }

    #[test]
    fn test_scope_multiple_fields() {
        let payload = json!({"a": 1, "b": 2, "c": 3});
        let result = ash_extract_scoped_fields(&payload, &["a", "c"]).unwrap();
        assert_eq!(result, json!({"a": 1, "c": 3}));
    }

    #[test]
    fn test_scope_nested_field() {
        let payload = json!({"user": {"name": "John", "age": 30}});
        let result = ash_extract_scoped_fields(&payload, &["user.name"]).unwrap();
        assert_eq!(result, json!({"user": {"name": "John"}}));
    }

    #[test]
    fn test_scope_array_index() {
        let payload = json!({"items": [1, 2, 3]});
        let result = ash_extract_scoped_fields(&payload, &["items[0]"]).unwrap();
        assert_eq!(result, json!({"items": [1]}));
    }

    #[test]
    fn test_scope_hash_empty() {
        let hash = ash_hash_scope(&[]).unwrap();
        assert!(hash.is_empty());
    }

    #[test]
    fn test_scope_hash_order_independent() {
        let hash1 = ash_hash_scope(&["a", "b", "c"]).unwrap();
        let hash2 = ash_hash_scope(&["c", "a", "b"]).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_scope_field_max_length() {
        let long_field = "a".repeat(65);
        let result = ash_hash_scope(&[&long_field]);
        assert!(result.is_err());
    }

    #[test]
    fn test_scope_too_many_fields() {
        // The limit might be on total length or field count
        // Test with enough fields to potentially trigger limits
        let fields: Vec<String> = (0..150).map(|i| format!("field{}", i)).collect();
        let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let result = ash_hash_scope(&field_refs);
        // May succeed or fail depending on implementation
        // Just ensure it doesn't panic
        let _ = result;
    }
}

// ============================================================================
// SECTION 9: TIMING SAFE COMPARISON EDGE CASES
// ============================================================================

mod timing_safe_edge_cases {
    use super::*;

    #[test]
    fn test_timing_safe_empty_both() {
        assert!(ash_timing_safe_equal(b"", b""));
    }

    #[test]
    fn test_timing_safe_empty_first() {
        assert!(!ash_timing_safe_equal(b"", b"a"));
    }

    #[test]
    fn test_timing_safe_empty_second() {
        assert!(!ash_timing_safe_equal(b"a", b""));
    }

    #[test]
    fn test_timing_safe_same_content() {
        assert!(ash_timing_safe_equal(b"hello", b"hello"));
    }

    #[test]
    fn test_timing_safe_different_content() {
        assert!(!ash_timing_safe_equal(b"hello", b"world"));
    }

    #[test]
    fn test_timing_safe_first_byte_different() {
        assert!(!ash_timing_safe_equal(b"aello", b"hello"));
    }

    #[test]
    fn test_timing_safe_last_byte_different() {
        assert!(!ash_timing_safe_equal(b"hellp", b"hello"));
    }

    #[test]
    fn test_timing_safe_different_lengths() {
        assert!(!ash_timing_safe_equal(b"hi", b"hello"));
    }

    #[test]
    fn test_timing_safe_max_size() {
        let a = vec![0x41u8; 2048];
        let b = vec![0x41u8; 2048];
        assert!(ash_timing_safe_equal(&a, &b));
    }

    #[test]
    fn test_timing_safe_over_max_size() {
        let a = vec![0x41u8; 2049];
        let b = vec![0x41u8; 2049];
        assert!(!ash_timing_safe_equal(&a, &b));
    }
}

// ============================================================================
// SECTION 10: MASS FUZZ TESTING
// ============================================================================

mod mass_fuzz {
    use super::*;

    #[test]
    fn fuzz_json_1000_iterations() {
        for _ in 0..1000 {
            let len = rand::thread_rng().gen_range(1..1000);
            let random_str: String = (0..len).map(|_| rand::thread_rng().gen::<char>()).collect();
            let _ = ash_canonicalize_json(&random_str);
        }
    }

    #[test]
    fn fuzz_query_1000_iterations() {
        for _ in 0..1000 {
            let len = rand::thread_rng().gen_range(1..500);
            let random_str: String = (0..len).map(|_| rand::thread_rng().gen::<char>()).collect();
            let _ = ash_canonicalize_query(&random_str);
        }
    }

    #[test]
    fn fuzz_binding_1000_iterations() {
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
        for _ in 0..1000 {
            let method = methods.choose(&mut thread_rng()).unwrap();
            let path_len = rand::thread_rng().gen_range(1..100);
            let path = format!("{}{}", "/", &"a/".repeat(path_len));
            let query_len = rand::thread_rng().gen_range(0..100);
            let query: String = (0..query_len).map(|_| rand::thread_rng().gen::<char>()).collect();
            let _ = ash_normalize_binding(method, &path, &query);
        }
    }

    #[test]
    fn fuzz_nonce_validation_500_iterations() {
        for _ in 0..500 {
            let len = rand::thread_rng().gen_range(1..600);
            let nonce: String = (0..len).map(|_| {
                let c = rand::thread_rng().gen_range(0..16);
                char::from_digit(c, 16).unwrap()
            }).collect();
            let _ = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        }
    }
}

// ============================================================================
// SECTION 11: CONCURRENCY STRESS TESTS
// ============================================================================

mod concurrency_stress {
    use super::*;
    use std::thread;

    #[test]
    fn test_concurrent_canonicalization() {
        let handles: Vec<_> = (0..100).map(|i| {
            thread::spawn(move || {
                let json = format!(r#"{{"id":{}}}"#, i);
                ash_canonicalize_json(&json).unwrap()
            })
        }).collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_hashing() {
        let handles: Vec<_> = (0..100).map(|i| {
            thread::spawn(move || {
                let data = format!("data{}", i);
                ash_hash_body(&data)
            })
        }).collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let unique: HashSet<_> = results.iter().cloned().collect();
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn test_concurrent_proof_generation() {
        let nonce = "a".repeat(32);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let body_hash = ash_hash_body("test");

        let handles: Vec<_> = (0..100).map(|i| {
            let secret = secret.clone();
            let body_hash = body_hash.clone();
            thread::spawn(move || {
                let timestamp = (1700000000 + i).to_string();
                ash_build_proof(&secret, &timestamp, "POST|/|", &body_hash).unwrap()
            })
        }).collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let unique: HashSet<_> = results.iter().cloned().collect();
        assert_eq!(unique.len(), 100);
    }
}

// ============================================================================
// SECTION 12: COMPREHENSIVE ROUND-TRIP TESTS
// ============================================================================

mod comprehensive_roundtrip {
    use super::*;

    #[test]
    fn roundtrip_basic_get() {
        let nonce = "a".repeat(32);
        let context_id = "ctx";
        let binding = "GET|/api/users|";
        let timestamp = "1700000000";
        let body = r#"{"page":1}"#;
        let body_hash = ash_hash_body(body);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn roundtrip_post_with_body() {
        let nonce = "a".repeat(32);
        let context_id = "ctx";
        let binding = "POST|/api/users|";
        let timestamp = "1700000000";
        let body = r#"{"name":"John","email":"john@example.com"}"#;
        let canonical = ash_canonicalize_json(body).unwrap();
        let body_hash = ash_hash_body(&canonical);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn roundtrip_100_different_requests() {
        for i in 0..100 {
            let nonce = format!("{:032x}", i);
            let context_id = format!("ctx_{}", i);
            let binding = format!("POST|/api/resource{}|", i);
            let timestamp = (1700000000 + i).to_string();
            let body = format!(r#"{{"id":{}}}"#, i);
            let body_hash = ash_hash_body(&body);

            let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
            let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();
            let valid = ash_verify_proof(&nonce, &context_id, &binding, &timestamp, &body_hash, &proof).unwrap();
            assert!(valid, "Request {} should verify", i);
        }
    }
}
