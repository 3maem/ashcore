//! Fuzzing Tests for ASH Rust SDK
//!
//! Tests random inputs, boundary conditions, and malformed data handling.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query, ash_canonicalize_urlencoded,
    ash_hash_body, ash_normalize_binding,
    ash_extract_scoped_fields,
};
use rand::Rng;

// =========================================================================
// RANDOM INPUT FUZZING
// =========================================================================

mod random_input {
    use super::*;

    fn random_string(len: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen_range(0x20..0x7F) as u8 as char).collect()
    }

    fn random_hex(len: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| {
            let c = rng.gen_range(0..16);
            char::from_digit(c, 16).unwrap()
        }).collect()
    }

    #[test]
    fn test_fuzz_json_canonicalization() {
        for _ in 0..1000 {
            let random_input = random_string(rand::thread_rng().gen_range(1..200));
            // Should not panic, either Ok or Err
            let _ = ash_canonicalize_json(&random_input);
        }
    }

    #[test]
    fn test_fuzz_valid_json_structures() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let key = format!("key{}", rng.gen_range(0..100));
            let value = rng.gen_range(0..10000);
            let json = format!(r#"{{"{}":{}}}"#, key, value);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Valid JSON should canonicalize: {}", json);
        }
    }

    #[test]
    fn test_fuzz_query_canonicalization() {
        for _ in 0..1000 {
            let random_input = random_string(rand::thread_rng().gen_range(1..200));
            // Should not panic
            let _ = ash_canonicalize_query(&random_input);
        }
    }

    #[test]
    fn test_fuzz_valid_query_strings() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let key = format!("key{}", rng.gen_range(0..100));
            let value = format!("value{}", rng.gen_range(0..100));
            let query = format!("{}={}", key, value);
            let result = ash_canonicalize_query(&query);
            assert!(result.is_ok(), "Valid query should canonicalize: {}", query);
        }
    }

    #[test]
    fn test_fuzz_urlencoded_canonicalization() {
        for _ in 0..1000 {
            let random_input = random_string(rand::thread_rng().gen_range(1..200));
            // Should not panic
            let _ = ash_canonicalize_urlencoded(&random_input);
        }
    }

    #[test]
    fn test_fuzz_binding_normalization() {
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let method = methods[rng.gen_range(0..methods.len())];
            let path = format!("/api/{}", random_string(rng.gen_range(1..50)));
            let query = random_string(rng.gen_range(0..50));

            // Should not panic
            let _ = ash_normalize_binding(method, &path, &query);
        }
    }

    #[test]
    fn test_fuzz_nonce_validation() {
        for _ in 0..1000 {
            let nonce = random_hex(rand::thread_rng().gen_range(0..200));
            // Should not panic
            let _ = ash_derive_client_secret(&nonce, "ctx_test", "GET|/|");
        }
    }

    #[test]
    fn test_fuzz_body_hashing() {
        for _ in 0..1000 {
            let body = random_string(rand::thread_rng().gen_range(0..1000));
            let hash = ash_hash_body(&body);
            assert_eq!(hash.len(), 64, "Hash should always be 64 chars");
        }
    }

    #[test]
    fn test_fuzz_timestamps() {
        let mut rng = rand::thread_rng();
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

        for _ in 0..1000 {
            let timestamp = format!("{}", rng.gen_range(0i64..i64::MAX));
            // Should not panic
            let _ = ash_build_proof(&secret, &timestamp, "POST|/|", &"b".repeat(64));
        }
    }

    #[test]
    fn test_fuzz_proof_verification() {
        let nonce = "a".repeat(64);

        for _ in 0..1000 {
            let random_proof = random_hex(64);
            let timestamp = chrono::Utc::now().timestamp().to_string();
            let body_hash = "b".repeat(64);

            // Should not panic, should return false for random proof
            let result = ash_verify_proof(&nonce, "ctx", "POST|/|", &timestamp, &body_hash, &random_proof);
            if let Ok(valid) = result {
                assert!(!valid, "Random proof should not verify");
            }
        }
    }

    #[test]
    fn test_fuzz_scope_extraction() {
        let mut rng = rand::thread_rng();

        for _ in 0..500 {
            let num_fields = rng.gen_range(1..10);
            let mut obj = serde_json::Map::new();
            let mut scope_fields = Vec::new();

            for i in 0..num_fields {
                let key = format!("field{}", i);
                obj.insert(key.clone(), serde_json::json!(rng.gen_range(0..100)));
                if rng.gen_bool(0.5) {
                    scope_fields.push(key);
                }
            }

            let payload = serde_json::Value::Object(obj);
            let scope_refs: Vec<&str> = scope_fields.iter().map(|s| s.as_str()).collect();

            // Should not panic
            let _ = ash_extract_scoped_fields(&payload, &scope_refs);
        }
    }
}

// =========================================================================
// BOUNDARY TESTING
// =========================================================================

mod boundary_tests {
    use super::*;

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
    fn test_empty_string() {
        let result = ash_canonicalize_json("");
        assert!(result.is_err(), "Empty string is not valid JSON");
    }

    #[test]
    fn test_whitespace_only() {
        let result = ash_canonicalize_json("   ");
        assert!(result.is_err(), "Whitespace only is not valid JSON");
    }

    #[test]
    fn test_null_json() {
        let result = ash_canonicalize_json("null");
        assert!(result.is_ok());
    }

    #[test]
    fn test_boolean_true() {
        let result = ash_canonicalize_json("true");
        assert!(result.is_ok());
    }

    #[test]
    fn test_boolean_false() {
        let result = ash_canonicalize_json("false");
        assert!(result.is_ok());
    }

    #[test]
    fn test_number_zero() {
        let result = ash_canonicalize_json("0");
        assert!(result.is_ok());
    }

    #[test]
    fn test_number_negative_zero() {
        let result = ash_canonicalize_json("-0");
        assert!(result.is_ok());
        // Should normalize to 0
        assert!(!result.unwrap().contains("-0"));
    }

    #[test]
    fn test_minimum_nonce() {
        let nonce = "a".repeat(32);  // Minimum 32 hex chars
        let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_maximum_nonce() {
        let nonce = "a".repeat(512);  // Maximum 512 hex chars (MAX_NONCE_LENGTH)
        let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_just_under_minimum() {
        let nonce = "a".repeat(31);
        let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_just_over_maximum() {
        // MAX_NONCE_LENGTH is 512 hex characters
        let nonce = "a".repeat(513);
        let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_query_string() {
        let result = ash_canonicalize_query("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_query_only_question_mark() {
        let result = ash_canonicalize_query("?");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_empty_body_hash() {
        let hash = ash_hash_body("");
        assert_eq!(hash.len(), 64);
        // SHA-256 of empty string
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_single_character_body() {
        let hash = ash_hash_body("a");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_very_long_json_key() {
        let long_key = "k".repeat(1000);
        let json = format!(r#"{{"{}":{}}}"#, long_key, 1);
        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_json_string_value() {
        let long_value = "v".repeat(10000);
        let json = format!(r#"{{"key":"{}"}}"#, long_value);
        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }
}

// =========================================================================
// UNICODE EDGE CASES
// =========================================================================

mod unicode_fuzzing {
    use super::*;

    #[test]
    fn test_all_ascii_printable() {
        // All printable ASCII characters
        let printable: String = (0x20u8..0x7F).map(|c| c as char).collect();
        let json = format!(r#"{{"text":"{}"}}"#, printable.replace('\\', "\\\\").replace('"', "\\\""));
        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_control_characters() {
        // Control characters should be escaped
        for c in 0x00u8..0x20 {
            let json = format!(r#"{{"text":"\u{:04x}"}}"#, c);
            let _result = ash_canonicalize_json(&json);
            // Most should work (escaped), some might fail
        }
    }

    #[test]
    fn test_high_unicode_codepoints() {
        // High Unicode codepoints
        let codepoints = [
            '\u{1F600}',  // 😀
            '\u{1F4A9}',  // 💩
            '\u{10000}',  // Linear B
            '\u{1F1FA}',  // Regional indicator U
        ];

        for cp in codepoints {
            let json = format!(r#"{{"emoji":"{}"}}"#, cp);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Should handle codepoint U+{:X}", cp as u32);
        }
    }

    #[test]
    fn test_combining_marks() {
        // Various combining marks
        let combos = [
            "e\u{0301}",    // e + acute
            "n\u{0303}",    // n + tilde
            "o\u{0308}",    // o + diaeresis
            "a\u{0300}",    // a + grave
        ];

        for combo in combos {
            let json = format!(r#"{{"text":"{}"}}"#, combo);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_zero_width_characters() {
        let zero_width = [
            '\u{200B}',  // Zero width space
            '\u{200C}',  // Zero width non-joiner
            '\u{200D}',  // Zero width joiner
            '\u{FEFF}',  // BOM / Zero width no-break space
        ];

        for zw in zero_width {
            let json = format!(r#"{{"text":"a{}b"}}"#, zw);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_rtl_characters() {
        let rtl_texts = [
            "مرحبا",      // Arabic
            "שלום",       // Hebrew
            "ہیلو",       // Urdu
        ];

        for text in rtl_texts {
            let json = format!(r#"{{"text":"{}"}}"#, text);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_mixed_scripts() {
        let json = r#"{"en":"Hello","jp":"こんにちは","cn":"你好","ar":"مرحبا"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }
}

// =========================================================================
// MALFORMED INPUT HANDLING
// =========================================================================

mod malformed_input {
    use super::*;

    #[test]
    fn test_unclosed_json_object() {
        let result = ash_canonicalize_json("{\"key\":1");
        assert!(result.is_err());
    }

    #[test]
    fn test_unclosed_json_array() {
        let result = ash_canonicalize_json("[1,2,3");
        assert!(result.is_err());
    }

    #[test]
    fn test_trailing_comma_object() {
        let result = ash_canonicalize_json(r#"{"key":1,}"#);
        // Trailing comma is invalid JSON
        assert!(result.is_err());
    }

    #[test]
    fn test_trailing_comma_array() {
        let result = ash_canonicalize_json("[1,2,3,]");
        assert!(result.is_err());
    }

    #[test]
    fn test_single_quotes() {
        let result = ash_canonicalize_json("{'key':'value'}");
        assert!(result.is_err());
    }

    #[test]
    fn test_unquoted_key() {
        let result = ash_canonicalize_json("{key:\"value\"}");
        assert!(result.is_err());
    }

    #[test]
    fn test_comments_in_json() {
        let result = ash_canonicalize_json(r#"{"key":1 /* comment */}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_keys() {
        // Duplicate keys - behavior may vary
        let json = r#"{"key":1,"key":2}"#;
        let result = ash_canonicalize_json(json);
        // Should succeed (last value wins per RFC 8259)
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_escape_sequence() {
        let result = ash_canonicalize_json(r#"{"text":"\x00"}"#);
        // \x is not valid JSON escape
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_unicode_escape() {
        let result = ash_canonicalize_json(r#"{"text":"\u00"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_leading_zeros_in_number() {
        let result = ash_canonicalize_json(r#"{"num":007}"#);
        // Leading zeros not allowed except for 0
        assert!(result.is_err());
    }

    #[test]
    fn test_plus_sign_in_number() {
        let result = ash_canonicalize_json(r#"{"num":+1}"#);
        // Plus sign not allowed in JSON
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_number() {
        let result = ash_canonicalize_json(r#"{"num":0xFF}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_characters() {
        let result = ash_derive_client_secret("ghijklmnopqrstuvwxyz123456789012", "ctx", "GET|/|");
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_with_spaces() {
        let nonce = "a".repeat(32) + " " + &"b".repeat(31);
        let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_with_newlines() {
        let nonce = "a".repeat(32) + "\n" + &"b".repeat(31);
        let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_err());
    }
}

// =========================================================================
// STRESS TESTS
// =========================================================================

mod stress_tests {
    use super::*;

    #[test]
    fn test_many_canonicalizations() {
        for i in 0..10000 {
            let json = format!(r#"{{"index":{}}}"#, i);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_many_hashes() {
        for i in 0..10000 {
            let body = format!("body content {}", i);
            let hash = ash_hash_body(&body);
            assert_eq!(hash.len(), 64);
        }
    }

    #[test]
    fn test_many_proof_generations() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let body_hash = "b".repeat(64);

        for i in 0..10000 {
            let timestamp = format!("{}", 1700000000 + i);
            let proof = ash_build_proof(&secret, &timestamp, "POST|/|", &body_hash);
            assert!(proof.is_ok());
        }
    }

    #[test]
    fn test_many_verifications() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api|";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let timestamp = "1700000000";
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        for _ in 0..10000 {
            let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
            assert!(valid);
        }
    }
}
