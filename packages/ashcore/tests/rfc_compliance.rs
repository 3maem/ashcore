//! RFC Compliance Tests for ASH Rust SDK
//!
//! Verifies compliance with:
//! - RFC 8785: JSON Canonicalization Scheme (JCS)
//! - RFC 4648: Base16 (Hex) Encoding
//! - RFC 2104: HMAC
//! - RFC 3986: URI Encoding

use ashcore::{
    ash_canonicalize_json, ash_canonicalize_query, ash_canonicalize_urlencoded,
    ash_hash_body, ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_timing_safe_equal, ash_normalize_binding,
};

// =========================================================================
// RFC 8785: JSON Canonicalization Scheme (JCS)
// =========================================================================

mod rfc8785 {
    use super::*;

    // 3.2.2.1 Primitive Literals
    #[test]
    fn test_serialize_null() {
        let result = ash_canonicalize_json(r#"{"value":null}"#).unwrap();
        assert!(result.contains("null"));
    }

    #[test]
    fn test_serialize_true() {
        let result = ash_canonicalize_json(r#"{"value":true}"#).unwrap();
        assert!(result.contains("true"));
    }

    #[test]
    fn test_serialize_false() {
        let result = ash_canonicalize_json(r#"{"value":false}"#).unwrap();
        assert!(result.contains("false"));
    }

    // 3.2.2.2 Numbers
    #[test]
    fn test_serialize_integer_without_decimal() {
        let result = ash_canonicalize_json(r#"{"value":42}"#).unwrap();
        assert_eq!(result, r#"{"value":42}"#);
    }

    #[test]
    fn test_normalize_negative_zero() {
        let result = ash_canonicalize_json(r#"{"value":-0}"#).unwrap();
        assert!(!result.contains("-0"));
        assert!(result.contains(":0"));
    }

    #[test]
    fn test_serialize_float_minimal() {
        let result = ash_canonicalize_json(r#"{"value":3.14}"#).unwrap();
        assert_eq!(result, r#"{"value":3.14}"#);
    }

    #[test]
    fn test_whole_float_becomes_integer() {
        let result = ash_canonicalize_json(r#"{"value":3.0}"#).unwrap();
        // Should be 3, not 3.0
        assert!(result.contains(":3}") || result.contains(":3,"));
    }

    // 3.2.2.3 Strings
    #[test]
    fn test_escape_newline() {
        let result = ash_canonicalize_json(r#"{"text":"line1\nline2"}"#).unwrap();
        assert!(result.contains("\\n"));
    }

    #[test]
    fn test_escape_backslash() {
        let result = ash_canonicalize_json(r#"{"text":"path\\file"}"#).unwrap();
        assert!(result.contains("\\\\"));
    }

    #[test]
    fn test_escape_quote() {
        let result = ash_canonicalize_json(r#"{"text":"say \"hello\""}"#).unwrap();
        assert!(result.contains("\\\""));
    }

    #[test]
    fn test_unicode_preserved() {
        let result = ash_canonicalize_json(r#"{"text":"日本語"}"#).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["text"], "日本語");
    }

    // 3.2.3 Arrays
    #[test]
    fn test_preserve_array_order() {
        let result = ash_canonicalize_json(r#"{"arr":[3,1,4,1,5,9]}"#).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        let arr: Vec<i64> = parsed["arr"].as_array().unwrap()
            .iter().map(|v| v.as_i64().unwrap()).collect();
        assert_eq!(arr, vec![3, 1, 4, 1, 5, 9]);
    }

    #[test]
    fn test_empty_array() {
        let result = ash_canonicalize_json(r#"{"arr":[]}"#).unwrap();
        assert_eq!(result, r#"{"arr":[]}"#);
    }

    #[test]
    fn test_nested_arrays() {
        let result = ash_canonicalize_json(r#"{"matrix":[[1,2],[3,4]]}"#).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["matrix"][0][0], 1);
        assert_eq!(parsed["matrix"][1][1], 4);
    }

    // 3.2.4 Objects
    #[test]
    fn test_sort_object_keys() {
        let result = ash_canonicalize_json(r#"{"z":1,"a":2,"m":3}"#).unwrap();
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_sort_nested_object_keys() {
        let result = ash_canonicalize_json(r#"{"outer":{"z":1,"a":2}}"#).unwrap();
        assert_eq!(result, r#"{"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_empty_object() {
        let result = ash_canonicalize_json(r#"{}"#).unwrap();
        assert_eq!(result, r#"{}"#);
    }

    #[test]
    fn test_remove_whitespace() {
        let result = ash_canonicalize_json(r#"{ "key" : "value" }"#).unwrap();
        assert!(!result.contains(' '));
        assert_eq!(result, r#"{"key":"value"}"#);
    }

    // 3.2.5 Unicode Normalization
    #[test]
    fn test_unicode_nfc_normalization() {
        // e + combining acute accent (NFD) should equal é (NFC)
        let nfd = r#"{"text":"cafe\u0301"}"#;
        let nfc = r#"{"text":"café"}"#;

        let result_nfd = ash_canonicalize_json(nfd).unwrap();
        let result_nfc = ash_canonicalize_json(nfc).unwrap();

        assert_eq!(result_nfd, result_nfc, "Should normalize to NFC");
    }
}

// =========================================================================
// RFC 4648: Base16 (Hex) Encoding
// =========================================================================

mod rfc4648 {
    use super::*;

    #[test]
    fn test_hash_lowercase_hex() {
        let hash = ash_hash_body("test");
        // Should be lowercase hex only
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_proof_lowercase_hex() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        // Should be lowercase hex only
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_hash_64_characters() {
        let hash = ash_hash_body("test");
        assert_eq!(hash.len(), 64, "SHA-256 hash should be 64 hex chars");
    }

    #[test]
    fn test_proof_64_characters() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        assert_eq!(proof.len(), 64, "HMAC-SHA256 proof should be 64 hex chars");
    }
}

// =========================================================================
// RFC 2104: HMAC
// =========================================================================

mod rfc2104 {
    use super::*;

    #[test]
    fn test_hmac_consistent_output() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let proof1 = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
        let proof2 = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        assert_eq!(proof1, proof2, "HMAC should be deterministic");
    }

    #[test]
    fn test_hmac_256_bit_output() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        // 64 hex chars = 32 bytes = 256 bits
        assert_eq!(proof.len(), 64);
    }

    #[test]
    fn test_different_keys_different_output() {
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let nonce1 = "a".repeat(64);
        let nonce2 = "b".repeat(64);
        let context_id = "ctx_test";

        let secret1 = ash_derive_client_secret(&nonce1, context_id, binding).unwrap();
        let secret2 = ash_derive_client_secret(&nonce2, context_id, binding).unwrap();

        let proof1 = ash_build_proof(&secret1, timestamp, binding, &body_hash).unwrap();
        let proof2 = ash_build_proof(&secret2, timestamp, binding, &body_hash).unwrap();

        assert_ne!(proof1, proof2, "Different keys should produce different proofs");
    }
}

// =========================================================================
// RFC 3986: URI Encoding
// =========================================================================

mod rfc3986 {
    use super::*;

    #[test]
    fn test_uppercase_percent_encoding() {
        let result = ash_canonicalize_query("key=%2f").unwrap();
        assert_eq!(result, "key=%2F", "Should uppercase hex digits");
    }

    #[test]
    fn test_preserve_uppercase_encoding() {
        let result = ash_canonicalize_query("key=%2F").unwrap();
        assert_eq!(result, "key=%2F");
    }

    #[test]
    fn test_double_encoded_preserved() {
        let result = ash_canonicalize_query("key=%252F").unwrap();
        assert!(result.contains("%252F"), "Double encoding should be preserved");
    }

    #[test]
    fn test_ampersand_separator() {
        let result = ash_canonicalize_query("a=1&b=2&c=3").unwrap();
        assert!(result.contains('&'));
    }

    #[test]
    fn test_equals_in_value() {
        let result = ash_canonicalize_query("equation=1%2B1%3D2").unwrap();
        assert!(result.contains("equation="));
    }

    #[test]
    fn test_strip_fragment() {
        let result = ash_canonicalize_query("a=1#section").unwrap();
        assert!(!result.contains('#'));
        assert_eq!(result, "a=1");
    }

    #[test]
    fn test_strip_leading_question_mark() {
        let result = ash_canonicalize_query("?a=1&b=2").unwrap();
        assert!(!result.contains('?'));
        assert_eq!(result, "a=1&b=2");
    }
}

// =========================================================================
// ashcore Specification
// =========================================================================

mod ash_protocol {
    use super::*;

    // Section 3.1: Nonce Requirements
    #[test]
    fn test_nonce_256_bits() {
        // 64 hex chars = 32 bytes = 256 bits
        let nonce = "a".repeat(64);
        assert_eq!(nonce.len(), 64);

        // Should be accepted
        let result = ash_derive_client_secret(&nonce, "ctx", "POST|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_nonce_hex_only() {
        let valid_nonce = "0123456789abcdef".repeat(4);
        let result = ash_derive_client_secret(&valid_nonce, "ctx", "POST|/|");
        assert!(result.is_ok());

        let invalid_nonce = "ghijklmnopqrstuv".repeat(4);
        let result = ash_derive_client_secret(&invalid_nonce, "ctx", "POST|/|");
        assert!(result.is_err());
    }

    // Section 4.1: Binding Format
    #[test]
    fn test_binding_format() {
        let binding = ash_normalize_binding("POST", "/api/users", "page=1").unwrap();
        let parts: Vec<&str> = binding.split('|').collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "POST");
        assert_eq!(parts[1], "/api/users");
        assert_eq!(parts[2], "page=1");
    }

    #[test]
    fn test_binding_method_uppercase() {
        let binding = ash_normalize_binding("get", "/api", "").unwrap();
        assert!(binding.starts_with("GET|"));
    }

    #[test]
    fn test_binding_trailing_pipe() {
        let binding = ash_normalize_binding("GET", "/api", "").unwrap();
        assert_eq!(binding, "GET|/api|");
    }

    // Section 4.2: Proof Construction
    #[test]
    fn test_proof_hmac_sha256() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = "1700000000";
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        // Verify format: 64 hex chars
        assert_eq!(proof.len(), 64);
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify it validates
        let valid = ash_verify_proof(&nonce, context_id, binding, timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }
}

// =========================================================================
// Timing Safety
// =========================================================================

mod timing_safety {
    use super::*;

    #[test]
    fn test_constant_time_comparison() {
        assert!(ash_timing_safe_equal(b"abc", b"abc"));
        assert!(!ash_timing_safe_equal(b"abc", b"def"));
        assert!(!ash_timing_safe_equal(b"abc", b"abcd"));
    }

    #[test]
    fn test_symmetric_comparison() {
        let result1 = ash_timing_safe_equal(b"a", b"b");
        let result2 = ash_timing_safe_equal(b"b", b"a");
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_empty_string_comparison() {
        assert!(ash_timing_safe_equal(b"", b""));
        assert!(!ash_timing_safe_equal(b"", b"a"));
    }
}

// =========================================================================
// URL-Encoded Body Compliance
// =========================================================================

mod urlencoded {
    use super::*;

    #[test]
    fn test_plus_as_literal() {
        let result = ash_canonicalize_urlencoded("key=a+b").unwrap();
        assert!(result.contains("%2B"), "+ should become %2B");
    }

    #[test]
    fn test_preserve_percent20() {
        let result = ash_canonicalize_urlencoded("key=a%20b").unwrap();
        assert!(result.contains("%20"));
    }

    #[test]
    fn test_sort_parameters() {
        let result = ash_canonicalize_urlencoded("z=3&a=1&m=2").unwrap();
        assert_eq!(result, "a=1&m=2&z=3");
    }
}
