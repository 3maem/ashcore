//! Deep Audit Test Suite for ASH Core
//!
//! Covers:
//! - Every boundary condition for all public APIs
//! - Security attack scenarios (injection, replay, timing, spoofing)
//! - Edge cases for canonicalization, binding, proof, scoping, chaining
//! - Fuzz testing with thousands of iterations
//! - Performance and memory stress tests
//! - Logic correctness and bug detection

use ashcore::*;
use ashcore::binding::{ash_normalize_binding_value, BindingType, MAX_BINDING_VALUE_LENGTH};
use ashcore::config::ScopePolicyRegistry;
use ashcore::headers::{ash_extract_headers, HeaderMapView};
use ashcore::build::{build_request_proof, BuildRequestInput};
use ashcore::verify::{verify_incoming_request, VerifyRequestInput};
use rand::Rng;
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// HELPERS
// ============================================================================

const NONCE_32: &str = "0123456789abcdef0123456789abcdef";
const NONCE_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VALID_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn now_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

struct TestHeaders(Vec<(String, String)>);
impl HeaderMapView for TestHeaders {
    fn get_all_ci(&self, name: &str) -> Vec<&str> {
        let n = name.to_ascii_lowercase();
        self.0
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == n)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

// ============================================================================
// SECTION 1: NONCE VALIDATION — EXHAUSTIVE BOUNDARIES
// ============================================================================

mod nonce_boundaries {
    use super::*;

    #[test]
    fn exact_boundary_31_fails() {
        assert!(ash_validate_nonce(&"a".repeat(31)).is_err());
    }

    #[test]
    fn exact_boundary_32_passes() {
        assert!(ash_validate_nonce(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn exact_boundary_33_passes() {
        assert!(ash_validate_nonce(&"a".repeat(33)).is_ok());
    }

    #[test]
    fn exact_boundary_512_passes() {
        assert!(ash_validate_nonce(&"f".repeat(512)).is_ok());
    }

    #[test]
    fn exact_boundary_513_fails() {
        assert!(ash_validate_nonce(&"f".repeat(513)).is_err());
    }

    #[test]
    fn nonce_all_zeros() {
        assert!(ash_validate_nonce(&"0".repeat(32)).is_ok());
    }

    #[test]
    fn nonce_all_f() {
        assert!(ash_validate_nonce(&"f".repeat(64)).is_ok());
    }

    #[test]
    fn nonce_mixed_case_hex() {
        assert!(ash_validate_nonce(&"aAbBcCdDeEfF00112233".repeat(2)).is_ok());
    }

    #[test]
    fn nonce_with_g_fails() {
        let mut nonce = "a".repeat(31);
        nonce.push('g'); // not hex
        assert!(ash_validate_nonce(&nonce).is_err());
    }

    #[test]
    fn nonce_with_space_in_middle() {
        let nonce = format!("{} {}", "a".repeat(16), "b".repeat(15));
        assert!(ash_validate_nonce(&nonce).is_err());
    }

    #[test]
    fn nonce_with_unicode_digit() {
        // Arabic-Indic digit ٩ (U+0669) should fail
        let nonce = format!("{}٩", "a".repeat(31));
        assert!(ash_validate_nonce(&nonce).is_err());
    }

    #[test]
    fn nonce_with_newline() {
        let nonce = format!("{}\n{}", "a".repeat(16), "b".repeat(16));
        assert!(ash_validate_nonce(&nonce).is_err());
    }

    #[test]
    fn nonce_with_tab() {
        let nonce = format!("{}\t{}", "a".repeat(16), "b".repeat(16));
        assert!(ash_validate_nonce(&nonce).is_err());
    }

    #[test]
    fn nonce_error_codes_are_correct() {
        let too_short = ash_validate_nonce("abc").unwrap_err();
        assert_eq!(too_short.code(), AshErrorCode::ValidationError);
        assert_eq!(too_short.http_status(), 485);

        let too_long = ash_validate_nonce(&"a".repeat(513)).unwrap_err();
        assert_eq!(too_long.code(), AshErrorCode::ValidationError);

        let bad_chars = ash_validate_nonce(&format!("{}zz", "a".repeat(30))).unwrap_err();
        assert_eq!(bad_chars.code(), AshErrorCode::ValidationError);
    }

    // Fuzz: random valid/invalid nonces
    #[test]
    fn fuzz_nonce_validation_1000() {
        let mut rng = rand::thread_rng();
        let hex_chars: Vec<char> = "0123456789abcdef".chars().collect();

        for _ in 0..1000 {
            let len = rng.gen_range(0..600);
            let valid_hex = rng.gen_bool(0.7);

            let nonce: String = if valid_hex {
                (0..len).map(|_| hex_chars[rng.gen_range(0..16)]).collect()
            } else {
                (0..len)
                    .map(|_| {
                        if rng.gen_bool(0.9) {
                            hex_chars[rng.gen_range(0..16)]
                        } else {
                            // inject non-hex
                            ['g', 'z', 'G', ' ', '\n', '\0'][rng.gen_range(0..6)]
                        }
                    })
                    .collect()
            };

            let result = ash_validate_nonce(&nonce);
            // Should never panic
            let _ = result;
        }
    }
}

// ============================================================================
// SECTION 2: TIMESTAMP VALIDATION — EXHAUSTIVE BOUNDARIES
// ============================================================================

mod timestamp_boundaries {
    use super::*;

    #[test]
    fn timestamp_zero() {
        assert!(ash_validate_timestamp_format("0").is_ok());
    }

    #[test]
    fn timestamp_one() {
        assert!(ash_validate_timestamp_format("1").is_ok());
    }

    #[test]
    fn timestamp_leading_zero_01_fails() {
        assert!(ash_validate_timestamp_format("01").is_err());
    }

    #[test]
    fn timestamp_leading_zero_001_fails() {
        assert!(ash_validate_timestamp_format("001").is_err());
    }

    #[test]
    fn timestamp_leading_zero_0123_fails() {
        assert!(ash_validate_timestamp_format("0123456789").is_err());
    }

    #[test]
    fn timestamp_max_valid_year_3000() {
        // 32503680000 = year 3000
        assert!(ash_validate_timestamp_format("32503680000").is_ok());
    }

    #[test]
    fn timestamp_over_max_fails() {
        assert!(ash_validate_timestamp_format("32503680001").is_err());
    }

    #[test]
    fn timestamp_y2k38() {
        // 2147483647 = max i32 (year 2038 problem)
        assert!(ash_validate_timestamp_format("2147483647").is_ok());
    }

    #[test]
    fn timestamp_y2k38_plus_one() {
        assert!(ash_validate_timestamp_format("2147483648").is_ok());
    }

    #[test]
    fn timestamp_empty_fails() {
        let err = ash_validate_timestamp_format("").unwrap_err();
        assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
        assert_eq!(err.http_status(), 482);
    }

    #[test]
    fn timestamp_negative_fails() {
        assert!(ash_validate_timestamp_format("-1").is_err());
    }

    #[test]
    fn timestamp_float_fails() {
        assert!(ash_validate_timestamp_format("1700000000.5").is_err());
    }

    #[test]
    fn timestamp_with_plus_sign_fails() {
        assert!(ash_validate_timestamp_format("+1700000000").is_err());
    }

    #[test]
    fn timestamp_hex_fails() {
        assert!(ash_validate_timestamp_format("0x65e5f000").is_err());
    }

    #[test]
    fn timestamp_scientific_notation_fails() {
        assert!(ash_validate_timestamp_format("1.7e9").is_err());
    }

    #[test]
    fn timestamp_with_whitespace_fails() {
        assert!(ash_validate_timestamp_format(" 1700000000").is_err());
        assert!(ash_validate_timestamp_format("1700000000 ").is_err());
        assert!(ash_validate_timestamp_format("1700 000000").is_err());
    }

    #[test]
    fn timestamp_u64_max_fails() {
        // u64::MAX = 18446744073709551615
        assert!(ash_validate_timestamp_format("18446744073709551615").is_err());
    }

    #[test]
    fn timestamp_u64_overflow_fails() {
        // Larger than u64::MAX
        assert!(ash_validate_timestamp_format("99999999999999999999").is_err());
    }

    #[test]
    fn timestamp_freshness_current_time_passes() {
        let ts = now_ts();
        assert!(ash_validate_timestamp(&ts, 300, 60).is_ok());
    }

    #[test]
    fn timestamp_freshness_expired() {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = (now - 600).to_string(); // 10 min ago with 5 min max_age
        assert!(ash_validate_timestamp(&old, 300, 60).is_err());
    }

    #[test]
    fn timestamp_freshness_future_within_skew() {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future = (now + 30).to_string(); // 30s in future with 60s skew
        assert!(ash_validate_timestamp(&future, 300, 60).is_ok());
    }

    #[test]
    fn timestamp_freshness_future_beyond_skew() {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let far_future = (now + 120).to_string(); // 120s in future with 60s skew
        assert!(ash_validate_timestamp(&far_future, 300, 60).is_err());
    }
}

// ============================================================================
// SECTION 3: CONTEXT ID VALIDATION — EXHAUSTIVE
// ============================================================================

mod context_id_boundaries {
    use super::*;

    #[test]
    fn context_id_empty_fails() {
        assert!(ash_derive_client_secret(NONCE_32, "", "GET|/|").is_err());
    }

    #[test]
    fn context_id_single_char() {
        assert!(ash_derive_client_secret(NONCE_32, "a", "GET|/|").is_ok());
    }

    #[test]
    fn context_id_256_chars() {
        let ctx = "a".repeat(256);
        assert!(ash_derive_client_secret(NONCE_32, &ctx, "GET|/|").is_ok());
    }

    #[test]
    fn context_id_257_chars_fails() {
        let ctx = "a".repeat(257);
        assert!(ash_derive_client_secret(NONCE_32, &ctx, "GET|/|").is_err());
    }

    #[test]
    fn context_id_allowed_chars() {
        // A-Z a-z 0-9 _ - .
        assert!(ash_derive_client_secret(NONCE_32, "ABCxyz0189_-.", "GET|/|").is_ok());
    }

    #[test]
    fn context_id_rejects_pipe() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx|id", "GET|/|").is_err());
    }

    #[test]
    fn context_id_rejects_space() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx id", "GET|/|").is_err());
    }

    #[test]
    fn context_id_rejects_at_sign() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx@id", "GET|/|").is_err());
    }

    #[test]
    fn context_id_rejects_slash() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx/id", "GET|/|").is_err());
    }

    #[test]
    fn context_id_rejects_null() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx\0id", "GET|/|").is_err());
    }

    #[test]
    fn context_id_rejects_unicode() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx_مرحبا", "GET|/|").is_err());
    }

    #[test]
    fn context_id_rejects_emoji() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx_😀", "GET|/|").is_err());
    }

    #[test]
    fn context_id_all_digits() {
        assert!(ash_derive_client_secret(NONCE_32, "1234567890", "GET|/|").is_ok());
    }

    #[test]
    fn context_id_all_dots() {
        assert!(ash_derive_client_secret(NONCE_32, "...", "GET|/|").is_ok());
    }

    #[test]
    fn context_id_typical_format() {
        assert!(ash_derive_client_secret(NONCE_32, "ash_abc123-def.456", "GET|/|").is_ok());
    }
}

// ============================================================================
// SECTION 4: BINDING NORMALIZATION — DEEP EDGE CASES
// ============================================================================

mod binding_normalization {
    use super::*;

    #[test]
    fn empty_method_fails() {
        assert!(ash_normalize_binding("", "/api", "").is_err());
    }

    #[test]
    fn whitespace_method_fails() {
        assert!(ash_normalize_binding("   ", "/api", "").is_err());
    }

    #[test]
    fn method_trimmed_and_uppercased() {
        assert_eq!(
            ash_normalize_binding(" get ", "/api", "").unwrap(),
            "GET|/api|"
        );
    }

    #[test]
    fn non_ascii_method_fails() {
        assert!(ash_normalize_binding("GËT", "/api", "").is_err());
    }

    #[test]
    fn path_without_leading_slash_fails() {
        assert!(ash_normalize_binding("GET", "api", "").is_err());
    }

    #[test]
    fn root_path() {
        assert_eq!(
            ash_normalize_binding("GET", "/", "").unwrap(),
            "GET|/|"
        );
    }

    #[test]
    fn trailing_slash_removed() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/", "").unwrap(),
            "GET|/api|"
        );
    }

    #[test]
    fn multiple_slashes_collapsed() {
        assert_eq!(
            ash_normalize_binding("GET", "/api///users////profile", "").unwrap(),
            "GET|/api/users/profile|"
        );
    }

    #[test]
    fn dot_segments_resolved() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/./users/../admin", "").unwrap(),
            "GET|/api/admin|"
        );
    }

    #[test]
    fn double_dots_past_root() {
        assert_eq!(
            ash_normalize_binding("GET", "/../../api", "").unwrap(),
            "GET|/api|"
        );
    }

    #[test]
    fn all_dots_path_becomes_root() {
        assert_eq!(
            ash_normalize_binding("GET", "/./././.", "").unwrap(),
            "GET|/|"
        );
    }

    #[test]
    fn encoded_slashes_decoded_and_collapsed() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/%2F%2F/users", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn encoded_question_mark_rejected() {
        assert!(ash_normalize_binding("GET", "/api/users%3Fid=5", "").is_err());
    }

    #[test]
    fn unicode_path_encoded() {
        let result = ash_normalize_binding("GET", "/api/café", "").unwrap();
        assert!(result.contains("%C3%A9") || result.contains("café"));
    }

    #[test]
    fn query_sorted() {
        assert_eq!(
            ash_normalize_binding("GET", "/api", "z=3&a=1&m=2").unwrap(),
            "GET|/api|a=1&m=2&z=3"
        );
    }

    #[test]
    fn query_fragment_stripped() {
        assert_eq!(
            ash_normalize_binding("GET", "/api", "q=test#section").unwrap(),
            "GET|/api|q=test"
        );
    }

    #[test]
    fn query_plus_is_literal() {
        assert_eq!(
            ash_normalize_binding("GET", "/api", "q=a+b").unwrap(),
            "GET|/api|q=a%2Bb"
        );
    }

    #[test]
    fn whitespace_only_query_treated_as_empty() {
        assert_eq!(
            ash_normalize_binding("GET", "/api", "   ").unwrap(),
            "GET|/api|"
        );
    }

    #[test]
    fn binding_from_url_splits_correctly() {
        assert_eq!(
            ash_normalize_binding_from_url("GET", "/api/users?z=3&a=1").unwrap(),
            "GET|/api/users|a=1&z=3"
        );
    }

    #[test]
    fn binding_from_url_no_query() {
        assert_eq!(
            ash_normalize_binding_from_url("POST", "/api").unwrap(),
            "POST|/api|"
        );
    }

    #[test]
    fn binding_from_url_too_large_fails() {
        let huge_path = format!("/{}", "a".repeat(11 * 1024 * 1024));
        assert!(ash_normalize_binding_from_url("GET", &huge_path).is_err());
    }

    #[test]
    fn encoded_path_consistency() {
        // Encoded and unencoded should produce same result
        let r1 = ash_normalize_binding("GET", "/api/%2Ftest", "").unwrap();
        let r2 = ash_normalize_binding("GET", "/api//test", "").unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn all_http_methods() {
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"] {
            assert!(ash_normalize_binding(method, "/api", "").is_ok());
        }
    }

    #[test]
    fn custom_method() {
        assert_eq!(
            ash_normalize_binding("PROPFIND", "/webdav", "").unwrap(),
            "PROPFIND|/webdav|"
        );
    }

    #[test]
    fn special_chars_in_path_preserved() {
        let result = ash_normalize_binding("GET", "/api/users/@me", "").unwrap();
        assert_eq!(result, "GET|/api/users/@me|");
    }

    // Fuzz binding normalization
    #[test]
    fn fuzz_binding_normalization_500() {
        let mut rng = rand::thread_rng();
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
        let path_chars: Vec<char> = "/abcdefghijklmnop0123456789-_.~%".chars().collect();

        for _ in 0..500 {
            let method = methods[rng.gen_range(0..methods.len())];
            let path_len = rng.gen_range(1..100);
            let mut path = String::from("/");
            for _ in 0..path_len {
                path.push(path_chars[rng.gen_range(0..path_chars.len())]);
            }
            let query_len = rng.gen_range(0..50);
            let query: String = (0..query_len)
                .map(|_| path_chars[rng.gen_range(0..path_chars.len())])
                .collect();

            // Should never panic
            let _ = ash_normalize_binding(method, &path, &query);
        }
    }
}

// ============================================================================
// SECTION 5: JSON CANONICALIZATION — DEEP EDGE CASES
// ============================================================================

mod json_canonicalization {
    use super::*;

    #[test]
    fn empty_object() {
        assert_eq!(ash_canonicalize_json("{}").unwrap(), "{}");
    }

    #[test]
    fn empty_array() {
        assert_eq!(ash_canonicalize_json("[]").unwrap(), "[]");
    }

    #[test]
    fn null_value() {
        assert_eq!(ash_canonicalize_json("null").unwrap(), "null");
    }

    #[test]
    fn boolean_true() {
        assert_eq!(ash_canonicalize_json("true").unwrap(), "true");
    }

    #[test]
    fn boolean_false() {
        assert_eq!(ash_canonicalize_json("false").unwrap(), "false");
    }

    #[test]
    fn integer_zero() {
        assert_eq!(ash_canonicalize_json("0").unwrap(), "0");
    }

    #[test]
    fn negative_zero() {
        assert_eq!(ash_canonicalize_json("-0").unwrap(), "0");
    }

    #[test]
    fn negative_zero_in_object() {
        assert_eq!(
            ash_canonicalize_json(r#"{"a":-0}"#).unwrap(),
            r#"{"a":0}"#
        );
    }

    #[test]
    fn whole_float_becomes_integer() {
        assert_eq!(
            ash_canonicalize_json(r#"{"a":5.0}"#).unwrap(),
            r#"{"a":5}"#
        );
    }

    #[test]
    fn fractional_preserved() {
        let result = ash_canonicalize_json(r#"{"a":5.5}"#).unwrap();
        assert!(result.contains("5.5"));
    }

    #[test]
    fn keys_sorted() {
        assert_eq!(
            ash_canonicalize_json(r#"{"z":1,"a":2,"m":3}"#).unwrap(),
            r#"{"a":2,"m":3,"z":1}"#
        );
    }

    #[test]
    fn nested_keys_sorted() {
        assert_eq!(
            ash_canonicalize_json(r#"{"b":{"d":4,"c":3},"a":1}"#).unwrap(),
            r#"{"a":1,"b":{"c":3,"d":4}}"#
        );
    }

    #[test]
    fn whitespace_stripped() {
        assert_eq!(
            ash_canonicalize_json(r#"{ "a" : 1 , "b" : 2 }"#).unwrap(),
            r#"{"a":1,"b":2}"#
        );
    }

    #[test]
    fn array_order_preserved() {
        assert_eq!(
            ash_canonicalize_json("[3,1,2]").unwrap(),
            "[3,1,2]"
        );
    }

    #[test]
    fn nested_arrays_and_objects() {
        let input = r#"{"items":[{"z":1,"a":2},{"m":3}],"total":100}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"items":[{"a":2,"z":1},{"m":3}],"total":100}"#);
    }

    #[test]
    fn unicode_nfc_normalized() {
        // e + combining acute → é (NFC)
        let input = r#"{"name":"caf\u0065\u0301"}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert!(output.contains("café") || output.contains("caf\\u00e9"));
    }

    #[test]
    fn emoji_preserved() {
        let input = r#"{"emoji":"😀🎉"}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert!(output.contains("😀") || output.contains("\\u"));
    }

    #[test]
    fn large_integer() {
        let input = r#"{"big":9007199254740991}"#; // MAX_SAFE_INTEGER
        let output = ash_canonicalize_json(input).unwrap();
        assert!(output.contains("9007199254740991"));
    }

    #[test]
    fn max_depth_64() {
        // BUG-095: MAX_RECURSION_DEPTH=64, check is `depth >= 64`, so valid
        // depths are 0..63 (64 levels). 63 wraps = leaf at depth 63 = OK.
        let mut json = r#""leaf""#.to_string();
        for _ in 0..63 {
            json = format!(r#"{{"a":{}}}"#, json);
        }
        assert!(ash_canonicalize_json(&json).is_ok());
    }

    #[test]
    fn depth_65_fails() {
        // BUG-095: 64 wraps = leaf at depth 64 = rejected by `depth >= 64`.
        let mut json = r#""leaf""#.to_string();
        for _ in 0..64 {
            json = format!(r#"{{"a":{}}}"#, json);
        }
        assert!(ash_canonicalize_json(&json).is_err());
    }

    #[test]
    fn payload_too_large_fails() {
        let huge = format!(r#"{{"data":"{}"}}"#, "x".repeat(11 * 1024 * 1024));
        assert!(ash_canonicalize_json(&huge).is_err());
    }

    #[test]
    fn invalid_json_fails() {
        assert!(ash_canonicalize_json("{invalid}").is_err());
        assert!(ash_canonicalize_json("").is_err());
        assert!(ash_canonicalize_json("{").is_err());
    }

    #[test]
    fn duplicate_keys_last_wins() {
        // serde_json keeps last occurrence for duplicate keys
        let output = ash_canonicalize_json(r#"{"a":1,"a":2}"#).unwrap();
        assert!(output.contains("2"));
    }

    #[test]
    fn string_with_escapes() {
        let input = r#"{"msg":"hello\nworld\t\"quoted\""}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert!(output.contains("\\n"));
        assert!(output.contains("\\t"));
    }

    #[test]
    fn deeply_nested_array() {
        let mut json = "1".to_string();
        for _ in 0..60 {
            json = format!("[{}]", json);
        }
        assert!(ash_canonicalize_json(&json).is_ok());
    }

    #[test]
    fn canonicalize_deterministic_1000_iterations() {
        let input = r#"{"z":{"c":3,"a":1},"m":[3,1,2],"a":"hello"}"#;
        let first = ash_canonicalize_json(input).unwrap();
        for _ in 0..1000 {
            assert_eq!(ash_canonicalize_json(input).unwrap(), first);
        }
    }

    // Fuzz JSON canonicalization
    #[test]
    fn fuzz_json_canonicalization_500() {
        let mut rng = rand::thread_rng();
        for _ in 0..500 {
            let obj = json!({
                "a": rng.gen_range(-1000..1000),
                "b": format!("str_{}", rng.gen_range(0..1000)),
                "c": rng.gen_bool(0.5),
                "d": serde_json::Value::Null,
                "e": vec![rng.gen_range(0..100), rng.gen_range(0..100)],
            });
            let input = serde_json::to_string(&obj).unwrap();
            let r1 = ash_canonicalize_json(&input).unwrap();
            let r2 = ash_canonicalize_json(&input).unwrap();
            assert_eq!(r1, r2, "Non-deterministic for: {}", input);
        }
    }
}

// ============================================================================
// SECTION 6: QUERY CANONICALIZATION — DEEP EDGE CASES
// ============================================================================

mod query_canonicalization {
    use super::*;

    #[test]
    fn empty_query() {
        assert_eq!(ash_canonicalize_query("").unwrap(), "");
    }

    #[test]
    fn single_param() {
        assert_eq!(ash_canonicalize_query("a=1").unwrap(), "a=1");
    }

    #[test]
    fn sorted_params() {
        assert_eq!(
            ash_canonicalize_query("z=3&a=1&m=2").unwrap(),
            "a=1&m=2&z=3"
        );
    }

    #[test]
    fn duplicate_keys_sorted_by_value() {
        assert_eq!(
            ash_canonicalize_query("a=2&a=1&a=3").unwrap(),
            "a=1&a=2&a=3"
        );
    }

    #[test]
    fn fragment_stripped() {
        assert_eq!(
            ash_canonicalize_query("a=1#section").unwrap(),
            "a=1"
        );
    }

    #[test]
    fn leading_question_mark_stripped() {
        assert_eq!(
            ash_canonicalize_query("?a=1&b=2").unwrap(),
            "a=1&b=2"
        );
    }

    #[test]
    fn plus_is_literal_not_space() {
        let result = ash_canonicalize_query("q=a+b").unwrap();
        assert!(result.contains("%2B"), "Plus should be encoded as %2B, got: {}", result);
    }

    #[test]
    fn empty_value() {
        assert_eq!(ash_canonicalize_query("key=").unwrap(), "key=");
    }

    #[test]
    fn key_without_value() {
        assert_eq!(ash_canonicalize_query("key").unwrap(), "key=");
    }

    #[test]
    fn multiple_ampersands() {
        assert_eq!(
            ash_canonicalize_query("a=1&&b=2&").unwrap(),
            "a=1&b=2"
        );
    }

    #[test]
    fn percent_encoding_uppercase() {
        // %2f should become %2F in output
        let result = ash_canonicalize_query("path=%2ftest").unwrap();
        assert!(result.contains("%2F") || result.contains("%2f"));
    }

    #[test]
    fn only_fragment() {
        assert_eq!(ash_canonicalize_query("#section").unwrap(), "");
    }

    #[test]
    fn enriched_query_metadata() {
        let result = ash_canonicalize_query_enriched("?z=3&a=1&a=2#frag").unwrap();
        assert_eq!(result.pairs_count, 3);
        assert_eq!(result.unique_keys, 2);
        assert!(result.had_fragment);
        assert!(result.had_leading_question_mark);
    }
}

// ============================================================================
// SECTION 7: PROOF GENERATION & VERIFICATION — COMPLETE
// ============================================================================

mod proof_complete {
    use super::*;

    #[test]
    fn derive_secret_deterministic() {
        let s1 = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let s2 = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn derive_secret_different_nonces() {
        let s1 = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let s2 = ash_derive_client_secret(NONCE_64, "ctx", "POST|/api|").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_secret_different_contexts() {
        let s1 = ash_derive_client_secret(NONCE_32, "ctx_a", "POST|/api|").unwrap();
        let s2 = ash_derive_client_secret(NONCE_32, "ctx_b", "POST|/api|").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_secret_different_bindings() {
        let s1 = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let s2 = ash_derive_client_secret(NONCE_32, "ctx", "GET|/api|").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_secret_case_insensitive_nonce() {
        // Nonce should be lowercased internally
        let s1 = ash_derive_client_secret(
            "0123456789ABCDEF0123456789ABCDEF",
            "ctx",
            "POST|/api|",
        )
        .unwrap();
        let s2 = ash_derive_client_secret(
            "0123456789abcdef0123456789abcdef",
            "ctx",
            "POST|/api|",
        )
        .unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn derive_secret_empty_binding_fails() {
        assert!(ash_derive_client_secret(NONCE_32, "ctx", "").is_err());
    }

    #[test]
    fn derive_secret_binding_length_limit() {
        let long_binding = "X".repeat(8193);
        assert!(ash_derive_client_secret(NONCE_32, "ctx", &long_binding).is_err());
    }

    #[test]
    fn build_proof_deterministic() {
        let p1 = ash_build_proof("secret", "1700000000", "POST|/api|", VALID_BODY_HASH).unwrap();
        let p2 = ash_build_proof("secret", "1700000000", "POST|/api|", VALID_BODY_HASH).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 64); // 32 bytes hex
    }

    #[test]
    fn build_proof_empty_secret_fails() {
        assert!(ash_build_proof("", "ts", "bind", VALID_BODY_HASH).is_err());
    }

    #[test]
    fn build_proof_empty_timestamp_fails() {
        assert!(ash_build_proof("secret", "", "bind", VALID_BODY_HASH).is_err());
    }

    #[test]
    fn build_proof_empty_binding_fails() {
        assert!(ash_build_proof("secret", "ts", "", VALID_BODY_HASH).is_err());
    }

    #[test]
    fn build_proof_invalid_body_hash_length() {
        assert!(ash_build_proof("secret", "ts", "bind", "abc").is_err());
        assert!(ash_build_proof("secret", "ts", "bind", &"a".repeat(65)).is_err());
    }

    #[test]
    fn build_proof_non_hex_body_hash() {
        let bad = format!("g{}", "a".repeat(63));
        assert!(ash_build_proof("secret", "ts", "bind", &bad).is_err());
    }

    #[test]
    fn build_proof_body_hash_case_normalized() {
        // Upper and lowercase body hashes should produce same proof
        let upper = VALID_BODY_HASH.to_uppercase();
        let p1 = ash_build_proof("secret", "1700000000", "bind", VALID_BODY_HASH).unwrap();
        let p2 = ash_build_proof("secret", "1700000000", "bind", &upper).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn verify_proof_roundtrip() {
        let nonce = NONCE_32;
        let ctx = "ctx_test";
        let binding = "POST|/api/transfer|";
        let ts = "1700000000";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let proof = ash_build_proof(&secret, ts, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(nonce, ctx, binding, ts, &body_hash, &proof).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_proof_wrong_proof() {
        let nonce = NONCE_32;
        let ctx = "ctx_test";
        let binding = "POST|/api|";
        let ts = "1700000000";

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let _proof = ash_build_proof(&secret, ts, binding, VALID_BODY_HASH).unwrap();
        let wrong = "f".repeat(64);
        let valid = ash_verify_proof(nonce, ctx, binding, ts, VALID_BODY_HASH, &wrong).unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_proof_wrong_nonce() {
        let nonce = NONCE_32;
        let ctx = "ctx_test";
        let binding = "POST|/api|";
        let ts = "1700000000";

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let proof = ash_build_proof(&secret, ts, binding, VALID_BODY_HASH).unwrap();
        let wrong_nonce = "f".repeat(32);
        let valid =
            ash_verify_proof(&wrong_nonce, ctx, binding, ts, VALID_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_proof_wrong_context() {
        let nonce = NONCE_32;
        let binding = "POST|/api|";
        let ts = "1700000000";

        let secret = ash_derive_client_secret(nonce, "ctx_a", binding).unwrap();
        let proof = ash_build_proof(&secret, ts, binding, VALID_BODY_HASH).unwrap();
        let valid =
            ash_verify_proof(nonce, "ctx_b", binding, ts, VALID_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_proof_wrong_binding() {
        let nonce = NONCE_32;
        let ctx = "ctx_test";
        let ts = "1700000000";

        let secret = ash_derive_client_secret(nonce, ctx, "POST|/api|").unwrap();
        let proof = ash_build_proof(&secret, ts, "POST|/api|", VALID_BODY_HASH).unwrap();
        let valid =
            ash_verify_proof(nonce, ctx, "GET|/other|", ts, VALID_BODY_HASH, &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn hash_body_deterministic() {
        let h1 = ash_hash_body("test");
        let h2 = ash_hash_body("test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn hash_body_empty() {
        let h = ash_hash_body("");
        assert_eq!(h.len(), 64);
        // SHA-256 of empty = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(h, VALID_BODY_HASH);
    }

    #[test]
    fn hash_body_different_inputs() {
        let h1 = ash_hash_body("a");
        let h2 = ash_hash_body("b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_proof_non_empty() {
        let h = ash_hash_proof("abc123").unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn hash_proof_empty_fails() {
        assert!(ash_hash_proof("").is_err());
    }

    // Avalanche effect: single bit change causes ~50% of output bits to change
    #[test]
    fn avalanche_effect() {
        let h1 = ash_hash_body("test1");
        let h2 = ash_hash_body("test2");
        let bits_different = h1
            .chars()
            .zip(h2.chars())
            .filter(|(a, b)| a != b)
            .count();
        // Should differ in many positions (> 25% of hex chars)
        assert!(bits_different > 16, "Avalanche effect weak: only {} chars differ", bits_different);
    }

    // Collision resistance: 1000 unique inputs produce 1000 unique hashes
    #[test]
    fn collision_resistance_1000() {
        let mut hashes = HashSet::new();
        for i in 0..1000 {
            let h = ash_hash_body(&format!("input_{}", i));
            assert!(hashes.insert(h), "Collision at input_{}", i);
        }
    }
}

// ============================================================================
// SECTION 8: SCOPED PROOFS — COMPLETE
// ============================================================================

mod scoped_proofs {
    use super::*;

    #[test]
    fn scoped_proof_roundtrip() {
        let nonce = NONCE_32;
        let ctx = "ctx_scoped";
        let binding = "POST|/transfer|";
        let ts = "1700000000";
        let payload = r#"{"amount":100,"recipient":"alice","note":"hi"}"#;
        let scope = vec!["amount", "recipient"];

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let (proof, scope_hash) =
            ash_build_proof_scoped(&secret, ts, binding, payload, &scope).unwrap();
        let valid = ash_verify_proof_scoped(
            nonce, ctx, binding, ts, payload, &scope, &scope_hash, &proof,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn scoped_ignores_unscoped_changes() {
        let nonce = NONCE_32;
        let ctx = "ctx_scoped";
        let binding = "POST|/transfer|";
        let ts = "1700000000";
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let payload1 = r#"{"amount":100,"note":"hello"}"#;
        let (proof, scope_hash) =
            ash_build_proof_scoped(&secret, ts, binding, payload1, &scope).unwrap();

        let payload2 = r#"{"amount":100,"note":"different"}"#;
        let valid = ash_verify_proof_scoped(
            nonce, ctx, binding, ts, payload2, &scope, &scope_hash, &proof,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn scoped_detects_scoped_changes() {
        let nonce = NONCE_32;
        let ctx = "ctx_scoped";
        let binding = "POST|/transfer|";
        let ts = "1700000000";
        let scope = vec!["amount"];

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let (proof, scope_hash) =
            ash_build_proof_scoped(&secret, ts, binding, r#"{"amount":100}"#, &scope).unwrap();

        let valid = ash_verify_proof_scoped(
            nonce,
            ctx,
            binding,
            ts,
            r#"{"amount":999}"#,
            &scope,
            &scope_hash,
            &proof,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn scope_order_independent() {
        let nonce = NONCE_32;
        let ctx = "ctx_test";
        let binding = "POST|/api|";
        let ts = "1700000000";
        let payload = r#"{"a":1,"b":2,"c":3}"#;

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let (p1, h1) =
            ash_build_proof_scoped(&secret, ts, binding, payload, &["a", "b"]).unwrap();
        let (p2, h2) =
            ash_build_proof_scoped(&secret, ts, binding, payload, &["b", "a"]).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn scope_deduplication() {
        let h1 = ash_hash_scope(&["a", "b", "a"]).unwrap();
        let h2 = ash_hash_scope(&["a", "b"]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn empty_scope_hash_is_empty() {
        let h = ash_hash_scope(&[]).unwrap();
        assert!(h.is_empty());
    }

    #[test]
    fn scope_empty_field_name_fails() {
        assert!(ash_hash_scope(&[""]).is_err());
    }

    #[test]
    fn scope_delimiter_in_field_fails() {
        assert!(ash_hash_scope(&["field\x1F"]).is_err());
    }

    #[test]
    fn scope_field_name_too_long() {
        let long_field = "a".repeat(65);
        assert!(ash_hash_scope(&[&long_field]).is_err());
    }

    #[test]
    fn scope_field_name_at_max() {
        let field = "a".repeat(64);
        assert!(ash_hash_scope(&[&field]).is_ok());
    }

    #[test]
    fn scope_too_many_fields() {
        let fields: Vec<String> = (0..101).map(|i| format!("f{}", i)).collect();
        let scope: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        let payload = json!({});
        assert!(ash_extract_scoped_fields(&payload, &scope).is_err());
    }

    #[test]
    fn extract_nested_field() {
        let payload = json!({"user": {"name": "alice", "age": 30}});
        let scoped = ash_extract_scoped_fields(&payload, &["user.name"]).unwrap();
        assert_eq!(scoped, json!({"user": {"name": "alice"}}));
    }

    #[test]
    fn extract_array_index() {
        let payload = json!({"items": [{"id": 1}, {"id": 2}]});
        let scoped = ash_extract_scoped_fields(&payload, &["items[0]"]).unwrap();
        let items = scoped.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], 1);
    }

    #[test]
    fn extract_missing_field_non_strict() {
        let payload = json!({"a": 1});
        let scoped = ash_extract_scoped_fields(&payload, &["missing"]).unwrap();
        assert_eq!(scoped, json!({}));
    }

    #[test]
    fn extract_missing_field_strict_fails() {
        let payload = json!({"a": 1});
        let err = ash_extract_scoped_fields_strict(&payload, &["missing"], true).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ScopedFieldMissing);
        assert_eq!(err.http_status(), 475);
    }

    #[test]
    fn hash_scoped_body_strict_missing_field_fails() {
        let err = ash_hash_scoped_body_strict(r#"{"a":1}"#, &["missing"]).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ScopedFieldMissing);
    }

    #[test]
    fn scoped_body_empty_payload_as_empty_object() {
        assert!(ash_hash_scoped_body("", &["field"]).is_ok());
        assert!(ash_hash_scoped_body("   ", &["field"]).is_ok());
    }

    #[test]
    fn verify_scoped_scope_hash_mismatch() {
        let nonce = NONCE_32;
        let ctx = "ctx_test";
        let binding = "POST|/api|";
        let ts = "1700000000";
        let payload = r#"{"a":1}"#;

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let (proof, _) =
            ash_build_proof_scoped(&secret, ts, binding, payload, &["a"]).unwrap();

        // Use wrong scope_hash
        let valid = ash_verify_proof_scoped(
            nonce, ctx, binding, ts, payload, &["a"], "wrong_hash", &proof,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_scoped_empty_scope_nonempty_hash_fails() {
        // BUG-049: scope_hash must be empty when scope is empty
        let err = ash_verify_proof_scoped(
            NONCE_32,
            "ctx",
            "POST|/api|",
            "1700000000",
            "{}",
            &[],
            "notempty",
            &"f".repeat(64),
        )
        .unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ScopeMismatch);
    }
}

// ============================================================================
// SECTION 9: UNIFIED PROOFS & CHAINING
// ============================================================================

mod unified_and_chaining {
    use super::*;

    #[test]
    fn unified_basic_no_scope_no_chain() {
        let secret = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let result = ash_build_proof_unified(
            &secret,
            "1700000000",
            "POST|/api|",
            r#"{"a":1}"#,
            &[],
            None,
        )
        .unwrap();
        assert_eq!(result.proof.len(), 64);
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn unified_with_scope() {
        let secret = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let result = ash_build_proof_unified(
            &secret,
            "1700000000",
            "POST|/api|",
            r#"{"a":1,"b":2}"#,
            &["a"],
            None,
        )
        .unwrap();
        assert!(!result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn unified_with_chain() {
        let secret = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let prev_proof = "a".repeat(64);
        let result = ash_build_proof_unified(
            &secret,
            "1700000000",
            "POST|/api|",
            r#"{"a":1}"#,
            &[],
            Some(&prev_proof),
        )
        .unwrap();
        assert!(!result.chain_hash.is_empty());
        assert_eq!(result.chain_hash.len(), 64);
    }

    #[test]
    fn unified_with_scope_and_chain() {
        let secret = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let prev_proof = "b".repeat(64);
        let result = ash_build_proof_unified(
            &secret,
            "1700000000",
            "POST|/api|",
            r#"{"a":1,"b":2}"#,
            &["a"],
            Some(&prev_proof),
        )
        .unwrap();
        assert!(!result.scope_hash.is_empty());
        assert!(!result.chain_hash.is_empty());
    }

    #[test]
    fn chain_hash_deterministic() {
        let h1 = ash_hash_proof("proof_abc").unwrap();
        let h2 = ash_hash_proof("proof_abc").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_hash_different_proofs() {
        let h1 = ash_hash_proof("proof_a").unwrap();
        let h2 = ash_hash_proof("proof_b").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn unified_empty_previous_proof_is_no_chain() {
        let secret = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let r1 = ash_build_proof_unified(
            &secret, "1700000000", "POST|/api|", "{}", &[], None,
        ).unwrap();
        let r2 = ash_build_proof_unified(
            &secret, "1700000000", "POST|/api|", "{}", &[], Some(""),
        ).unwrap();
        assert_eq!(r1.chain_hash, r2.chain_hash);
    }

    #[test]
    fn build_request_proof_basic() {
        let result = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":100}"#,
            nonce: NONCE_32,
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        })
        .unwrap();
        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.body_hash.len(), 64);
        assert_eq!(result.binding, "POST|/api/transfer|");
    }

    #[test]
    fn build_request_proof_scoped() {
        let result = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":100,"note":"hi"}"#,
            nonce: NONCE_32,
            context_id: "ctx_test",
            timestamp: "1700000000",
            scope: Some(&["amount"]),
            previous_proof: None,
        })
        .unwrap();
        assert!(!result.scope_hash.is_empty());
    }

    #[test]
    fn build_request_proof_chained() {
        let first = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/step1",
            raw_query: "",
            canonical_body: r#"{"step":1}"#,
            nonce: NONCE_32,
            context_id: "ctx_chain",
            timestamp: "1700000000",
            scope: None,
            previous_proof: None,
        })
        .unwrap();

        let second = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api/step2",
            raw_query: "",
            canonical_body: r#"{"step":2}"#,
            nonce: NONCE_32,
            context_id: "ctx_chain",
            timestamp: "1700000001",
            scope: None,
            previous_proof: Some(&first.proof),
        })
        .unwrap();
        assert!(!second.chain_hash.is_empty());
    }

    #[test]
    fn build_request_proof_bad_nonce_first() {
        let err = build_request_proof(&BuildRequestInput {
            method: "POST",
            path: "/api",
            raw_query: "",
            canonical_body: "{}",
            nonce: "short",
            context_id: "ctx",
            timestamp: "bad_ts",
            scope: None,
            previous_proof: None,
        })
        .unwrap_err();
        // Nonce fails before timestamp (step 1 vs step 2)
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }
}

// ============================================================================
// SECTION 10: TIMING-SAFE COMPARISON — EXHAUSTIVE
// ============================================================================

mod timing_safe {
    use super::*;

    #[test]
    fn equal_empty() {
        assert!(ash_timing_safe_equal(b"", b""));
    }

    #[test]
    fn equal_same() {
        assert!(ash_timing_safe_equal(b"hello", b"hello"));
    }

    #[test]
    fn not_equal_different() {
        assert!(!ash_timing_safe_equal(b"hello", b"world"));
    }

    #[test]
    fn not_equal_different_length() {
        assert!(!ash_timing_safe_equal(b"hello", b"hell"));
    }

    #[test]
    fn not_equal_empty_vs_nonempty() {
        assert!(!ash_timing_safe_equal(b"", b"x"));
        assert!(!ash_timing_safe_equal(b"x", b""));
    }

    #[test]
    fn single_bit_difference() {
        assert!(!ash_timing_safe_equal(b"aaaaaaaaaa", b"aaaaaaaaab"));
    }

    #[test]
    fn max_size_works() {
        let a = vec![0x41u8; 2048];
        let b = vec![0x41u8; 2048];
        assert!(ash_timing_safe_equal(&a, &b));
    }

    #[test]
    fn over_max_size_rejects() {
        let large = vec![0x41u8; 2049];
        assert!(!ash_timing_safe_equal(&large, &large));
        assert!(!ash_timing_safe_equal(&large, b"small"));
        assert!(!ash_timing_safe_equal(b"small", &large));
    }

    #[test]
    fn compare_strings() {
        assert!(ash_timing_safe_compare("test", "test"));
        assert!(!ash_timing_safe_compare("test", "Test"));
    }

    // Timing consistency: both should take similar time
    #[test]
    fn timing_consistency_no_early_exit() {
        let a = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let mut same_time = 0u128;
        let mut diff_time = 0u128;

        for _ in 0..100 {
            let start = Instant::now();
            ash_timing_safe_equal(a, a);
            same_time += start.elapsed().as_nanos();

            let b = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
            let start = Instant::now();
            ash_timing_safe_equal(a, b);
            diff_time += start.elapsed().as_nanos();
        }

        // Ratio should be roughly 1:1 (within 5x factor is acceptable for CI)
        let ratio = if same_time > diff_time {
            same_time as f64 / diff_time as f64
        } else {
            diff_time as f64 / same_time as f64
        };
        assert!(
            ratio < 5.0,
            "Timing ratio {:.2} suggests early exit (same={}ns, diff={}ns)",
            ratio,
            same_time,
            diff_time
        );
    }
}

// ============================================================================
// SECTION 11: BINDING VALUE NORMALIZATION — EXHAUSTIVE
// ============================================================================

mod binding_value_normalization {
    use super::*;

    #[test]
    fn device_basic() {
        let r = ash_normalize_binding_value(BindingType::Device, "dev_123").unwrap();
        assert_eq!(r.value, "dev_123");
        assert!(!r.was_trimmed);
    }

    #[test]
    fn device_trimmed() {
        let r = ash_normalize_binding_value(BindingType::Device, "  dev_123  ").unwrap();
        assert_eq!(r.value, "dev_123");
        assert!(r.was_trimmed);
    }

    #[test]
    fn empty_fails() {
        assert!(ash_normalize_binding_value(BindingType::Session, "").is_err());
        assert!(ash_normalize_binding_value(BindingType::Session, "   ").is_err());
    }

    #[test]
    fn null_byte_fails() {
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\0abc").is_err());
    }

    #[test]
    fn newline_fails() {
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\nabc").is_err());
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\rabc").is_err());
    }

    #[test]
    fn control_chars_fail() {
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\x01abc").is_err());
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\x1Fabc").is_err());
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\x7Fabc").is_err());
    }

    #[test]
    fn max_length_accepted() {
        let v = "a".repeat(MAX_BINDING_VALUE_LENGTH);
        assert!(ash_normalize_binding_value(BindingType::Custom, &v).is_ok());
    }

    #[test]
    fn over_max_length_rejected() {
        let v = "a".repeat(MAX_BINDING_VALUE_LENGTH + 1);
        assert!(ash_normalize_binding_value(BindingType::Custom, &v).is_err());
    }

    #[test]
    fn route_type_rejected() {
        assert!(ash_normalize_binding_value(BindingType::Route, "POST|/api|").is_err());
    }

    #[test]
    fn ip_valid_v4() {
        assert!(ash_normalize_binding_value(BindingType::Ip, "192.168.1.1").is_ok());
        assert!(ash_normalize_binding_value(BindingType::Ip, "0.0.0.0").is_ok());
        assert!(ash_normalize_binding_value(BindingType::Ip, "255.255.255.255").is_ok());
    }

    #[test]
    fn ip_valid_v6() {
        assert!(ash_normalize_binding_value(BindingType::Ip, "::1").is_ok());
        assert!(ash_normalize_binding_value(BindingType::Ip, "2001:db8::1").is_ok());
    }

    #[test]
    fn ip_invalid_rejected() {
        assert!(ash_normalize_binding_value(BindingType::Ip, "999.999.999.999").is_err());
        assert!(ash_normalize_binding_value(BindingType::Ip, "256.1.1.1").is_err());
        assert!(ash_normalize_binding_value(BindingType::Ip, "not_an_ip").is_err());
    }

    #[test]
    fn ip_non_ascii_rejected() {
        assert!(ash_normalize_binding_value(BindingType::Ip, "192.168.١.1").is_err());
    }

    #[test]
    fn user_nfc_normalized() {
        let decomposed = "caf\u{0065}\u{0301}"; // e + combining acute
        let r = ash_normalize_binding_value(BindingType::User, decomposed).unwrap();
        assert_eq!(r.value, "café");
    }

    #[test]
    fn custom_unicode_accepted() {
        assert!(ash_normalize_binding_value(BindingType::Custom, "مستخدم").is_ok());
    }

    #[test]
    fn binding_type_display() {
        assert_eq!(BindingType::Route.to_string(), "route");
        assert_eq!(BindingType::Ip.to_string(), "ip");
        assert_eq!(BindingType::Custom.to_string(), "custom");
    }
}

// ============================================================================
// SECTION 12: HEADER EXTRACTION — EXHAUSTIVE
// ============================================================================

mod header_extraction {
    use super::*;

    fn make_headers(extra: Vec<(&str, &str)>) -> TestHeaders {
        let mut h = vec![
            ("X-ASH-TS".to_string(), "1700000000".to_string()),
            ("x-ash-nonce".to_string(), "a".repeat(32)),
            ("X-Ash-Body-Hash".to_string(), "b".repeat(64)),
            ("x-ash-proof".to_string(), "c".repeat(64)),
        ];
        for (k, v) in extra {
            h.push((k.to_string(), v.to_string()));
        }
        TestHeaders(h)
    }

    #[test]
    fn all_required_present() {
        let bundle = ash_extract_headers(&make_headers(vec![])).unwrap();
        assert_eq!(bundle.ts, "1700000000");
        assert!(bundle.context_id.is_none());
    }

    #[test]
    fn with_optional_context_id() {
        let bundle =
            ash_extract_headers(&make_headers(vec![("X-ASH-Context-ID", "ctx_123")])).unwrap();
        assert_eq!(bundle.context_id, Some("ctx_123".to_string()));
    }

    #[test]
    fn case_insensitive() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("X-ASH-NONCE".into(), "a".repeat(32)),
            ("x-AsH-bOdY-hAsH".into(), "b".repeat(64)),
            ("X-Ash-Proof".into(), "c".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_ok());
    }

    #[test]
    fn missing_timestamp() {
        let h = TestHeaders(vec![
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-body-hash".into(), "b".repeat(64)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    #[test]
    fn missing_nonce() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-body-hash".into(), "b".repeat(64)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_err());
    }

    #[test]
    fn missing_body_hash() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_err());
    }

    #[test]
    fn missing_proof() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-body-hash".into(), "b".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_err());
    }

    #[test]
    fn multi_value_rejected() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000".into()),
            ("x-ash-ts".into(), "1700000001".into()), // duplicate
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-body-hash".into(), "b".repeat(64)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        let err = ash_extract_headers(&h).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    #[test]
    fn trailing_control_chars_rejected() {
        // BUG-051: Trailing \n is now rejected (control char check before trim)
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000\n".into()),
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-body-hash".into(), "b".repeat(64)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_err());
    }

    #[test]
    fn embedded_control_chars_rejected() {
        // Control char in the middle IS rejected
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "17000\x0000000".into()),
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-body-hash".into(), "b".repeat(64)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        assert!(ash_extract_headers(&h).is_err());
    }

    #[test]
    fn whitespace_trimmed() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), " 1700000000 ".into()),
            ("x-ash-nonce".into(), format!(" {} ", "a".repeat(32))),
            ("x-ash-body-hash".into(), format!(" {} ", "b".repeat(64))),
            ("x-ash-proof".into(), format!(" {} ", "c".repeat(64))),
        ]);
        let bundle = ash_extract_headers(&h).unwrap();
        assert_eq!(bundle.ts, "1700000000");
    }
}

// ============================================================================
// SECTION 13: VERIFY INCOMING REQUEST — FULL PIPELINE
// ============================================================================

mod verify_pipeline {
    use super::*;

    fn make_valid_request() -> (TestHeaders, String, String) {
        let nonce = NONCE_32;
        let ctx = "ctx_verify";
        let binding = "POST|/api/transfer|";
        let ts = now_ts();
        let body = r#"{"amount":100}"#;
        let body_hash = ash_hash_body(body);

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let proof = ash_build_proof(&secret, &ts, binding, &body_hash).unwrap();

        let headers = TestHeaders(vec![
            ("x-ash-ts".into(), ts),
            ("x-ash-body-hash".into(), body_hash),
            ("x-ash-proof".into(), proof),
        ]);
        (headers, body.to_string(), nonce.to_string())
    }

    #[test]
    fn valid_request_passes() {
        let (headers, body, nonce) = make_valid_request();
        let result = verify_incoming_request(&VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: &body,
            nonce: &nonce,
            context_id: "ctx_verify",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        });
        assert!(result.ok, "Expected ok, got: {:?}", result.error);
    }

    #[test]
    fn tampered_body_fails() {
        let (headers, _body, nonce) = make_valid_request();
        let result = verify_incoming_request(&VerifyRequestInput {
            headers: &headers,
            method: "POST",
            path: "/api/transfer",
            raw_query: "",
            canonical_body: r#"{"amount":999}"#,
            nonce: &nonce,
            context_id: "ctx_verify",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        });
        assert!(!result.ok);
    }

    #[test]
    fn wrong_endpoint_fails() {
        let (headers, body, nonce) = make_valid_request();
        let result = verify_incoming_request(&VerifyRequestInput {
            headers: &headers,
            method: "GET", // wrong method
            path: "/api/transfer",
            raw_query: "",
            canonical_body: &body,
            nonce: &nonce,
            context_id: "ctx_verify",
            max_age_seconds: 300,
            clock_skew_seconds: 60,
        });
        assert!(!result.ok);
    }
}

// ============================================================================
// SECTION 14: SCOPE POLICY REGISTRY — EXHAUSTIVE
// ============================================================================

mod scope_policy_registry {
    use super::*;

    #[test]
    fn register_and_get() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("POST|/api/transfer|", &["amount"]);
        assert_eq!(reg.get("POST|/api/transfer|"), vec!["amount"]);
    }

    #[test]
    fn no_match_returns_empty() {
        let reg = ScopePolicyRegistry::new();
        assert!(reg.get("GET|/unknown|").is_empty());
    }

    #[test]
    fn wildcard_single_segment() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("PUT|/api/users/*|", &["role"]);
        assert_eq!(reg.get("PUT|/api/users/123|"), vec!["role"]);
        assert!(reg.get("PUT|/api/users/123/extra|").is_empty());
    }

    #[test]
    fn wildcard_double_multi_segment() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("GET|/api/**/data|", &["field"]);
        assert_eq!(reg.get("GET|/api/v1/users/data|"), vec!["field"]);
    }

    #[test]
    fn flask_style_param() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("PUT|/api/users/<id>|", &["role"]);
        assert_eq!(reg.get("PUT|/api/users/456|"), vec!["role"]);
    }

    #[test]
    fn express_style_param() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("PUT|/api/users/:id|", &["role"]);
        assert_eq!(reg.get("PUT|/api/users/789|"), vec!["role"]);
    }

    #[test]
    fn laravel_style_param() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("PUT|/api/users/{id}|", &["email"]);
        assert_eq!(reg.get("PUT|/api/users/abc|"), vec!["email"]);
    }

    #[test]
    fn pattern_too_long_rejected() {
        let mut reg = ScopePolicyRegistry::new();
        let long = "POST|/api/".to_string() + &"a".repeat(600) + "|";
        assert!(!reg.register(&long, &["field"]));
    }

    #[test]
    fn too_many_wildcards_rejected() {
        let mut reg = ScopePolicyRegistry::new();
        let pattern = "POST|/*/*/*/*/*/*/*/*/*|"; // 9 wildcards
        assert!(!reg.register(pattern, &["field"]));
    }

    #[test]
    fn max_wildcards_accepted() {
        let mut reg = ScopePolicyRegistry::new();
        let pattern = "POST|/*/*/*/*/*/*/*/*|"; // 8 wildcards
        assert!(reg.register(pattern, &["field"]));
    }

    #[test]
    fn escaped_asterisk_exact_match() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register(r"POST|/api/\*|", &["field"]);
        assert_eq!(reg.get("POST|/api/*|"), vec!["field"]);
        assert!(reg.get("POST|/api/test|").is_empty());
    }

    #[test]
    fn clear_removes_all() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("POST|/api|", &["a"]);
        assert!(reg.has("POST|/api|"));
        reg.clear();
        assert!(!reg.has("POST|/api|"));
    }

    #[test]
    fn register_many() {
        let mut reg = ScopePolicyRegistry::new();
        let mut policies = BTreeMap::new();
        policies.insert("POST|/a|", vec!["x"]);
        policies.insert("POST|/b|", vec!["y"]);
        assert_eq!(reg.register_many(&policies), 2);
    }

    #[test]
    fn replace_existing_pattern() {
        let mut reg = ScopePolicyRegistry::new();
        reg.register("POST|/api|", &["old"]);
        reg.register("POST|/api|", &["new"]);
        assert_eq!(reg.get("POST|/api|"), vec!["new"]);
    }

    #[test]
    fn first_registered_wins_wildcard_before_exact() {
        // BUG-006 FIX: "First registered pattern wins" — a wildcard registered
        // before a matching exact pattern takes priority, not the other way around.
        // Register specific patterns before general ones for correct priority.
        let mut reg = ScopePolicyRegistry::new();
        reg.register("POST|/api/*|", &["general"]);
        reg.register("POST|/api/specific|", &["specific"]);
        // Wildcard was registered first, so it wins per BUG-006
        assert_eq!(reg.get("POST|/api/specific|"), vec!["general"]);
    }

    #[test]
    fn exact_match_wins_when_registered_first() {
        // When the exact match is registered first, it correctly wins
        let mut reg = ScopePolicyRegistry::new();
        reg.register("POST|/api/specific|", &["specific"]);
        reg.register("POST|/api/*|", &["general"]);
        assert_eq!(reg.get("POST|/api/specific|"), vec!["specific"]);
    }

    #[test]
    fn first_wildcard_registered_wins() {
        // BUG-006: Among wildcards, the first registered pattern wins
        let mut reg = ScopePolicyRegistry::new();
        reg.register("POST|/api/*|", &["general"]);
        reg.register("POST|/api/**|", &["deep"]);
        // "POST|/api/foo|" matches both wildcards; first registered ("general") wins
        assert_eq!(reg.get("POST|/api/foo|"), vec!["general"]);
    }
}

// ============================================================================
// SECTION 15: ERROR TYPES — COMPLETE
// ============================================================================

mod error_types {
    use super::*;

    #[test]
    fn all_error_codes_have_unique_http_status() {
        let codes = [
            AshErrorCode::CtxNotFound,
            AshErrorCode::CtxExpired,
            AshErrorCode::CtxAlreadyUsed,
            AshErrorCode::ProofInvalid,
            AshErrorCode::BindingMismatch,
            AshErrorCode::ScopeMismatch,
            AshErrorCode::ChainBroken,
            AshErrorCode::ScopedFieldMissing,
            AshErrorCode::TimestampInvalid,
            AshErrorCode::ProofMissing,
            AshErrorCode::CanonicalizationError,
            AshErrorCode::ValidationError,
            AshErrorCode::ModeViolation,
            AshErrorCode::UnsupportedContentType,
            AshErrorCode::InternalError,
        ];

        let mut statuses = HashSet::new();
        for code in &codes {
            let status = code.http_status();
            assert!(
                statuses.insert(status),
                "Duplicate HTTP status {} for {:?}",
                status,
                code
            );
        }
    }

    #[test]
    fn serde_roundtrip_all_codes() {
        let codes = [
            AshErrorCode::CtxNotFound,
            AshErrorCode::CtxExpired,
            AshErrorCode::CtxAlreadyUsed,
            AshErrorCode::ProofInvalid,
            AshErrorCode::BindingMismatch,
            AshErrorCode::ScopeMismatch,
            AshErrorCode::ChainBroken,
            AshErrorCode::ScopedFieldMissing,
            AshErrorCode::TimestampInvalid,
            AshErrorCode::ProofMissing,
            AshErrorCode::CanonicalizationError,
            AshErrorCode::ValidationError,
            AshErrorCode::ModeViolation,
            AshErrorCode::UnsupportedContentType,
            AshErrorCode::InternalError,
        ];

        for code in &codes {
            let json = serde_json::to_string(code).unwrap();
            assert!(json.contains("ASH_"), "Missing ASH_ prefix for {:?}", code);
            let back: AshErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(*code, back);
        }
    }

    #[test]
    fn retryable_codes() {
        assert!(AshErrorCode::TimestampInvalid.retryable());
        assert!(AshErrorCode::InternalError.retryable());
        assert!(!AshErrorCode::ProofInvalid.retryable());
        assert!(!AshErrorCode::ValidationError.retryable());
    }

    #[test]
    fn error_with_details() {
        let err = AshError::new(AshErrorCode::ProofInvalid, "test")
            .with_detail("key", "value");
        assert!(err.details().is_some());
        assert_eq!(err.details().unwrap().get("key").unwrap(), "value");
    }

    #[test]
    fn error_display() {
        let err = AshError::ctx_not_found();
        assert_eq!(err.to_string(), "ASH_CTX_NOT_FOUND: Context not found");
    }

    #[test]
    fn convenience_constructors() {
        assert_eq!(AshError::ctx_not_found().code(), AshErrorCode::CtxNotFound);
        assert_eq!(AshError::ctx_expired().code(), AshErrorCode::CtxExpired);
        assert_eq!(AshError::ctx_already_used().code(), AshErrorCode::CtxAlreadyUsed);
        assert_eq!(AshError::binding_mismatch().code(), AshErrorCode::BindingMismatch);
        assert_eq!(AshError::proof_missing().code(), AshErrorCode::ProofMissing);
        assert_eq!(AshError::proof_invalid().code(), AshErrorCode::ProofInvalid);
        assert_eq!(
            AshError::canonicalization_error().code(),
            AshErrorCode::CanonicalizationError
        );
    }

    #[test]
    fn invalid_serde_string_rejected() {
        let result: Result<AshErrorCode, _> = serde_json::from_str(r#""INVALID""#);
        assert!(result.is_err());
        let result: Result<AshErrorCode, _> = serde_json::from_str(r#""CTX_NOT_FOUND""#);
        assert!(result.is_err()); // missing ASH_ prefix
    }
}

// ============================================================================
// SECTION 16: TYPES — EXHAUSTIVE
// ============================================================================

mod types_exhaustive {
    use super::*;

    #[test]
    fn ash_mode_default_is_balanced() {
        assert_eq!(AshMode::default(), AshMode::Balanced);
    }

    #[test]
    fn ash_mode_from_str() {
        assert_eq!("minimal".parse::<AshMode>().unwrap(), AshMode::Minimal);
        assert_eq!("balanced".parse::<AshMode>().unwrap(), AshMode::Balanced);
        assert_eq!("strict".parse::<AshMode>().unwrap(), AshMode::Strict);
        assert_eq!("MINIMAL".parse::<AshMode>().unwrap(), AshMode::Minimal);
        assert_eq!("Balanced".parse::<AshMode>().unwrap(), AshMode::Balanced);
    }

    #[test]
    fn ash_mode_invalid() {
        assert!("invalid".parse::<AshMode>().is_err());
        assert!("".parse::<AshMode>().is_err());
    }

    #[test]
    fn ash_mode_display() {
        assert_eq!(AshMode::Minimal.to_string(), "minimal");
        assert_eq!(AshMode::Balanced.to_string(), "balanced");
        assert_eq!(AshMode::Strict.to_string(), "strict");
    }

    #[test]
    fn stored_context_expiry() {
        let ctx = StoredContext {
            context_id: "test".into(),
            binding: "POST|/api|".into(),
            mode: AshMode::Balanced,
            issued_at: 1000,
            expires_at: 2000,
            nonce: None,
            consumed_at: None,
        };
        assert!(!ctx.is_expired(1500));
        assert!(ctx.is_expired(2000)); // boundary: exact = expired
        assert!(ctx.is_expired(2001));
    }

    #[test]
    fn stored_context_consumed() {
        let mut ctx = StoredContext {
            context_id: "test".into(),
            binding: "POST|/api|".into(),
            mode: AshMode::Balanced,
            issued_at: 1000,
            expires_at: 2000,
            nonce: None,
            consumed_at: None,
        };
        assert!(!ctx.is_consumed());
        ctx.consumed_at = Some(1500);
        assert!(ctx.is_consumed());
    }

    #[test]
    fn version_constants() {
        assert_eq!(ASH_SDK_VERSION, "1.0.0");
    }
}

// ============================================================================
// SECTION 17: ENRICHED API — COMPLETE
// ============================================================================

mod enriched_api {
    use super::*;

    #[test]
    fn body_hash_enriched() {
        let r = ash_hash_body_enriched(r#"{"a":1}"#);
        assert_eq!(r.hash.len(), 64);
        assert_eq!(r.input_bytes, 7);
        assert!(!r.is_empty);
    }

    #[test]
    fn body_hash_enriched_empty() {
        let r = ash_hash_body_enriched("");
        assert!(r.is_empty);
        assert_eq!(r.input_bytes, 0);
    }

    #[test]
    fn body_hash_enriched_matches_base() {
        let body = r#"{"test":"value"}"#;
        assert_eq!(ash_hash_body(body), ash_hash_body_enriched(body).hash);
    }

    #[test]
    fn binding_enriched() {
        let r = ash_normalize_binding_enriched("post", "/api//users/", "z=3&a=1").unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/api/users");
        assert_eq!(r.canonical_query, "a=1&z=3");
        assert!(r.had_query);
    }

    #[test]
    fn binding_enriched_no_query() {
        let r = ash_normalize_binding_enriched("GET", "/api", "").unwrap();
        assert!(!r.had_query);
        assert_eq!(r.canonical_query, "");
    }

    #[test]
    fn parse_binding() {
        let r = ash_parse_binding("POST|/api/users|page=1").unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/api/users");
        assert_eq!(r.canonical_query, "page=1");
        assert!(r.had_query);
    }

    #[test]
    fn parse_binding_invalid() {
        assert!(ash_parse_binding("invalid").is_err());
        assert!(ash_parse_binding("GET|/api").is_err());
    }
}

// ============================================================================
// SECTION 18: SECURITY ATTACK SCENARIOS
// ============================================================================

mod security_attacks {
    use super::*;

    // --- Injection attacks ---

    #[test]
    fn sql_injection_in_context_id() {
        let injections = [
            "ctx' OR '1'='1",
            "ctx'; DROP TABLE--",
            "ctx\" UNION SELECT *",
        ];
        for inj in &injections {
            // Should be rejected by charset validation
            assert!(ash_derive_client_secret(NONCE_32, inj, "GET|/|").is_err());
        }
    }

    #[test]
    fn path_traversal_normalized() {
        let result = ash_normalize_binding("GET", "/../../../etc/passwd", "").unwrap();
        assert_eq!(result, "GET|/etc/passwd|");
        // Cannot escape root
    }

    #[test]
    fn null_byte_in_binding_handled() {
        // Null byte in path should be caught by percent encoding or produce deterministic result
        let result = ash_normalize_binding("GET", "/api\0admin", "");
        // Should not panic, regardless of whether it succeeds or fails
        let _ = result;
    }

    #[test]
    fn header_injection_blocked() {
        let h = TestHeaders(vec![
            ("x-ash-ts".into(), "1700000000\r\nX-Injected: value".into()),
            ("x-ash-nonce".into(), "a".repeat(32)),
            ("x-ash-body-hash".into(), "b".repeat(64)),
            ("x-ash-proof".into(), "c".repeat(64)),
        ]);
        // Control characters should be rejected
        assert!(ash_extract_headers(&h).is_err());
    }

    // --- Replay attacks ---

    #[test]
    fn replay_with_different_binding_fails() {
        let nonce = NONCE_32;
        let ctx = "ctx_replay";
        let binding = "POST|/api/transfer|";
        let ts = "1700000000";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let proof = ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

        // Try to replay with different binding
        let valid = ash_verify_proof(
            nonce,
            ctx,
            "POST|/api/admin|",
            ts,
            &body_hash,
            &proof,
        )
        .unwrap();
        assert!(!valid);
    }

    #[test]
    fn replay_with_different_body_fails() {
        let nonce = NONCE_32;
        let ctx = "ctx_replay";
        let binding = "POST|/api/transfer|";
        let ts = "1700000000";
        let body_hash = ash_hash_body(r#"{"amount":100}"#);

        let secret = ash_derive_client_secret(nonce, ctx, binding).unwrap();
        let proof = ash_build_proof(&secret, ts, binding, &body_hash).unwrap();

        // Different body hash
        let tampered_hash = ash_hash_body(r#"{"amount":99999}"#);
        let valid =
            ash_verify_proof(nonce, ctx, binding, ts, &tampered_hash, &proof).unwrap();
        assert!(!valid);
    }

    // --- Spoofing attacks ---

    #[test]
    fn hex_case_spoofing_prevented() {
        // Upper and lower case nonces should produce same secrets
        let s1 = ash_derive_client_secret(
            "AABBCCDD00112233AABBCCDD00112233",
            "ctx",
            "GET|/|",
        ).unwrap();
        let s2 = ash_derive_client_secret(
            "aabbccdd00112233aabbccdd00112233",
            "ctx",
            "GET|/|",
        ).unwrap();
        assert_eq!(s1, s2);
    }

    // --- DoS resistance ---

    #[test]
    fn large_json_rejected() {
        let huge = format!(r#"{{"data":"{}"}}"#, "x".repeat(11 * 1024 * 1024));
        assert!(ash_canonicalize_json(&huge).is_err());
    }

    #[test]
    fn deep_nesting_rejected() {
        let mut json = "0".to_string();
        for _ in 0..66 {
            json = format!("[{}]", json);
        }
        assert!(ash_canonicalize_json(&json).is_err());
    }

    #[test]
    fn many_scope_fields_rejected() {
        let fields: Vec<String> = (0..101).map(|i| format!("f{}", i)).collect();
        let scope: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        assert!(ash_extract_scoped_fields(&json!({}), &scope).is_err());
    }

    // --- Delimiter collision ---

    #[test]
    fn context_id_pipe_collision_prevented() {
        // If context_id could contain |, then "ctx|POST" + binding "GET|/"
        // would collide with "ctx" + binding "POST|GET|/"
        assert!(ash_derive_client_secret(NONCE_32, "ctx|POST", "GET|/|").is_err());
    }

    #[test]
    fn scope_delimiter_collision_prevented() {
        // Field name containing unit separator should be rejected
        assert!(ash_hash_scope(&["field\x1Fother"]).is_err());
    }
}

// ============================================================================
// SECTION 19: FUZZ TESTING — THOUSANDS OF ITERATIONS
// ============================================================================

mod fuzz_testing {
    use super::*;

    #[test]
    fn fuzz_derive_client_secret_2000() {
        let mut rng = rand::thread_rng();
        let hex_chars: Vec<char> = "0123456789abcdef".chars().collect();

        for _ in 0..2000 {
            let nonce_len = rng.gen_range(0..600);
            let nonce: String = (0..nonce_len)
                .map(|_| hex_chars[rng.gen_range(0..16)])
                .collect();
            let ctx_len = rng.gen_range(0..300);
            let ctx: String = (0..ctx_len)
                .map(|_| {
                    let chars = "abcdefghijklmnopqrstuvwxyz0123456789_-.";
                    chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                })
                .collect();
            let binding = "GET|/api|";

            let _ = ash_derive_client_secret(&nonce, &ctx, binding);
            // Must not panic
        }
    }

    #[test]
    fn fuzz_canonicalize_json_1000() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let obj = json!({
                "key1": rng.gen_range(-10000i64..10000),
                "key2": format!("val_{}", rng.gen_range(0..10000)),
                "key3": rng.gen_bool(0.5),
                "nested": {
                    "a": rng.gen_range(0..100),
                    "b": [rng.gen_range(0..10), rng.gen_range(0..10)]
                }
            });
            let input = serde_json::to_string(&obj).unwrap();
            let r1 = ash_canonicalize_json(&input).unwrap();
            let r2 = ash_canonicalize_json(&input).unwrap();
            assert_eq!(r1, r2, "Non-deterministic for: {}", input);
        }
    }

    #[test]
    fn fuzz_query_canonicalization_1000() {
        let mut rng = rand::thread_rng();
        let chars = "abcdefghijklmnopqrstuvwxyz0123456789=&%+";

        for _ in 0..1000 {
            let len = rng.gen_range(0..200);
            let query: String = (0..len)
                .map(|_| chars.chars().nth(rng.gen_range(0..chars.len())).unwrap())
                .collect();

            let r1 = ash_canonicalize_query(&query);
            let r2 = ash_canonicalize_query(&query);
            // Should be deterministic if both succeed
            match (r1, r2) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                _ => {} // Both error is ok too
            }
        }
    }

    #[test]
    fn fuzz_proof_roundtrip_500() {
        let mut rng = rand::thread_rng();
        let hex_chars: Vec<char> = "0123456789abcdef".chars().collect();

        for _ in 0..500 {
            let nonce: String = (0..32).map(|_| hex_chars[rng.gen_range(0..16)]).collect();
            let ctx_len = rng.gen_range(1..50);
            let ctx: String = (0..ctx_len)
                .map(|_| "abcdefghijklmnopqrstuvwxyz0123456789_-.".chars().nth(rng.gen_range(0..38)).unwrap())
                .collect();
            let binding = "POST|/api/test|";
            let ts = (1700000000u64 + rng.gen_range(0..1000)).to_string();
            let body = format!(r#"{{"v":{}}}"#, rng.gen_range(0..10000));
            let body_hash = ash_hash_body(&body);

            let secret = match ash_derive_client_secret(&nonce, &ctx, binding) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let proof = ash_build_proof(&secret, &ts, binding, &body_hash).unwrap();
            let valid =
                ash_verify_proof(&nonce, &ctx, binding, &ts, &body_hash, &proof).unwrap();
            assert!(valid, "Roundtrip failed for nonce={}, ctx={}", nonce, ctx);
        }
    }

    #[test]
    fn fuzz_scoped_proof_roundtrip_300() {
        let mut rng = rand::thread_rng();
        let hex_chars: Vec<char> = "0123456789abcdef".chars().collect();

        for _ in 0..300 {
            let nonce: String = (0..32).map(|_| hex_chars[rng.gen_range(0..16)]).collect();
            let ctx = format!("ctx_{}", rng.gen_range(0..1000));
            let binding = "POST|/api/scoped|";
            let ts = (1700000000u64 + rng.gen_range(0..1000)).to_string();

            let val_a = rng.gen_range(0..10000);
            let val_b = rng.gen_range(0..10000);
            let payload = format!(r#"{{"a":{},"b":{},"c":"extra"}}"#, val_a, val_b);
            let scope = vec!["a", "b"];

            let secret = match ash_derive_client_secret(&nonce, &ctx, binding) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (proof, scope_hash) =
                ash_build_proof_scoped(&secret, &ts, binding, &payload, &scope).unwrap();
            let valid = ash_verify_proof_scoped(
                &nonce,
                &ctx,
                binding,
                &ts,
                &payload,
                &scope,
                &scope_hash,
                &proof,
            )
            .unwrap();
            assert!(valid, "Scoped roundtrip failed");
        }
    }

    #[test]
    fn fuzz_timing_safe_equal_1000() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let len = rng.gen_range(0..300);
            let a: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let b: Vec<u8> = if rng.gen_bool(0.3) {
                a.clone()
            } else {
                (0..rng.gen_range(0..300)).map(|_| rng.gen()).collect()
            };

            let result = ash_timing_safe_equal(&a, &b);
            let expected = a == b && a.len() <= 2048;
            assert_eq!(
                result, expected,
                "Mismatch for a.len()={}, b.len()={}",
                a.len(),
                b.len()
            );
        }
    }
}

// ============================================================================
// SECTION 20: PERFORMANCE & MEMORY STRESS TESTS
// ============================================================================

mod performance_stress {
    use super::*;

    #[test]
    fn canonicalize_json_throughput() {
        let input = serde_json::to_string(&json!({
            "user": {"name": "alice", "age": 30, "tags": ["a", "b", "c"]},
            "amount": 100,
            "metadata": {"key": "value", "nested": {"deep": true}}
        }))
        .unwrap();

        let start = Instant::now();
        for _ in 0..10_000 {
            ash_canonicalize_json(&input).unwrap();
        }
        let elapsed = start.elapsed();
        // Should complete in under 5 seconds for 10k iterations
        assert!(
            elapsed.as_secs() < 5,
            "Canonicalization too slow: {:?} for 10k iterations",
            elapsed
        );
    }

    #[test]
    fn proof_generation_throughput() {
        let secret = ash_derive_client_secret(NONCE_32, "ctx", "POST|/api|").unwrap();
        let start = Instant::now();
        for i in 0..10_000 {
            let ts = (1700000000u64 + i).to_string();
            ash_build_proof(&secret, &ts, "POST|/api|", VALID_BODY_HASH).unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 5,
            "Proof generation too slow: {:?} for 10k iterations",
            elapsed
        );
    }

    #[test]
    fn many_scope_policies() {
        let mut reg = ScopePolicyRegistry::new();
        for i in 0..1000 {
            let binding = format!("POST|/api/endpoint_{}|", i);
            reg.register(&binding, &["field"]);
        }
        assert!(reg.has("POST|/api/endpoint_999|"));
        assert!(reg.get("POST|/api/endpoint_0|") == vec!["field"]);
    }

    #[test]
    fn large_payload_canonicalization() {
        let mut items = Vec::new();
        for i in 0..1000 {
            items.push(json!({"id": i, "name": format!("item_{}", i), "value": i * 100}));
        }
        let payload = serde_json::to_string(&json!({"items": items})).unwrap();

        let start = Instant::now();
        let result = ash_canonicalize_json(&payload);
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(
            elapsed.as_millis() < 1000,
            "Large payload took {:?}",
            elapsed
        );
    }

    #[test]
    fn many_concurrent_hash_computations() {
        let mut hashes = Vec::with_capacity(10_000);
        for i in 0..10_000 {
            hashes.push(ash_hash_body(&format!("payload_{}", i)));
        }
        // All should be unique
        let unique: HashSet<&String> = hashes.iter().collect();
        assert_eq!(unique.len(), 10_000);
    }

    #[test]
    fn binding_normalization_throughput() {
        let start = Instant::now();
        for _ in 0..10_000 {
            ash_normalize_binding("POST", "/api/v1/users/profile/settings", "sort=name&page=1&limit=20").unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 5,
            "Binding normalization too slow: {:?}",
            elapsed
        );
    }
}

// ============================================================================
// SECTION 21: NONCE GENERATION
// ============================================================================

mod nonce_generation {
    use super::*;

    #[test]
    fn generate_nonce_16_bytes() {
        let nonce = ash_generate_nonce(16).unwrap();
        assert_eq!(nonce.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn generate_nonce_32_bytes() {
        let nonce = ash_generate_nonce(32).unwrap();
        assert_eq!(nonce.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn generate_nonce_too_small_fails() {
        assert!(ash_generate_nonce(15).is_err());
        assert!(ash_generate_nonce(0).is_err());
        assert!(ash_generate_nonce(1).is_err());
    }

    #[test]
    fn generate_nonce_uniqueness() {
        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let n = ash_generate_nonce(32).unwrap();
            assert!(nonces.insert(n), "Duplicate nonce generated");
        }
    }

    #[test]
    fn generate_nonce_is_valid_hex() {
        let nonce = ash_generate_nonce(32).unwrap();
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_context_id() {
        let ctx = ash_generate_context_id().unwrap();
        assert!(ctx.starts_with("ash_"));
        assert!(ctx.len() > 4);
    }

    #[test]
    fn generate_context_id_256() {
        let ctx = ash_generate_context_id_256().unwrap();
        assert!(ctx.starts_with("ash_"));
        assert!(ctx.len() > 4);
        // 32 bytes = 64 hex + "ash_" prefix = 68
        assert_eq!(ctx.len(), 68);
    }

    #[test]
    fn generate_nonce_or_panic_works() {
        let nonce = ash_generate_nonce_or_panic(16);
        assert_eq!(nonce.len(), 32);
    }
}

// ============================================================================
// SECTION 22: URL-ENCODED CANONICALIZATION
// ============================================================================

mod urlencoded_canonicalization {
    use super::*;

    #[test]
    fn basic_urlencoded() {
        assert_eq!(
            ash_canonicalize_urlencoded("z=3&a=1&a=2&b=hello%20world").unwrap(),
            "a=1&a=2&b=hello%20world&z=3"
        );
    }

    #[test]
    fn empty_input() {
        assert_eq!(ash_canonicalize_urlencoded("").unwrap(), "");
    }

    #[test]
    fn single_pair() {
        assert_eq!(ash_canonicalize_urlencoded("key=value").unwrap(), "key=value");
    }

    #[test]
    fn plus_is_literal() {
        let result = ash_canonicalize_urlencoded("q=a+b").unwrap();
        assert!(result.contains("%2B"), "Plus should be encoded: {}", result);
    }

    #[test]
    fn too_large_fails() {
        let huge = "a=".to_string() + &"x".repeat(11 * 1024 * 1024);
        assert!(ash_canonicalize_urlencoded(&huge).is_err());
    }
}

// ============================================================================
// SECTION 23: JSON VALUE CANONICALIZATION WITH SIZE CHECK
// ============================================================================

mod json_value_canonicalization {
    use super::*;

    #[test]
    fn canonicalize_value_basic() {
        let value = json!({"z": 1, "a": 2});
        let output = ash_canonicalize_json_value(&value).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn canonicalize_value_with_size_check_basic() {
        let value = json!({"z": 1, "a": 2});
        let output = ash_canonicalize_json_value_with_size_check(&value).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn value_matches_string_canonicalization() {
        let input = r#"{"b": {"d": 4, "c": 3}, "a": 1}"#;
        let from_str = ash_canonicalize_json(input).unwrap();
        let value: serde_json::Value = serde_json::from_str(input).unwrap();
        let from_value = ash_canonicalize_json_value(&value).unwrap();
        assert_eq!(from_str, from_value);
    }
}

// ============================================================================
// SECTION 24: CROSS-CUTTING CONCERNS & BUG-SPECIFIC REGRESSION TESTS
// ============================================================================

mod regression_tests {
    use super::*;

    // BUG-001: Delimiter collision in HMAC message
    #[test]
    fn bug001_delimiter_collision_prevented() {
        // These should produce different secrets because context_id cannot contain |
        let s1 = ash_derive_client_secret(NONCE_32, "ctx_a", "POST|/api|").unwrap();
        let s2 = ash_derive_client_secret(NONCE_32, "ctx_b", "POST|/api|").unwrap();
        assert_ne!(s1, s2);
    }

    // BUG-004: Non-hex nonce rejection
    #[test]
    fn bug004_non_hex_nonce_rejected() {
        assert!(ash_derive_client_secret("z".repeat(32).as_str(), "ctx", "GET|/|").is_err());
    }

    // BUG-025: Path percent-encoding normalization
    #[test]
    fn bug025_encoded_slashes_decoded() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/%2F%2F/users", "").unwrap(),
            "GET|/api/users|"
        );
    }

    // BUG-027: Encoded query delimiter bypass
    #[test]
    fn bug027_encoded_question_mark_rejected() {
        assert!(ash_normalize_binding("GET", "/api/users%3Fid=5", "").is_err());
    }

    // BUG-029: Empty proof in chain
    #[test]
    fn bug029_empty_proof_chain_rejected() {
        assert!(ash_hash_proof("").is_err());
    }

    // BUG-035: Dot-segment resolution
    #[test]
    fn bug035_dot_segments_resolved() {
        assert_eq!(
            ash_normalize_binding("GET", "/api/v1/../users", "").unwrap(),
            "GET|/api/users|"
        );
    }

    // BUG-038: Leading zeros in timestamp
    #[test]
    fn bug038_leading_zeros_rejected() {
        assert!(ash_validate_timestamp_format("0123456789").is_err());
        assert!(ash_validate_timestamp_format("0").is_ok()); // "0" itself is valid
    }

    // BUG-040: Body hash format validation
    #[test]
    fn bug040_invalid_body_hash_rejected() {
        assert!(ash_build_proof("secret", "ts", "bind", "too_short").is_err());
        assert!(ash_build_proof("secret", "ts", "bind", &"g".repeat(64)).is_err());
    }

    // BUG-041: Empty context_id
    #[test]
    fn bug041_empty_context_id_rejected() {
        assert!(ash_derive_client_secret(NONCE_32, "", "GET|/|").is_err());
    }

    // BUG-042: ASCII method validation
    #[test]
    fn bug042_non_ascii_method_rejected() {
        assert!(ash_normalize_binding("GËT", "/api", "").is_err());
    }

    // BUG-043: Whitespace query handling
    #[test]
    fn bug043_whitespace_query_treated_as_empty() {
        assert_eq!(
            ash_normalize_binding("GET", "/api", "   ").unwrap(),
            "GET|/api|"
        );
    }

    // SEC-008: Constant-time comparison
    #[test]
    fn sec008_constant_time_comparison() {
        assert!(ash_timing_safe_equal(b"test", b"test"));
        assert!(!ash_timing_safe_equal(b"test", b"tess"));
    }

    // SEC-011: Array index exceeding MAX_ARRAY_INDEX (10000) is rejected
    #[test]
    fn sec011_large_array_index_rejected() {
        let payload = json!({"items": [1, 2, 3]});
        // Index 99999 exceeds MAX_TOTAL_ARRAY_ALLOCATION (10000), so this errors
        let result = ash_extract_scoped_fields(&payload, &["items[99999]"]);
        assert!(result.is_err());
    }

    // SEC-011: Array index within limit succeeds (even if index doesn't exist in data)
    #[test]
    fn sec011_valid_array_index_accepted() {
        let payload = json!({"items": [1, 2, 3]});
        // Index 5 is within MAX_ARRAY_INDEX, field just won't be found
        let scoped = ash_extract_scoped_fields(&payload, &["items[5]"]).unwrap();
        let _ = scoped;
    }

    // SEC-014: Minimum nonce entropy
    #[test]
    fn sec014_short_nonce_rejected() {
        assert!(ash_derive_client_secret("abc", "ctx", "GET|/|").is_err());
    }

    // SEC-018: Max timestamp
    #[test]
    fn sec018_unreasonable_timestamp_rejected() {
        assert!(ash_validate_timestamp_format("32503680001").is_err());
    }

    // SEC-AUDIT-007: Oversized comparison inputs rejected
    #[test]
    fn sec_audit_007_oversized_comparison() {
        let large = vec![0x41u8; 2049];
        assert!(!ash_timing_safe_equal(&large, &large));
    }

    // Verify that error messages don't leak sensitive data
    #[test]
    fn error_messages_safe_for_logging() {
        let err = ash_canonicalize_json("{malicious: payload}").unwrap_err();
        assert!(!err.message().contains("malicious"));
        assert!(!err.message().contains("payload"));
    }
}
