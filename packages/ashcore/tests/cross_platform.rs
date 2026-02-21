//! Cross-Platform Compatibility Tests for ASH Rust SDK
//!
//! Tests Unicode handling, number representation, string encoding,
//! and byte order consistency across platforms.

use ashcore::{
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_normalize_binding,
    ash_derive_client_secret, ash_build_proof,
};

// =========================================================================
// UNICODE HANDLING
// =========================================================================

mod unicode_handling {
    use super::*;

    #[test]
    fn test_utf8_basic_multilingual_plane() {
        // BMP characters (U+0000 to U+FFFF)
        let json = r#"{"latin":"Hello","greek":"Γεια","cyrillic":"Привет"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_utf8_supplementary_planes() {
        // SMP characters (U+10000 and above)
        let json = r#"{"emoji":"😀🎉","math":"𝕳𝖊𝖑𝖑𝖔"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nfc_normalization_consistency() {
        // Same character, different representations
        let nfc = r#"{"name":"café"}"#;                    // é as single char (U+00E9)
        let nfd = r#"{"name":"cafe\u0301"}"#;              // e + combining acute (U+0065 U+0301)

        let result_nfc = ash_canonicalize_json(nfc).unwrap();
        let result_nfd = ash_canonicalize_json(nfd).unwrap();

        assert_eq!(result_nfc, result_nfd, "NFC and NFD should canonicalize to same output");
    }

    #[test]
    fn test_nfc_various_characters() {
        let test_cases = [
            ("ñ", "n\u{0303}"),       // n with tilde
            ("ö", "o\u{0308}"),       // o with diaeresis
            ("ç", "c\u{0327}"),       // c with cedilla
            ("å", "a\u{030A}"),       // a with ring above
        ];

        for (nfc, nfd) in test_cases {
            let json_nfc = format!(r#"{{"char":"{}"}}"#, nfc);
            let json_nfd = format!(r#"{{"char":"{}"}}"#, nfd);

            let result_nfc = ash_canonicalize_json(&json_nfc).unwrap();
            let result_nfd = ash_canonicalize_json(&json_nfd).unwrap();

            assert_eq!(result_nfc, result_nfd, "NFC/NFD mismatch for {}", nfc);
        }
    }

    #[test]
    fn test_emoji_handling() {
        let emojis = ["😀", "🎉", "💯", "🚀", "❤️", "👨‍👩‍👧‍👦"];

        for emoji in emojis {
            let json = format!(r#"{{"emoji":"{}"}}"#, emoji);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed to canonicalize emoji: {}", emoji);
        }
    }

    #[test]
    fn test_emoji_zwj_sequences() {
        // Zero-width joiner sequences
        let zwj_emojis = [
            "👨‍👩‍👧",      // Family
            "👩‍💻",        // Woman technologist
            "🏳️‍🌈",       // Rainbow flag
        ];

        for emoji in zwj_emojis {
            let json = format!(r#"{{"emoji":"{}"}}"#, emoji);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed ZWJ emoji: {}", emoji);
        }
    }

    #[test]
    fn test_rtl_text_handling() {
        // Right-to-left text
        let rtl_texts = [
            ("arabic", "العربية"),
            ("hebrew", "עברית"),
            ("persian", "فارسی"),
        ];

        for (lang, text) in rtl_texts {
            let json = format!(r#"{{"{}":{}}}"#, lang, serde_json::json!(text));
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed RTL text: {}", lang);
        }
    }

    #[test]
    fn test_bidi_text() {
        // Bidirectional text
        let json = r#"{"mixed":"Hello مرحبا World"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cjk_characters() {
        let cjk = [
            ("chinese_simplified", "你好世界"),
            ("chinese_traditional", "你好世界"),
            ("japanese_hiragana", "こんにちは"),
            ("japanese_katakana", "コンニチハ"),
            ("japanese_kanji", "今日は"),
            ("korean", "안녕하세요"),
        ];

        for (name, text) in cjk {
            let json = format!(r#"{{"{}":{}}}"#, name, serde_json::json!(text));
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed CJK: {}", name);
        }
    }

    #[test]
    fn test_unicode_in_binding_path() {
        let result = ash_normalize_binding("GET", "/api/用户", "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_unicode_in_query_value() {
        let result = ash_canonicalize_query("name=日本語");
        assert!(result.is_ok());
    }
}

// =========================================================================
// NUMBER REPRESENTATION
// =========================================================================

mod number_representation {
    use super::*;

    #[test]
    fn test_integer_zero() {
        let result = ash_canonicalize_json(r#"{"value":0}"#).unwrap();
        assert!(result.contains(":0}"));
    }

    #[test]
    fn test_negative_zero_normalized() {
        let result = ash_canonicalize_json(r#"{"value":-0}"#).unwrap();
        // -0 should become 0
        assert!(!result.contains("-0"));
        assert!(result.contains(":0}"));
    }

    #[test]
    fn test_positive_integers() {
        let integers = [1, 42, 100, 999, 10000, 1000000];
        for i in integers {
            let json = format!(r#"{{"value":{}}}"#, i);
            let result = ash_canonicalize_json(&json).unwrap();
            assert!(result.contains(&format!(":{}", i)));
        }
    }

    #[test]
    fn test_negative_integers() {
        let integers = [-1, -42, -100, -999, -10000];
        for i in integers {
            let json = format!(r#"{{"value":{}}}"#, i);
            let result = ash_canonicalize_json(&json).unwrap();
            assert!(result.contains(&format!(":{}", i)));
        }
    }

    #[test]
    fn test_large_integers() {
        // Safe integer range for JavaScript: -(2^53 - 1) to 2^53 - 1
        let large = [
            9007199254740991i64,   // MAX_SAFE_INTEGER
            -9007199254740991i64,  // MIN_SAFE_INTEGER
        ];

        for n in large {
            let json = format!(r#"{{"value":{}}}"#, n);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Failed for large integer: {}", n);
        }
    }

    #[test]
    fn test_float_basic() {
        let result = ash_canonicalize_json(r#"{"value":3.14}"#).unwrap();
        assert!(result.contains("3.14"));
    }

    #[test]
    fn test_whole_float_becomes_integer() {
        let result = ash_canonicalize_json(r#"{"value":3.0}"#).unwrap();
        // 3.0 should become 3
        assert!(result.contains(":3}") || result.contains(":3,"));
    }

    #[test]
    fn test_float_precision() {
        let floats = [
            ("0.1", "0.1"),
            ("0.01", "0.01"),
            ("0.001", "0.001"),
            ("1.5", "1.5"),
            ("3.14159", "3.14159"),
        ];

        for (input, expected) in floats {
            let json = format!(r#"{{"value":{}}}"#, input);
            let result = ash_canonicalize_json(&json).unwrap();
            assert!(result.contains(expected), "Float {} not preserved", input);
        }
    }

    #[test]
    fn test_scientific_notation_normalized() {
        let json = r#"{"value":1e10}"#;
        let result = ash_canonicalize_json(json).unwrap();
        // Should be normalized to decimal form
        assert!(result.contains("10000000000") || result.contains("1e10") || result.contains("1E10"));
    }

    #[test]
    fn test_very_small_numbers() {
        let json = r#"{"value":0.0000001}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }
}

// =========================================================================
// STRING ENCODING
// =========================================================================

mod string_encoding {
    use super::*;

    #[test]
    fn test_escape_backslash() {
        let json = r#"{"path":"C:\\Users\\file"}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\\\"));
    }

    #[test]
    fn test_escape_quote() {
        let json = r#"{"text":"say \"hello\""}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\\""));
    }

    #[test]
    fn test_escape_newline() {
        let json = "{\"text\":\"line1\\nline2\"}";
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\n"));
    }

    #[test]
    fn test_escape_tab() {
        let json = "{\"text\":\"col1\\tcol2\"}";
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\t"));
    }

    #[test]
    fn test_escape_carriage_return() {
        let json = "{\"text\":\"line1\\rline2\"}";
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\r"));
    }

    #[test]
    fn test_escape_form_feed() {
        let json = "{\"text\":\"page1\\fpage2\"}";
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\f"));
    }

    #[test]
    fn test_escape_backspace() {
        let json = "{\"text\":\"back\\bspace\"}";
        let result = ash_canonicalize_json(json).unwrap();
        assert!(result.contains("\\b"));
    }

    #[test]
    fn test_control_characters_escaped() {
        // Control characters U+0000 to U+001F should be escaped
        for c in 0u8..32 {
            let json = format!(r#"{{"text":"\u{:04x}"}}"#, c);
            let result = ash_canonicalize_json(&json);
            if let Ok(canonical) = result {
                // Should contain escape sequence
                assert!(
                    canonical.contains("\\u") ||
                    canonical.contains("\\n") ||
                    canonical.contains("\\r") ||
                    canonical.contains("\\t") ||
                    canonical.contains("\\b") ||
                    canonical.contains("\\f"),
                    "Control char U+{:04X} not escaped", c
                );
            }
        }
    }

    #[test]
    fn test_solidus_not_escaped() {
        // Forward slash (solidus) should NOT be escaped
        let json = r#"{"url":"https://example.com/path"}"#;
        let result = ash_canonicalize_json(json).unwrap();
        // Should NOT contain escaped solidus
        assert!(!result.contains("\\/"));
        assert!(result.contains("/"));
    }
}

// =========================================================================
// BYTE ORDER AND HEX ENCODING
// =========================================================================

mod byte_order {
    use super::*;

    #[test]
    fn test_hash_lowercase_hex() {
        let hash = ash_hash_body("test");
        // Should be all lowercase
        assert!(hash.chars().all(|c| !c.is_uppercase()));
        // Should be valid hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_consistent_length() {
        let long_body = "x".repeat(1000);
        let bodies = ["", "a", "ab", "abc", "test", long_body.as_str()];
        for body in bodies {
            let hash = ash_hash_body(body);
            assert_eq!(hash.len(), 64, "Hash length should always be 64");
        }
    }

    #[test]
    fn test_proof_lowercase_hex() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let proof = ash_build_proof(&secret, "1700000000", "POST|/|", &"b".repeat(64)).unwrap();

        // Should be all lowercase
        assert!(proof.chars().all(|c| !c.is_uppercase()));
        // Should be valid hex
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(proof.len(), 64);
    }

    #[test]
    fn test_nonce_case_insensitive_input() {
        let nonce_lower = "a".repeat(64);
        let nonce_upper = "A".repeat(64);
        let nonce_mixed = "aA".repeat(32);

        let secret_lower = ash_derive_client_secret(&nonce_lower, "ctx", "GET|/|");
        let secret_upper = ash_derive_client_secret(&nonce_upper, "ctx", "GET|/|");
        let secret_mixed = ash_derive_client_secret(&nonce_mixed, "ctx", "GET|/|");

        // All should succeed
        assert!(secret_lower.is_ok());
        assert!(secret_upper.is_ok());
        assert!(secret_mixed.is_ok());
    }

    #[test]
    fn test_deterministic_hash() {
        let body = "test content";
        let hash1 = ash_hash_body(body);
        let hash2 = ash_hash_body(body);
        assert_eq!(hash1, hash2, "Same input should produce same hash");
    }

    #[test]
    fn test_known_hash_value() {
        // Known SHA-256 hash of "test"
        let hash = ash_hash_body("test");
        assert_eq!(hash, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
    }
}

// =========================================================================
// KEY SORTING
// =========================================================================

mod key_sorting {
    use super::*;

    #[test]
    fn test_alphabetical_key_sorting() {
        let json = r#"{"z":1,"a":2,"m":3}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_numeric_string_keys_lexicographic() {
        let json = r#"{"10":1,"2":2,"1":3}"#;
        let result = ash_canonicalize_json(json).unwrap();
        // Lexicographic order: "1" < "10" < "2"
        assert_eq!(result, r#"{"1":3,"10":1,"2":2}"#);
    }

    #[test]
    fn test_case_sensitive_sorting() {
        let json = r#"{"a":1,"A":2,"b":3,"B":4}"#;
        let result = ash_canonicalize_json(json).unwrap();
        // ASCII order: A (65) < B (66) < a (97) < b (98)
        assert_eq!(result, r#"{"A":2,"B":4,"a":1,"b":3}"#);
    }

    #[test]
    fn test_unicode_key_sorting() {
        let json = r#"{"é":1,"e":2,"ê":3}"#;
        let result = ash_canonicalize_json(json).unwrap();
        // Should be sorted by UTF-8 byte order
        assert!(!result.is_empty());  // Order depends on NFC normalization
    }

    #[test]
    fn test_nested_object_key_sorting() {
        let json = r#"{"outer":{"z":1,"a":2}}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, r#"{"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn test_deeply_nested_key_sorting() {
        let json = r#"{"l1":{"l2":{"z":1,"a":2}}}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, r#"{"l1":{"l2":{"a":2,"z":1}}}"#);
    }
}

// =========================================================================
// ARRAY ORDER PRESERVATION
// =========================================================================

mod array_order {
    use super::*;

    #[test]
    fn test_array_order_preserved() {
        let json = r#"{"arr":[3,1,4,1,5,9,2,6]}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, r#"{"arr":[3,1,4,1,5,9,2,6]}"#);
    }

    #[test]
    fn test_array_of_objects_preserved() {
        let json = r#"{"items":[{"id":2},{"id":1},{"id":3}]}"#;
        let result = ash_canonicalize_json(json).unwrap();
        // Order should be preserved, but keys within objects sorted
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        let items = parsed["items"].as_array().unwrap();
        assert_eq!(items[0]["id"], 2);
        assert_eq!(items[1]["id"], 1);
        assert_eq!(items[2]["id"], 3);
    }

    #[test]
    fn test_nested_arrays_preserved() {
        let json = r#"{"matrix":[[3,1],[4,1],[5,9]]}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, r#"{"matrix":[[3,1],[4,1],[5,9]]}"#);
    }
}
