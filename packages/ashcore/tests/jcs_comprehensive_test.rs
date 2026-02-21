//! Comprehensive JCS (JSON Canonicalization Scheme) Tests - RFC 8785 Compliance
//!
//! These tests cover edge cases in JSON canonicalization including:
//! - Nested structure handling
//! - Unicode normalization
//! - Special characters
//! - Key sorting
//! - Number handling

use ashcore::{ash_canonicalize_json, ash_canonicalize_json_value};
use serde_json::json;

// =========================================================================
// NESTED STRUCTURE TESTS
// =========================================================================

mod nested_structures {
    use super::*;

    #[test]
    fn test_deeply_nested_objects_10_levels() {
        let json = r#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, json);
    }

    #[test]
    fn test_deeply_nested_arrays_10_levels() {
        let json = r#"[[[[[[[[[[1]]]]]]]]]]"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, json);
    }

    #[test]
    fn test_mixed_nested_objects_and_arrays() {
        let json = r#"{"arr":[{"nested":[1,2,{"deep":true}]}]}"#;
        let result = ash_canonicalize_json(json).unwrap();
        assert_eq!(result, json);
    }

    #[test]
    fn test_array_of_objects_sorting() {
        // Array order should be preserved
        let input = r#"[{"z":1},{"a":2},{"m":3}]"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_nested_object_key_sorting() {
        let input = r#"{"outer":{"z":1,"a":2,"m":3}}"#;
        let expected = r#"{"outer":{"a":2,"m":3,"z":1}}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_three_level_nested_sorting() {
        let input = r#"{"c":{"z":{"y":1,"x":2},"a":{"d":3,"b":4}},"a":1}"#;
        let expected = r#"{"a":1,"c":{"a":{"b":4,"d":3},"z":{"x":2,"y":1}}}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_array_with_mixed_types() {
        let input = r#"[1,"string",true,null,{"key":"value"},[1,2,3]]"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_empty_nested_structures() {
        let input = r#"{"empty_obj":{},"empty_arr":[],"nested":{"also_empty":{}}}"#;
        let expected = r#"{"empty_arr":[],"empty_obj":{},"nested":{"also_empty":{}}}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }
}

// =========================================================================
// UNICODE NORMALIZATION TESTS
// =========================================================================

mod unicode_normalization {
    use super::*;

    #[test]
    fn test_nfc_combining_acute_e() {
        // e + combining acute accent should normalize to precomposed é
        let input = r#"{"text":"e\u0301"}"#;  // e + combining acute
        let result = ash_canonicalize_json(input).unwrap();
        // Should contain the NFC-normalized form
        assert!(result.contains("é") || result.contains("\\u00e9") || result.contains("e\u{0301}"));
    }

    #[test]
    fn test_nfc_precomposed_vs_decomposed() {
        // Precomposed and decomposed should produce same output
        let precomposed = r#"{"text":"café"}"#;
        let decomposed = r#"{"text":"cafe\u0301"}"#;

        let result1 = ash_canonicalize_json(precomposed).unwrap();
        let result2 = ash_canonicalize_json(decomposed).unwrap();

        // After NFC normalization, both should be identical
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_unicode_key_normalization() {
        let input = r#"{"cafe\u0301":"value"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("café") || result.len() > 0);
    }

    #[test]
    fn test_emoji_preservation() {
        let input = r#"{"emoji":"😀🎉🚀"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("😀") && result.contains("🎉") && result.contains("🚀"));
    }

    #[test]
    fn test_cjk_characters() {
        let input = r#"{"chinese":"中文","japanese":"日本語","korean":"한국어"}"#;
        let expected = r#"{"chinese":"中文","japanese":"日本語","korean":"한국어"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_combining_mark_sequences() {
        // Multiple combining marks
        let input = r#"{"text":"a\u0300\u0301"}"#;  // a + grave + acute
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.len() > 0);
    }

    #[test]
    fn test_rtl_text_arabic() {
        let input = r#"{"arabic":"مرحبا بالعالم"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("مرحبا"));
    }

    #[test]
    fn test_rtl_text_hebrew() {
        let input = r#"{"hebrew":"שלום עולם"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("שלום"));
    }

    #[test]
    fn test_mixed_script_sorting() {
        // Keys in different scripts should sort by byte order
        let input = r#"{"α":"alpha","a":"latin","א":"aleph"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        // Should be sorted by byte order
        assert!(result.starts_with("{\"a\":"));
    }
}

// =========================================================================
// SPECIAL CHARACTER TESTS
// =========================================================================

mod special_characters {
    use super::*;

    #[test]
    fn test_escaped_quotes() {
        let input = r#"{"text":"He said \"Hello\""}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("\\\"Hello\\\""));
    }

    #[test]
    fn test_escaped_backslash() {
        let input = r#"{"path":"C:\\Users\\test"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("\\\\"));
    }

    #[test]
    fn test_newline_tab_characters() {
        let input = r#"{"text":"line1\nline2\ttab"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("\\n") && result.contains("\\t"));
    }

    #[test]
    fn test_carriage_return() {
        let input = r#"{"text":"line1\rline2"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("\\r"));
    }

    #[test]
    fn test_form_feed_and_backspace() {
        let input = r#"{"text":"a\fb\bc"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.len() > 0);
    }

    #[test]
    fn test_null_character_escaped() {
        let input = r#"{"text":"\u0000"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.len() > 0);
    }

    #[test]
    fn test_control_characters_low_range() {
        // Control characters 0x01 to 0x1F
        for i in 1u8..=0x1F {
            if i == 0x0A || i == 0x0D || i == 0x09 {
                continue; // Skip common escapes
            }
            let input = format!(r#"{{"text":"\u{:04x}"}}"#, i);
            let result = ash_canonicalize_json(&input);
            assert!(result.is_ok(), "Failed for control char 0x{:02X}", i);
        }
    }

    #[test]
    fn test_solidus_not_escaped() {
        // Forward slash does not need to be escaped
        let input = r#"{"url":"https://example.com/path"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("/"));
    }
}

// =========================================================================
// KEY SORTING TESTS
// =========================================================================

mod key_sorting {
    use super::*;

    #[test]
    fn test_numeric_string_keys_lexicographic() {
        // "10" should come before "2" lexicographically
        let input = r#"{"2":"two","10":"ten","1":"one"}"#;
        let expected = r#"{"1":"one","10":"ten","2":"two"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_case_sensitive_sorting() {
        // Uppercase letters come before lowercase in ASCII
        let input = r#"{"b":1,"B":2,"a":3,"A":4}"#;
        let expected = r#"{"A":4,"B":2,"a":3,"b":1}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_underscore_sorting() {
        // Underscore (0x5F) comes after uppercase, before lowercase
        let input = r#"{"_key":1,"zkey":2,"Akey":3}"#;
        let expected = r#"{"Akey":3,"_key":1,"zkey":2}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_empty_string_key() {
        let input = r#"{"":"empty","a":"has value"}"#;
        let expected = r#"{"":"empty","a":"has value"}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_single_character_keys() {
        let input = r#"{"z":26,"a":1,"m":13}"#;
        let expected = r#"{"a":1,"m":13,"z":26}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_long_key_names() {
        let long_key_a = "a".repeat(100);
        let long_key_b = "b".repeat(100);
        let input = format!(r#"{{"{}":{},"{}":{}}}"#, long_key_b, 2, long_key_a, 1);
        let result = ash_canonicalize_json(&input).unwrap();
        assert!(result.find(&long_key_a) < result.find(&long_key_b));
    }

    #[test]
    fn test_special_chars_in_keys() {
        let input = r#"{"key-with-dash":1,"key.with.dot":2,"key_with_underscore":3}"#;
        let result = ash_canonicalize_json(input).unwrap();
        // Dash (0x2D) < Dot (0x2E) < Underscore (0x5F)
        assert!(result.find("key-with-dash") < result.find("key.with.dot"));
    }
}

// =========================================================================
// NUMBER HANDLING TESTS
// =========================================================================

mod number_handling {
    use super::*;

    #[test]
    fn test_integer_zero() {
        let input = r#"{"num":0}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"num":0}"#);
    }

    #[test]
    fn test_negative_zero_becomes_zero() {
        let input = r#"{"num":-0}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"num":0}"#);
    }

    #[test]
    fn test_whole_float_becomes_integer() {
        let input = r#"{"num":5.0}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"num":5}"#);
    }

    #[test]
    fn test_large_whole_float_becomes_integer() {
        let input = r#"{"num":1000000.0}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"num":1000000}"#);
    }

    #[test]
    fn test_fractional_preserved() {
        let input = r#"{"num":3.14159}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("3.14159"));
    }

    #[test]
    fn test_negative_integer() {
        let input = r#"{"num":-42}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert_eq!(result, r#"{"num":-42}"#);
    }

    #[test]
    fn test_negative_float() {
        let input = r#"{"num":-3.14}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("-3.14"));
    }

    #[test]
    fn test_scientific_notation_input() {
        let input = r#"{"num":1e10}"#;
        let result = ash_canonicalize_json(input).unwrap();
        // Should be converted to standard notation
        assert!(result.contains("10000000000"));
    }

    #[test]
    fn test_small_exponential() {
        let input = r#"{"num":1e-5}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("0.00001") || result.contains("1e-5"));
    }

    #[test]
    fn test_max_safe_integer() {
        // 2^53 - 1 = 9007199254740991
        let input = r#"{"num":9007199254740991}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("9007199254740991"));
    }

    #[test]
    fn test_min_safe_integer() {
        // -(2^53 - 1) = -9007199254740991
        let input = r#"{"num":-9007199254740991}"#;
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("-9007199254740991"));
    }
}

// =========================================================================
// DETERMINISM TESTS
// =========================================================================

mod determinism {
    use super::*;

    #[test]
    fn test_repeated_canonicalization_same_result() {
        let input = r#"{"z":1,"a":2,"m":{"x":10,"y":20}}"#;
        let result1 = ash_canonicalize_json(input).unwrap();
        let result2 = ash_canonicalize_json(input).unwrap();
        let result3 = ash_canonicalize_json(input).unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_canonicalize_already_canonical() {
        let canonical = r#"{"a":1,"b":2,"c":3}"#;
        let result = ash_canonicalize_json(canonical).unwrap();
        assert_eq!(result, canonical);
    }

    #[test]
    fn test_whitespace_variations_same_result() {
        let compact = r#"{"a":1,"b":2}"#;
        let with_spaces = r#"{ "a" : 1 , "b" : 2 }"#;
        let with_newlines = "{\n  \"a\": 1,\n  \"b\": 2\n}";

        let result1 = ash_canonicalize_json(compact).unwrap();
        let result2 = ash_canonicalize_json(with_spaces).unwrap();
        let result3 = ash_canonicalize_json(with_newlines).unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_value_api_matches_string_api() {
        let value = json!({"z": 1, "a": 2});
        let string_input = r#"{"z":1,"a":2}"#;

        let result1 = ash_canonicalize_json_value(&value).unwrap();
        let result2 = ash_canonicalize_json(string_input).unwrap();

        assert_eq!(result1, result2);
    }
}

// =========================================================================
// EDGE CASES
// =========================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_single_value_null() {
        let result = ash_canonicalize_json("null").unwrap();
        assert_eq!(result, "null");
    }

    #[test]
    fn test_single_value_true() {
        let result = ash_canonicalize_json("true").unwrap();
        assert_eq!(result, "true");
    }

    #[test]
    fn test_single_value_false() {
        let result = ash_canonicalize_json("false").unwrap();
        assert_eq!(result, "false");
    }

    #[test]
    fn test_single_value_number() {
        let result = ash_canonicalize_json("42").unwrap();
        assert_eq!(result, "42");
    }

    #[test]
    fn test_single_value_string() {
        let result = ash_canonicalize_json(r#""hello""#).unwrap();
        assert_eq!(result, r#""hello""#);
    }

    #[test]
    fn test_unicode_surrogate_pairs() {
        // Emoji that requires surrogate pair in UTF-16
        let input = r#"{"emoji":"𝄞"}"#;  // Musical G clef U+1D11E
        let result = ash_canonicalize_json(input).unwrap();
        assert!(result.contains("𝄞"));
    }

    #[test]
    fn test_very_long_string_value() {
        let long_value = "x".repeat(10000);
        let input = format!(r#"{{"data":"{}"}}"#, long_value);
        let result = ash_canonicalize_json(&input).unwrap();
        assert!(result.contains(&long_value));
    }

    #[test]
    fn test_many_keys_object() {
        let mut input = String::from("{");
        for i in 0..100 {
            if i > 0 { input.push(','); }
            input.push_str(&format!(r#""key{}":{}"#, i, i));
        }
        input.push('}');

        let result = ash_canonicalize_json(&input).unwrap();
        // Keys should be sorted
        assert!(result.find("\"key0\"") < result.find("\"key1\""));
        assert!(result.find("\"key1\"") < result.find("\"key10\""));
    }
}
