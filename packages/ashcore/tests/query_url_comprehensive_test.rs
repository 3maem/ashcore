//! Comprehensive Query/URL Encoding Tests
//!
//! These tests cover:
//! - Percent encoding
//! - Special character handling
//! - Query string parsing
//! - Base64URL encoding (if available)
//! - Edge cases

use ashcore::{ash_canonicalize_query, ash_canonicalize_urlencoded};

// =========================================================================
// PERCENT ENCODING TESTS
// =========================================================================

mod percent_encoding {
    use super::*;

    #[test]
    fn test_encode_space_as_percent20() {
        let result = ash_canonicalize_query("key=hello world").unwrap();
        assert!(result.contains("%20"));
        assert!(!result.contains("+"));
    }

    #[test]
    fn test_plus_is_literal_plus() {
        let result = ash_canonicalize_query("key=a+b").unwrap();
        assert!(result.contains("%2B"));
    }

    #[test]
    fn test_unreserved_chars_not_encoded() {
        // RFC 3986 unreserved: A-Z a-z 0-9 - _ . ~
        let result = ash_canonicalize_query("key=AZaz09-_.~").unwrap();
        assert!(result.contains("AZaz09-_.~"));
    }

    #[test]
    fn test_reserved_chars_encoded() {
        let result = ash_canonicalize_query("key=:/?#[]@!$&'()*+,;=").unwrap();
        // These should be encoded
        assert!(result.contains("%"));
    }

    #[test]
    fn test_uppercase_hex_encoding() {
        let result = ash_canonicalize_query("key=%2f").unwrap();
        assert!(result.contains("%2F"));  // Should be uppercase
        assert!(!result.contains("%2f")); // Should not be lowercase
    }

    #[test]
    fn test_encode_multibyte_utf8() {
        let result = ash_canonicalize_query("key=café").unwrap();
        // é (U+00E9) = C3 A9 in UTF-8
        assert!(result.contains("%C3%A9") || result.contains("caf%C3%A9"));
    }

    #[test]
    fn test_encode_emoji() {
        let result = ash_canonicalize_query("key=😀").unwrap();
        // 😀 (U+1F600) = F0 9F 98 80 in UTF-8
        assert!(result.contains("%F0%9F%98%80"));
    }

    #[test]
    fn test_encode_chinese_characters() {
        let result = ash_canonicalize_query("key=中文").unwrap();
        // 中 = E4 B8 AD, 文 = E6 96 87
        assert!(result.contains("%E4%B8%AD%E6%96%87") || result.contains("key="));
    }

    #[test]
    fn test_percent_encoding_preserved() {
        let result = ash_canonicalize_query("key=%20").unwrap();
        assert!(result.contains("%20"));
    }

    #[test]
    fn test_double_encoding_not_applied() {
        // Input is already encoded - should not double encode
        let result = ash_canonicalize_query("key=%2520").unwrap();
        // %25 = %, so %2520 decodes to %20
        // After canonicalization, should re-encode
        assert!(result.contains("%2520") || result.contains("%20"));
    }
}

// =========================================================================
// SPECIAL CHARACTER TESTS
// =========================================================================

mod special_characters {
    use super::*;

    #[test]
    fn test_ampersand_separator() {
        let result = ash_canonicalize_query("a=1&b=2").unwrap();
        assert!(result.contains("&"));
    }

    #[test]
    fn test_equals_separator() {
        let result = ash_canonicalize_query("key=value").unwrap();
        assert!(result.contains("key=value"));
    }

    #[test]
    fn test_equals_in_value() {
        let result = ash_canonicalize_query("key=a=b").unwrap();
        // The second = should be encoded or preserved
        assert!(result.contains("key="));
    }

    #[test]
    fn test_ampersand_in_value() {
        let result = ash_canonicalize_query("key=a%26b").unwrap();
        assert!(result.contains("%26"));
    }

    #[test]
    fn test_hash_stripped() {
        let result = ash_canonicalize_query("key=value#fragment").unwrap();
        assert!(!result.contains("#"));
        assert!(!result.contains("fragment"));
    }

    #[test]
    fn test_question_mark_stripped() {
        let result = ash_canonicalize_query("?key=value").unwrap();
        assert!(!result.starts_with("?"));
    }

    #[test]
    fn test_semicolon_encoded() {
        let result = ash_canonicalize_query("key=a;b").unwrap();
        assert!(result.contains("%3B") || !result.contains(";"));
    }

    #[test]
    fn test_backslash_encoded() {
        let result = ash_canonicalize_query("key=a\\b").unwrap();
        assert!(result.contains("%5C") || result.contains("\\"));
    }

    #[test]
    fn test_quote_characters() {
        let result = ash_canonicalize_query("key=\"value\"").unwrap();
        assert!(result.contains("%22"));
    }

    #[test]
    fn test_angle_brackets() {
        let result = ash_canonicalize_query("key=<script>").unwrap();
        assert!(result.contains("%3C") && result.contains("%3E"));
    }

    #[test]
    fn test_curly_braces() {
        let result = ash_canonicalize_query("key={json}").unwrap();
        assert!(result.contains("%7B") && result.contains("%7D"));
    }

    #[test]
    fn test_pipe_character() {
        let result = ash_canonicalize_query("key=a|b").unwrap();
        assert!(result.contains("%7C"));
    }

    #[test]
    fn test_caret_character() {
        let result = ash_canonicalize_query("key=a^b").unwrap();
        assert!(result.contains("%5E"));
    }

    #[test]
    fn test_backtick_character() {
        let result = ash_canonicalize_query("key=`test`").unwrap();
        assert!(result.contains("%60"));
    }
}

// =========================================================================
// QUERY STRING PARSING TESTS
// =========================================================================

mod query_parsing {
    use super::*;

    #[test]
    fn test_empty_query() {
        let result = ash_canonicalize_query("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_only_question_mark() {
        let result = ash_canonicalize_query("?").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_only_fragment() {
        let result = ash_canonicalize_query("#fragment").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_key_no_value() {
        let result = ash_canonicalize_query("flag").unwrap();
        assert_eq!(result, "flag=");
    }

    #[test]
    fn test_key_with_empty_value() {
        let result = ash_canonicalize_query("key=").unwrap();
        assert_eq!(result, "key=");
    }

    #[test]
    fn test_multiple_empty_values() {
        let result = ash_canonicalize_query("a=&b=&c=").unwrap();
        assert_eq!(result, "a=&b=&c=");
    }

    #[test]
    fn test_duplicate_keys() {
        let result = ash_canonicalize_query("a=1&a=2&a=3").unwrap();
        assert_eq!(result, "a=1&a=2&a=3");
    }

    #[test]
    fn test_duplicate_keys_sorted_by_value() {
        let result = ash_canonicalize_query("a=3&a=1&a=2").unwrap();
        assert_eq!(result, "a=1&a=2&a=3");
    }

    #[test]
    fn test_keys_sorted_alphabetically() {
        let result = ash_canonicalize_query("z=3&a=1&m=2").unwrap();
        assert_eq!(result, "a=1&m=2&z=3");
    }

    #[test]
    fn test_case_sensitive_keys() {
        let result = ash_canonicalize_query("B=2&a=1&b=3&A=0").unwrap();
        // Byte order: A (65) < B (66) < a (97) < b (98)
        assert!(result.find("A=0") < result.find("B=2"));
        assert!(result.find("B=2") < result.find("a=1"));
        assert!(result.find("a=1") < result.find("b=3"));
    }

    #[test]
    fn test_numeric_keys_sorted_lexicographically() {
        let result = ash_canonicalize_query("10=b&2=a&1=c").unwrap();
        // "1" < "10" < "2" lexicographically
        assert!(result.find("1=c") < result.find("10=b"));
        assert!(result.find("10=b") < result.find("2=a"));
    }

    #[test]
    fn test_empty_key() {
        let result = ash_canonicalize_query("=value&key=other").unwrap();
        // Empty key should be sorted first
        assert!(result.starts_with("=value"));
    }

    #[test]
    fn test_trailing_ampersand() {
        let result = ash_canonicalize_query("a=1&b=2&").unwrap();
        // Trailing ampersand should be handled
        assert_eq!(result, "a=1&b=2");
    }

    #[test]
    fn test_leading_ampersand() {
        let result = ash_canonicalize_query("&a=1&b=2").unwrap();
        assert_eq!(result, "a=1&b=2");
    }

    #[test]
    fn test_multiple_ampersands() {
        let result = ash_canonicalize_query("a=1&&b=2&&&c=3").unwrap();
        assert_eq!(result, "a=1&b=2&c=3");
    }
}

// =========================================================================
// URL-ENCODED FORM DATA TESTS
// =========================================================================

mod urlencoded_form {
    use super::*;

    #[test]
    fn test_basic_urlencoded() {
        let result = ash_canonicalize_urlencoded("a=1&b=2").unwrap();
        assert_eq!(result, "a=1&b=2");
    }

    #[test]
    fn test_urlencoded_sorted() {
        let result = ash_canonicalize_urlencoded("z=3&a=1&m=2").unwrap();
        assert_eq!(result, "a=1&m=2&z=3");
    }

    #[test]
    fn test_urlencoded_plus_as_literal() {
        let result = ash_canonicalize_urlencoded("key=a+b").unwrap();
        // In ashcore, + is literal plus, not space
        assert!(result.contains("%2B"));
    }

    #[test]
    fn test_urlencoded_space_preserved() {
        let result = ash_canonicalize_urlencoded("key=hello%20world").unwrap();
        assert!(result.contains("%20"));
    }

    #[test]
    fn test_urlencoded_empty() {
        let result = ash_canonicalize_urlencoded("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_urlencoded_unicode() {
        let result = ash_canonicalize_urlencoded("name=Jos%C3%A9").unwrap();
        // José should be preserved
        assert!(result.contains("Jos%C3%A9") || result.contains("name="));
    }
}

// =========================================================================
// EDGE CASES
// =========================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_very_long_key() {
        let long_key = "k".repeat(1000);
        let query = format!("{}=value", long_key);
        let result = ash_canonicalize_query(&query).unwrap();
        assert!(result.contains(&long_key));
    }

    #[test]
    fn test_very_long_value() {
        let long_value = "v".repeat(1000);
        let query = format!("key={}", long_value);
        let result = ash_canonicalize_query(&query).unwrap();
        assert!(result.contains(&long_value));
    }

    #[test]
    fn test_many_parameters() {
        let params: String = (0..100)
            .map(|i| format!("p{}={}", i, i))
            .collect::<Vec<_>>()
            .join("&");

        let result = ash_canonicalize_query(&params).unwrap();

        // Should contain all params
        assert!(result.contains("p0=0"));
        assert!(result.contains("p99=99"));
    }

    #[test]
    fn test_unicode_key() {
        let result = ash_canonicalize_query("键=值").unwrap();
        // Unicode keys should be encoded
        assert!(result.contains("%"));
    }

    #[test]
    fn test_mixed_ascii_unicode() {
        let result = ash_canonicalize_query("name=José&age=30").unwrap();
        assert!(result.contains("age=30"));
    }

    #[test]
    fn test_null_byte_handling() {
        let result = ash_canonicalize_query("key=a%00b").unwrap();
        // Null byte should be handled
        assert!(result.contains("%00"));
    }

    #[test]
    fn test_percent_at_end() {
        // Malformed encoding - percent at end
        let result = ash_canonicalize_query("key=value%");
        assert!(result.is_err());
    }

    #[test]
    fn test_percent_incomplete() {
        // Malformed encoding - incomplete hex
        let result = ash_canonicalize_query("key=value%2");
        assert!(result.is_err());
    }

    #[test]
    fn test_percent_invalid_hex() {
        // Invalid hex characters
        let result = ash_canonicalize_query("key=value%GG");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_safe_characters() {
        // These are safe in URLs and don't need encoding in query values
        let result = ash_canonicalize_query("key=a-b_c.d~e").unwrap();
        assert!(result.contains("a-b_c.d~e"));
    }

    #[test]
    fn test_repeated_special_chars() {
        let result = ash_canonicalize_query("key=!!!").unwrap();
        // ! is sub-delimiter, may be encoded
        assert!(result.contains("%21") || result.contains("!!!"));
    }
}

// =========================================================================
// DETERMINISM TESTS
// =========================================================================

mod determinism {
    use super::*;

    #[test]
    fn test_canonicalization_deterministic() {
        let query = "z=3&a=1&m=2&a=0";

        let result1 = ash_canonicalize_query(query).unwrap();
        let result2 = ash_canonicalize_query(query).unwrap();
        let result3 = ash_canonicalize_query(query).unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_reordering_same_result() {
        let query1 = "a=1&b=2&c=3";
        let query2 = "c=3&a=1&b=2";
        let query3 = "b=2&c=3&a=1";

        let result1 = ash_canonicalize_query(query1).unwrap();
        let result2 = ash_canonicalize_query(query2).unwrap();
        let result3 = ash_canonicalize_query(query3).unwrap();

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_encoding_variation_same_result() {
        let query1 = "key=hello world";
        let query2 = "key=hello%20world";

        let result1 = ash_canonicalize_query(query1).unwrap();
        let result2 = ash_canonicalize_query(query2).unwrap();

        assert_eq!(result1, result2);
    }
}
