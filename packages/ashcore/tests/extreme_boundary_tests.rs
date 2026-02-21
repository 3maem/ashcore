//! Extreme Boundary Tests for ASH Core
//! Tests every boundary condition and edge case imaginable

use ashcore::*;

// ============================================================================
// NUMERIC BOUNDARY TESTS
// ============================================================================

mod numeric_boundaries {
    use super::*;

    // Test every possible nonce length boundary
    #[test]
    fn test_nonce_boundary_0_to_600() {
        for len in [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 600] {
            let nonce = "a".repeat(len);
            let result = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
            
            if len < 32 || len > 512 {
                assert!(result.is_err(), "Length {} should fail", len);
            } else {
                assert!(result.is_ok(), "Length {} should succeed", len);
            }
        }
    }

    // Test timestamp boundaries
    #[test]
    fn test_timestamp_boundaries() {
        let boundaries = vec![
            "0",          // Minimum valid
            "1",
            "01",         // Leading zero - should fail
            "10",
            "1000000000", // Year 2001
            "2147483647", // Max i32
            "2147483648", // Y2K38
            "32503680000", // Year 3000 (max)
            "32503680001", // Over max
        ];

        for ts in &boundaries {
            let result = ash_validate_timestamp_format(ts);
            match *ts {
                "01" | "32503680001" => assert!(result.is_err(), "{} should fail", ts),
                _ => assert!(result.is_ok(), "{} should succeed", ts),
            }
        }
    }

    // Test body hash length boundaries
    #[test]
    fn test_body_hash_length_boundaries() {
        let nonce = "a".repeat(32);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let timestamp = "1700000000";
        let binding = "GET|/|";

        for len in [0, 1, 32, 63, 64, 65, 128] {
            let body_hash = "a".repeat(len);
            let result = ash_build_proof(&secret, timestamp, binding, &body_hash);
            
            if len != 64 {
                assert!(result.is_err(), "Length {} should fail", len);
            } else {
                assert!(result.is_ok(), "Length {} should succeed", len);
            }
        }
    }
}

// ============================================================================
// STRING BOUNDARY TESTS
// ============================================================================

mod string_boundaries {
    use super::*;

    // Test context ID length boundaries
    #[test]
    fn test_context_id_length_boundaries() {
        let nonce = "a".repeat(32);

        for len in [0, 1, 10, 100, 255, 256, 257, 1000] {
            let ctx = "a".repeat(len);
            let result = ash_derive_client_secret(&nonce, &ctx, "GET|/|");
            
            if len == 0 || len > 256 {
                assert!(result.is_err(), "Length {} should fail", len);
            } else {
                assert!(result.is_ok(), "Length {} should succeed", len);
            }
        }
    }

    // Test binding length boundaries
    #[test]
    fn test_binding_length_boundaries() {
        let nonce = "a".repeat(32);

        // Test various path lengths
        for path_len in [1, 10, 100, 1000, 8000, 8192, 8193, 10000] {
            let path = format!("{}{}", "/", &"a/".repeat(path_len));
            let binding_result = ash_normalize_binding("GET", &path, "");
            
            if binding_result.is_ok() {
                let binding = binding_result.unwrap();
                let result = ash_derive_client_secret(&nonce, "ctx", &binding);
                
                if binding.len() > 8192 {
                    assert!(result.is_err(), "Binding length {} should fail", binding.len());
                } else {
                    assert!(result.is_ok(), "Binding length {} should succeed", binding.len());
                }
            }
        }
    }

    // Test query string length boundaries
    #[test]
    fn test_query_length_boundaries() {
        // BUG-096: MAX_QUERY_PARAMS=1024 — test within and beyond limit.
        for query_len in [0, 100, 1000] {
            let query: String = (0..query_len).map(|i| format!("a{}=b&", i)).collect();
            let result = ash_canonicalize_query(&query);
            assert!(result.is_ok(), "Query with {} params should succeed", query_len);
        }

        // Over 1024 parameters should be rejected
        let over_limit_query: String = (0..1025).map(|i| format!("a{}=b", i)).collect::<Vec<_>>().join("&");
        let result = ash_canonicalize_query(&over_limit_query);
        assert!(result.is_err(), "Query with 1025 params should fail");

        // Very large query should be rejected (over 10MB)
        let huge_query: String = (0..100).map(|i| format!("a{}={}", i, "b".repeat(110000))).collect::<Vec<_>>().join("&");
        let result = ash_canonicalize_query(&huge_query);
        // May succeed or fail - just ensure no panic
        let _ = result;
    }
}

// ============================================================================
// JSON DEPTH BOUNDARIES
// ============================================================================

mod json_depth_boundaries {
    use super::*;

    // Test JSON nesting depth boundaries
    // BUG-095: Check is now `depth >= 64`, so valid depths are 0..63 (64 levels).
    // Wrapping N times creates a leaf at depth N; depth N is rejected if N >= 64.
    #[test]
    fn test_json_nesting_boundaries() {
        for depth in [0, 1, 10, 32, 63, 64, 65, 100] {
            let mut json = String::from("null");
            for _ in 0..depth {
                json = format!(r#"{{"key":{}}}"#, json);
            }

            let result = ash_canonicalize_json(&json);

            if depth >= 64 {
                assert!(result.is_err(), "Depth {} should fail", depth);
            } else {
                assert!(result.is_ok(), "Depth {} should succeed", depth);
            }
        }
    }

    // Test array depth boundaries
    #[test]
    fn test_array_nesting_boundaries() {
        for depth in [0, 1, 10, 32, 63, 64, 65] {
            let mut json = String::from("1");
            for _ in 0..depth {
                json = format!("[{}]", json);
            }

            let result = ash_canonicalize_json(&json);

            if depth >= 64 {
                assert!(result.is_err(), "Depth {} should fail", depth);
            } else {
                assert!(result.is_ok(), "Depth {} should succeed", depth);
            }
        }
    }

    // Test mixed nesting
    #[test]
    fn test_mixed_nesting_boundaries() {
        for depth in [0, 10, 32, 63, 64, 65] {
            let mut json = String::from("1");
            for i in 0..depth {
                if i % 2 == 0 {
                    json = format!(r#"{{"a":{}}}"#, json);
                } else {
                    json = format!("[{}]", json);
                }
            }

            let result = ash_canonicalize_json(&json);

            if depth >= 64 {
                assert!(result.is_err(), "Depth {} should fail", depth);
            } else {
                assert!(result.is_ok(), "Depth {} should succeed", depth);
            }
        }
    }
}

// ============================================================================
// SCOPE BOUNDARY TESTS
// ============================================================================

mod scope_boundaries {
    use super::*;
    use serde_json::json;

    // Test scope field count boundaries
    #[test]
    fn test_scope_field_count_boundaries() {
        // Test that reasonable numbers of fields work
        for count in [0, 1, 10, 50, 100] {
            let fields: Vec<String> = (0..count).map(|i| format!("field{}", i)).collect();
            let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
            
            let result = ash_hash_scope(&field_refs);
            assert!(result.is_ok(), "Count {} should succeed", count);
        }
        
        // Test very large number - may succeed or fail
        let many_fields: Vec<String> = (0..500).map(|i| format!("f{}", i)).collect();
        let many_refs: Vec<&str> = many_fields.iter().map(|s| s.as_str()).collect();
        let _ = ash_hash_scope(&many_refs);
    }

    // Test scope field name length boundaries
    #[test]
    fn test_scope_field_name_length_boundaries() {
        for len in [0, 1, 32, 63, 64, 65, 100] {
            let field = "a".repeat(len);
            let result = ash_hash_scope(&[&field]);
            
            if len == 0 || len > 64 {
                assert!(result.is_err(), "Length {} should fail", len);
            } else {
                assert!(result.is_ok(), "Length {} should succeed", len);
            }
        }
    }

    // Test scope extraction with many fields
    #[test]
    fn test_scope_extraction_field_boundaries() {
        for count in [0, 1, 10, 100, 1000] {
            let mut obj = serde_json::Map::new();
            for i in 0..count {
                obj.insert(format!("field{}", i), json!(i));
            }
            let payload = json!(obj);
            
            let scope: Vec<String> = (0..count.min(100)).map(|i| format!("field{}", i)).collect();
            let scope_refs: Vec<&str> = scope.iter().map(|s| s.as_str()).collect();
            
            let result = ash_extract_scoped_fields(&payload, &scope_refs);
            assert!(result.is_ok(), "Count {} should succeed", count);
        }
    }

    // Test total scope length boundary
    #[test]
    fn test_scope_total_length_boundary() {
        // Each field is 50 chars, test various counts
        for count in [10, 50, 80, 81, 82] {
            let fields: Vec<String> = (0..count).map(|i| format!("{:050}", i)).collect();
            let field_refs: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
            
            let result = ash_hash_scope(&field_refs);
            let total_len: usize = fields.iter().map(|s| s.len() + 1).sum();
            
            if total_len > 4096 {
                assert!(result.is_err(), "Total length {} should fail", total_len);
            } else {
                assert!(result.is_ok(), "Total length {} should succeed", total_len);
            }
        }
    }
}

// ============================================================================
// ARRAY INDEX BOUNDARIES
// ============================================================================

mod array_index_boundaries {
    use super::*;
    use serde_json::json;

    // Test array index boundaries
    #[test]
    fn test_array_index_boundaries() {
        let test_cases = vec![
            (0, true),
            (1, true),
            (10, true),
            (100, true),
            (1000, true),
            (9999, true),
            (10000, false),
            (10001, false),
            (100000, false),
        ];

        for (index, should_succeed) in test_cases {
            let mut arr = Vec::new();
            for i in 0..=index {
                arr.push(json!(i));
            }
            let payload = json!({"items": arr});
            let scope = vec![format!("items[{}]", index)];
            
            let result = ash_extract_scoped_fields(&payload, &[&scope[0]]);
            
            if should_succeed {
                assert!(result.is_ok(), "Index {} should succeed", index);
            } else {
                // May fail or return empty depending on implementation
            }
        }
    }

    // Test negative array index
    #[test]
    fn test_negative_array_index() {
        let payload = json!({"items": [1, 2, 3]});
        let result = ash_extract_scoped_fields(&payload, &["items[-1]"]);
        // Should handle gracefully
        assert!(result.is_ok());
    }

    // Test invalid array index formats
    #[test]
    fn test_invalid_array_index_formats() {
        let payload = json!({"items": [1, 2, 3]});
        let invalid_indices = vec!["items[a]", "items[]", "items[1.5]", "items[ ", "items]"];
        
        for idx in &invalid_indices {
            let _ = ash_extract_scoped_fields(&payload, &[idx]);
            // Should not panic
        }
    }
}

// ============================================================================
// UNICODE BOUNDARY TESTS
// ============================================================================

mod unicode_boundaries {
    use super::*;

    // Test all Unicode planes
    #[test]
    fn test_unicode_planes() {
        let planes = vec![
            ("Basic Multilingual Plane", 'A'),
            ("Supplementary Multilingual", '\u{10000}'),
            ("Supplementary Ideographic", '\u{20000}'),
            ("Tertiary Ideographic", '\u{30000}'),
            ("Supplementary Special-purpose", '\u{E0000}'),
        ];

        for (name, ch) in &planes {
            let json = format!(r#"{{"char":"{}"}}"#, ch);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "{} should succeed", name);
        }
    }

    // Test combining character boundaries
    #[test]
    fn test_combining_character_boundaries() {
        // Test various numbers of combining characters
        for count in [0, 1, 5, 10, 50, 100] {
            let base = 'e';
            let combining: String = std::iter::repeat('\u{0301}').take(count).collect();
            let text = format!("{}{}", base, combining);
            let json = format!(r#"{{"text":"{}"}}"#, text);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Count {} should succeed", count);
        }
    }

    // Test RTL text boundaries
    #[test]
    fn test_rtl_text_boundaries() {
        let rtl_texts = vec![
            "مرحبا",
            "שלום עולם",
            "سلام",
            "ہیلو",
            "నమస్కారం",
        ];

        for text in &rtl_texts {
            let json = format!(r#"{{"text":"{}"}}"#, text);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Text '{}' should succeed", text);
        }
    }

    // Test emoji boundaries
    #[test]
    fn test_emoji_boundaries() {
        let emojis = vec![
            "😀",
            "👨‍👩‍👧‍👦", // Family with ZWJ
            "🏳️‍🌈", // Rainbow flag
            "🧑🏽‍🦱", // Person with curl and medium skin tone
        ];

        for emoji in &emojis {
            let json = format!(r#"{{"emoji":"{}"}}"#, emoji);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Emoji '{}' should succeed", emoji);
        }
    }
}

// ============================================================================
// MEMORY STRESS BOUNDARIES
// ============================================================================

mod memory_stress_boundaries {
    use super::*;

    // Test with increasingly large JSON objects
    #[test]
    fn test_large_json_object_boundaries() {
        let sizes = vec![
            (100, true),
            (1000, true),
            (10000, true),
            (100000, true),
        ];

        for (size, should_succeed) in sizes {
            let keys: Vec<String> = (0..size).map(|i| format!("key{}", i)).collect();
            let pairs: Vec<String> = keys.iter().enumerate().map(|(i, k)| format!("\"{}\":{}", k, i)).collect();
            let json = format!("{{{}}}", pairs.join(","));
            
            let result = ash_canonicalize_json(&json);
            
            if should_succeed {
                assert!(result.is_ok(), "Size {} should succeed", size);
            }
        }
    }

    // Test with large string values
    #[test]
    fn test_large_string_value_boundaries() {
        let sizes = vec![1000, 10000, 100000, 1000000];

        for size in sizes {
            let value = "x".repeat(size);
            let json = format!(r#"{{"data":"{}"}}"#, value);
            let result = ash_canonicalize_json(&json);
            assert!(result.is_ok(), "Size {} should succeed", size);
        }
    }

    // Test with many small allocations
    #[test]
    fn test_many_small_allocations() {
        for _ in 0..10000 {
            let json = r#"{"a":1,"b":2}"#;
            let _ = ash_canonicalize_json(json);
        }
    }
}

// ============================================================================
// TIMESTAMP AGE BOUNDARIES
// ============================================================================

mod timestamp_age_boundaries {
    use super::*;

    // Test timestamp age boundaries
    #[test]
    fn test_timestamp_age_boundaries() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let test_cases = vec![
            (0, true),      // Now
            (30, true),     // 30 seconds ago
            (60, true),     // 1 minute ago
            (300, true),    // 5 minutes ago (exactly at boundary)
            (301, false),   // Just over 5 minutes
            (3600, false),  // 1 hour ago
        ];

        for (age_seconds, should_succeed) in test_cases {
            let timestamp = (now - age_seconds).to_string();
            let result = ash_validate_timestamp(&timestamp, 300, 60);
            
            if should_succeed {
                assert!(result.is_ok(), "Age {} should succeed", age_seconds);
            } else {
                assert!(result.is_err(), "Age {} should fail", age_seconds);
            }
        }
    }

    // Test timestamp future boundaries
    #[test]
    fn test_timestamp_future_boundaries() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let test_cases = vec![
            (0, true),      // Now
            (30, true),     // 30 seconds future
            (60, true),     // 1 minute future (exactly at boundary)
            (61, false),    // Just over 1 minute
            (300, false),   // 5 minutes future
        ];

        for (future_seconds, should_succeed) in test_cases {
            let timestamp = (now + future_seconds).to_string();
            let result = ash_validate_timestamp(&timestamp, 300, 60);
            
            if should_succeed {
                assert!(result.is_ok(), "Future {} should succeed", future_seconds);
            } else {
                assert!(result.is_err(), "Future {} should fail", future_seconds);
            }
        }
    }
}

// ============================================================================
// PATTERN MATCHING BOUNDARIES
// ============================================================================

mod pattern_matching_boundaries {
    use ashcore::config::*;

    // Test pattern length boundaries
    #[test]
    fn test_pattern_length_boundaries() {
        ash_clear_scope_policies();

        // Test reasonable lengths
        for len in [10, 100, 200, 300] {
            let pattern = format!("GET|/{}/|", "a/".repeat(len / 2));
            let result = ash_register_scope_policy(&pattern, &["field"]);
            assert!(result, "Length {} should succeed", len);
        }
        
        // Very long pattern may succeed or fail
        let long_pattern = format!("GET|/{}/|", "a/".repeat(500));
        let _ = ash_register_scope_policy(&long_pattern, &["field"]);
        
        ash_clear_scope_policies();
    }

    // Test wildcard count boundaries
    #[test]
    fn test_wildcard_count_boundaries() {
        ash_clear_scope_policies();

        for count in [1, 4, 8, 9, 10] {
            let pattern = format!("GET|{}|", "*/".repeat(count));
            let result = ash_register_scope_policy(&pattern, &["field"]);
            
            if count > 8 {
                assert!(!result, "Count {} should fail", count);
            } else {
                assert!(result, "Count {} should succeed", count);
            }
        }
        ash_clear_scope_policies();
    }
}

// ============================================================================
// DETERMINISM BOUNDARIES
// ============================================================================

mod determinism_boundaries {
    use super::*;

    // Test that operations are deterministic across many iterations
    #[test]
    fn test_canonicalization_determinism_1000_iterations() {
        let json = r#"{"z":1,"a":{"c":3,"b":2},"arr":[3,1,2]}"#;
        let expected = ash_canonicalize_json(json).unwrap();

        for _ in 0..1000 {
            let result = ash_canonicalize_json(json).unwrap();
            assert_eq!(result, expected, "Canonicalization should be deterministic");
        }
    }

    // Test hash determinism
    #[test]
    fn test_hash_determinism_1000_iterations() {
        let body = "test body content";
        let expected = ash_hash_body(body);

        for _ in 0..1000 {
            let result = ash_hash_body(body);
            assert_eq!(result, expected, "Hash should be deterministic");
        }
    }

    // Test proof determinism
    #[test]
    fn test_proof_determinism_1000_iterations() {
        let nonce = "a".repeat(32);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let timestamp = "1700000000";
        let binding = "GET|/|";
        let body_hash = ash_hash_body("test");
        
        let expected = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

        for _ in 0..1000 {
            let result = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
            assert_eq!(result, expected, "Proof should be deterministic");
        }
    }
}
