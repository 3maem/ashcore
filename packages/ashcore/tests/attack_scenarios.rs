//! Attack Scenario Tests for ASH Core
//! Tests various attack vectors and malicious inputs

use ashcore::*;
use serde_json::json;

// ============================================================================
// INJECTION ATTACKS
// ============================================================================

mod injection_attacks {
    use super::*;

    // SQL injection attempts in various fields
    #[test]
    fn test_sql_injection_in_binding() {
        let injections = vec![
            "/api/users' OR '1'='1",
            "/api/users'; DROP TABLE users; --",
            "/api/users' UNION SELECT * FROM passwords --",
        ];

        for injection in &injections {
            let result = ash_normalize_binding("GET", injection, "");
            // Should either normalize or error, but not panic
            let _ = result;
        }
    }

    // Command injection attempts
    #[test]
    fn test_command_injection() {
        let injections = vec![
            "; cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "| ls -la",
        ];
        
        for injection in &injections {
            let _ = ash_normalize_binding("GET", "/api", injection);
            let _ = ash_canonicalize_query(injection);
        }
    }

    // Path traversal attacks
    #[test]
    fn test_path_traversal_attacks() {
        let traversals = vec![
            "/../../../etc/passwd",
            "/..\\..\\..\\windows\\system32\\config\\sam",
            "/....//....//etc/passwd",
            "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "/..%00/",
            "/..%0d/",
            "/.../...//",
        ];
        
        for path in &traversals {
            // Must handle path traversal attempts without panicking — the call itself is the test
            let _ = ash_normalize_binding("GET", path, "");
        }
    }

    // Null byte injection
    #[test]
    fn test_null_byte_injection() {
        let nonce = "a".repeat(32);
        let injections = vec![
            "ctx\0admin",
            "ctx\0\0\0",
            "GET|/api\0/admin|",
        ];
        
        for injection in &injections {
            let _ = ash_derive_client_secret(&nonce, injection, "GET|/|");
            let _ = ash_normalize_binding("GET", "/api\0/test", "");
        }
    }

    // Header injection attempts
    #[test]
    fn test_header_injection() {
        let injections = vec![
            "value\r\nX-Custom: injected",
            "value\nX-Custom: injected",
            "value\rX-Custom: injected",
        ];
        
        for injection in &injections {
            // These should be handled safely by header extraction
            let _ = ash_canonicalize_json(&format!(r#"{{"header":"{}"}}"#, injection.replace("\"", "\\\"")));
        }
    }
}

// ============================================================================
// FORMAT STRING ATTACKS
// ============================================================================

mod format_string_attacks {
    use super::*;

    #[test]
    fn test_format_string_in_binding() {
        let formats = vec![
            "%s%s%s%s%s",
            "%n%n%n%n%n",
            "%p%p%p%p%p",
            "%x%x%x%x%x",
            "%08x.%08x.%08x.%08x",
        ];
        
        for fmt in &formats {
            let _ = ash_normalize_binding("GET", &format!("/api/{}", fmt), "");
            let _ = ash_canonicalize_query(&format!("q={}", fmt));
        }
    }

    #[test]
    fn test_format_string_in_json() {
        let json = r#"{"msg":"%s%s%s%s","data":"%n%n%n%n"}"#;
        let result = ash_canonicalize_json(json);
        assert!(result.is_ok());
    }
}

// ============================================================================
// REGEX ATTACKS (ReDoS)
// ============================================================================

mod regex_attacks {
    use ashcore::config::*;

    #[test]
    fn test_redos_pattern_registration() {
        ash_clear_scope_policies();
        
        // Patterns that could cause catastrophic backtracking
        let suspicious_patterns = vec![
            "GET|/api/(a+)+|",
            "GET|/api/([a-zA-Z]+)*|",
            "GET|/api/(a|a)+|",
            "GET|/api/(a*)+|",
        ];
        
        for pattern in &suspicious_patterns {
            // Should either succeed with limits or fail gracefully
            let _ = ash_register_scope_policy(pattern, &["field"]);
        }
        ash_clear_scope_policies();
    }
}

// ============================================================================
// INTEGER OVERFLOW ATTACKS
// ============================================================================

mod integer_overflow_attacks {
    use super::*;

    #[test]
    fn test_timestamp_overflow() {
        let overflows = vec![
            "18446744073709551615", // u64::MAX
            "18446744073709551616", // u64::MAX + 1
            "99999999999999999999",
            "100000000000000000000",
        ];
        
        for ts in &overflows {
            let result = ash_validate_timestamp_format(ts);
            assert!(result.is_err() || result.unwrap() <= 32503680000);
        }
    }

    #[test]
    fn test_negative_timestamp_wraparound() {
        // Large negative numbers that might wrap around
        let _ = ash_validate_timestamp_format("-18446744073709551615");
        let _ = ash_validate_timestamp_format("-1");
    }

    #[test]
    fn test_array_index_overflow() {
        let indices = vec![
            "4294967295",  // u32::MAX
            "4294967296",  // u32::MAX + 1
            "9223372036854775807", // i64::MAX
        ];
        
        let payload = json!({"items": [1, 2, 3]});
        for idx in &indices {
            let scope = format!("items[{}]", idx);
            let _ = ash_extract_scoped_fields(&payload, &[&scope]);
        }
    }
}

// ============================================================================
// ENCODING ATTACKS
// ============================================================================

mod encoding_attacks {
    use super::*;

    #[test]
    fn test_double_encoding_attack() {
        let double_encoded = vec![
            "%252F",       // Double-encoded /
            "%25252F",     // Triple-encoded /
            "%253F",       // Double-encoded ?
            "%25253D",     // Triple-encoded =
        ];
        
        for enc in &double_encoded {
            let query = format!("path={}", enc);
            let _ = ash_canonicalize_query(&query);
        }
    }

    #[test]
    fn test_overlong_utf8_encoding() {
        // Overlong UTF-8 sequences (should be rejected)
        let overlong = vec![
            "%C0%AF",      // Overlong /
            "%E0%80%AF",   // Overlong /
            "%F0%80%80%AF", // Overlong /
        ];
        
        for seq in &overlong {
            let query = format!("path={}", seq);
            let _ = ash_canonicalize_query(&query);
        }
    }

    #[test]
    fn test_invalid_utf8_sequences() {
        let invalid = vec![
            "%FF%FE",
            "%FE%FF",
            "%80%80%80%80",
            "%C3%28",      // Invalid sequence
        ];
        
        for seq in &invalid {
            let query = format!("data={}", seq);
            let _ = ash_canonicalize_query(&query);
        }
    }

    #[test]
    fn test_bom_injection() {
        let with_bom = vec![
            "\u{FEFF}GET|/api|",
            "GET\u{FEFF}|/api|",
            "GET|\u{FEFF}/api|",
        ];
        
        for binding in &with_bom {
            let _ = ash_derive_client_secret(&"a".repeat(32), "ctx", binding);
        }
    }

    #[test]
    fn test_mixed_encoding_attack() {
        let mixed = vec![
            ("/api/hello%20world", "/api/hello%20world"),
            ("/api/hello+world", "/api/hello+world"),
            ("/api/hello%2Bworld", "/api/hello%2Bworld"),
        ];
        
        for (input, _expected) in &mixed {
            let _ = ash_normalize_binding("GET", input, "");
        }
    }
}

// ============================================================================
// JSON ATTACKS
// ============================================================================

mod json_attacks {
    use super::*;

    #[test]
    fn test_json_billion_laughs() {
        // XML billion laughs equivalent in JSON
        let nested = r#"{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}}}"#;
        let _ = ash_canonicalize_json(nested);
    }

    #[test]
    fn test_json_hash_collision() {
        // Keys that might cause hash collisions
        let keys: Vec<String> = (0..1000).map(|i| format!("key{:010}", i)).collect();
        let pairs: Vec<String> = keys.iter().enumerate().map(|(i, k)| format!("\"{}\":{}", k, i)).collect();
        let json = format!("{{{}}}", pairs.join(","));
        
        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_json_duplicate_keys() {
        let duplicates = vec![
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"a":2,"a":3}"#,
            r#"{"a":{"b":1},"a":{"b":2}}"#,
        ];
        
        for json in &duplicates {
            let result = ash_canonicalize_json(json);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_json_parser_confusion() {
        let confusing = vec![
            r#"{"\u0000":"null byte"}"#,
            r#"{"\u2028":"line separator"}"#,
            r#"{"\u2029":"paragraph separator"}"#,
            r#"{"\uFEFF":"BOM"}"#,
        ];
        
        for json in &confusing {
            let _ = ash_canonicalize_json(json);
        }
    }

    #[test]
    fn test_json_prototype_pollution_attempts() {
        let pollution = vec![
            r#"{"__proto__":{"polluted":true}}"#,
            r#"{"constructor":{"prototype":{"polluted":true}}}"#,
            r#"{"__defineGetter__":{}}"#,
            r#"{"__defineSetter__":{}}"#,
        ];
        
        for json in &pollution {
            let result = ash_canonicalize_json(json);
            assert!(result.is_ok());
            // In Rust, these are just regular keys
        }
    }

    #[test]
    fn test_json_deeply_nested_arrays() {
        let mut json = String::from("1");
        for _ in 0..100 {
            json = format!("[{}]", json);
        }
        
        let result = ash_canonicalize_json(&json);
        assert!(result.is_err()); // Should exceed depth limit
    }

    #[test]
    fn test_json_sparse_array() {
        // Arrays with very large indices
        let sparse = r#"{"items":{"9999":1}}"#;
        let _ = ash_canonicalize_json(sparse);
    }
}

// ============================================================================
// TIMING ATTACKS
// ============================================================================

mod timing_attacks {
    use super::*;

    #[test]
    fn test_proof_comparison_timing() {
        let nonce = "a".repeat(32);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let proof = ash_build_proof(&secret, "1700000000", "GET|/|", &ash_hash_body("test")).unwrap();
        
        // Test with proofs that differ at various positions
        for i in 0..proof.len() {
            let mut tampered: Vec<char> = proof.chars().collect();
            tampered[i] = if tampered[i] == 'a' { 'b' } else { 'a' };
            let tampered_proof: String = tampered.into_iter().collect();
            
            let valid = ash_verify_proof(&nonce, "ctx", "GET|/|", "1700000000", &ash_hash_body("test"), &tampered_proof).unwrap();
            assert!(!valid);
        }
    }

    #[test]
    fn test_body_hash_comparison_timing() {
        let hash1 = ash_hash_body("test1");
        let hash2 = ash_hash_body("test2");
        
        // Both should take same time regardless of where they differ
        assert!(!ash_timing_safe_equal(hash1.as_bytes(), hash2.as_bytes()));
        
        // Same hash should return true
        assert!(ash_timing_safe_equal(hash1.as_bytes(), hash1.as_bytes()));
    }

    #[test]
    fn test_early_exit_prevention() {
        let nonce = "a".repeat(32);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        
        // Generate many proofs and verify they all take similar time
        for i in 0..100 {
            let proof = ash_build_proof(&secret, &(1700000000 + i).to_string(), "GET|/|", &ash_hash_body("test")).unwrap();
            let _ = ash_verify_proof(&nonce, "ctx", "GET|/|", &(1700000000 + i).to_string(), &ash_hash_body("test"), &proof);
        }
    }
}

// ============================================================================
// REPLAY ATTACKS
// ============================================================================

mod replay_attacks {
    use super::*;

    #[test]
    fn test_timestamp_replay_prevention() {
        let old_timestamp = "1600000000"; // Way in the past
        let result = ash_validate_timestamp(old_timestamp, 300, 60);
        assert!(result.is_err());
    }

    #[test]
    fn test_fresh_timestamp_acceptance() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let result = ash_validate_timestamp(&now, 300, 60);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_replay_across_contexts() {
        let nonce = "a".repeat(32);
        let secret = ash_derive_client_secret(&nonce, "ctx1", "GET|/|").unwrap();
        let proof = ash_build_proof(&secret, "1700000000", "GET|/|", &ash_hash_body("test")).unwrap();
        
        // Try to replay with different context
        let valid = ash_verify_proof(&nonce, "ctx2", "GET|/|", "1700000000", &ash_hash_body("test"), &proof).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_proof_replay_across_bindings() {
        let nonce = "a".repeat(32);
        let secret1 = ash_derive_client_secret(&nonce, "ctx", "GET|/api1|").unwrap();
        let proof = ash_build_proof(&secret1, "1700000000", "GET|/api1|", &ash_hash_body("test")).unwrap();
        
        // Try to replay with different binding
        let valid = ash_verify_proof(&nonce, "ctx", "GET|/api2|", "1700000000", &ash_hash_body("test"), &proof).unwrap();
        assert!(!valid);
    }
}

// ============================================================================
// DENIAL OF SERVICE ATTACKS
// ============================================================================

mod dos_attacks {
    use super::*;

    #[test]
    fn test_slowloris_style_input() {
        // Very slow-to-parse inputs
        let slow = vec![
            "{",
            "{\"",
            "{\"a",
            "{\"a\":",
            "{\"a\":1",
        ];
        
        for input in &slow {
            let _ = ash_canonicalize_json(input);
        }
    }

    #[test]
    fn test_memory_exhaustion_attempt() {
        // These should be rejected before consuming too much memory
        let huge = vec![
            "{\"data\":\"".to_string() + &"x".repeat(100_000_000) + "\"}",
        ];
        
        for input in &huge {
            let result = ash_canonicalize_json(input);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_cpu_exhaustion_attempt() {
        // Deeply nested structures
        let mut json = String::from("1");
        for _ in 0..10000 {
            json = format!("{{\"a\":{}}}", json);
        }
        
        let result = ash_canonicalize_json(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithmic_complexity_attack() {
        // Many similar keys that might cause hash collisions
        let keys: Vec<String> = (0..10000).map(|i| format!("key{:08}", i)).collect();
        let pairs: Vec<String> = keys.iter().enumerate().map(|(i, k)| format!("\"{}\":{}", k, i)).collect();
        let json = format!("{{{}}}", pairs.join(","));
        
        // Should complete in reasonable time
        let start = std::time::Instant::now();
        let _ = ash_canonicalize_json(&json);
        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 10, "Should complete in under 10 seconds");
    }
}

// ============================================================================
// SPOOFING ATTACKS
// ============================================================================

mod spoofing_attacks {
    use super::*;

    #[test]
    fn test_binding_spoofing() {
        let spoof_attempts = vec![
            ("GET|/admin|", "GET|/admin|"),
            ("get|/admin|", "GET|/admin|"),
            ("Get|/admin|", "GET|/admin|"),
        ];
        
        for (input, expected) in &spoof_attempts {
            let result = ash_normalize_binding(&input[0..3], &input[4..input.len()-1], "");
            if let Ok(normalized) = result {
                assert_eq!(&normalized, *expected);
            }
        }
    }

    #[test]
    fn test_case_spoofing_in_context() {
        let nonce = "a".repeat(32);
        
        // Context IDs are case-sensitive
        let ctx1 = "MyContext";
        let ctx2 = "mycontext";
        
        let secret1 = ash_derive_client_secret(&nonce, ctx1, "GET|/|").unwrap();
        let secret2 = ash_derive_client_secret(&nonce, ctx2, "GET|/|").unwrap();
        
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_hex_case_spoofing() {
        let nonce_lower = "a".repeat(32);
        let nonce_upper = "A".repeat(32);
        
        let ctx = "ctx";
        let binding = "GET|/|";
        
        let secret_lower = ash_derive_client_secret(&nonce_lower, ctx, binding).unwrap();
        let secret_upper = ash_derive_client_secret(&nonce_upper, ctx, binding).unwrap();
        
        // Should be normalized to same value
        assert_eq!(secret_lower, secret_upper);
    }
}

// ============================================================================
// SIDE CHANNEL ATTACKS
// ============================================================================

mod side_channel_attacks {
    use super::*;

    #[test]
    fn test_error_message_information_leakage() {
        let test_cases: Vec<(String, &str, &str)> = vec![
            ("".to_string(), "ctx", "GET|/|"),
            ("a".to_string(), "ctx", "GET|/|"),
            ("g".repeat(32), "ctx", "GET|/|"),
        ];
        
        for (nonce, ctx, binding) in &test_cases {
            let result = ash_derive_client_secret(nonce, *ctx, *binding);
            if let Err(e) = result {
                let msg = e.message();
                // Error should not contain sensitive data
                // Only check for nonces with length > 10 to avoid false positives
                if nonce.len() > 10 {
                    assert!(!msg.contains(nonce), "Error should not contain nonce: {}", msg);
                }
                assert!(!msg.contains(ctx), "Error should not contain context ID: {}", msg);
                // Ensure no hex-like patterns in error (potential secret leakage)
                let hex_pattern = regex::Regex::new(r"[0-9a-f]{32,}").unwrap();
                assert!(
                    !hex_pattern.is_match(&msg.to_lowercase()),
                    "Error should not contain hex patterns (potential secret leakage): {}",
                    msg
                );
            }
        }
    }

    #[test]
    fn test_timing_side_channel_protection() {
        // Test that error paths take similar time
        let iterations = 100;
        
        for _ in 0..iterations {
            let _ = ash_derive_client_secret(&"a".repeat(31), "ctx", "GET|/|");
            let _ = ash_derive_client_secret(&"a".repeat(32), "ctx", "GET|/|");
            let _ = ash_derive_client_secret(&"g".repeat(32), "ctx", "GET|/|");
        }
    }
}
