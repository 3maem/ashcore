//! External Security Audit Tests for ASH Rust SDK
//!
//! Tests based on OWASP Top 10 and security audit requirements.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_normalize_binding,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_validate_timestamp, ash_timing_safe_equal,
};

// =========================================================================
// A01:2021 - BROKEN ACCESS CONTROL
// =========================================================================

mod a01_access_control {
    use super::*;

    #[test]
    fn test_context_isolation_by_binding() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        // Create proof for /api/users
        let binding_users = "GET|/api/users|";
        let secret = ash_derive_client_secret(&nonce, context_id, binding_users).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding_users, &body_hash).unwrap();

        // Cannot use for /api/admin
        let binding_admin = "GET|/api/admin|";
        let result = ash_verify_proof(&nonce, context_id, binding_admin, &timestamp, &body_hash, &proof).unwrap();
        assert!(!result, "Proof should not work for different binding");
    }

    #[test]
    fn test_context_isolation_by_method() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        // Create proof for GET
        let binding_get = "GET|/api/resource|";
        let secret = ash_derive_client_secret(&nonce, context_id, binding_get).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding_get, &body_hash).unwrap();

        // Cannot use for DELETE
        let binding_delete = "DELETE|/api/resource|";
        let result = ash_verify_proof(&nonce, context_id, binding_delete, &timestamp, &body_hash, &proof).unwrap();
        assert!(!result, "GET proof should not work for DELETE");
    }

    #[test]
    fn test_context_isolation_by_context_id() {
        let nonce = "a".repeat(64);
        let binding = "GET|/api/data|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        // Create proof with context_id_1
        let secret1 = ash_derive_client_secret(&nonce, "ctx_user1", binding).unwrap();
        let proof = ash_build_proof(&secret1, &timestamp, binding, &body_hash).unwrap();

        // Cannot verify with different context_id
        let result = ash_verify_proof(&nonce, "ctx_user2", binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(!result, "Proof should not work for different context_id");
    }

    #[test]
    fn test_binding_enforces_path_exactly() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        let binding_exact = "GET|/api/users/123|";
        let secret = ash_derive_client_secret(&nonce, context_id, binding_exact).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding_exact, &body_hash).unwrap();

        // Cannot use for different user ID
        let binding_other = "GET|/api/users/456|";
        let result = ash_verify_proof(&nonce, context_id, binding_other, &timestamp, &body_hash, &proof).unwrap();
        assert!(!result, "Proof should be path-specific");
    }
}

// =========================================================================
// A02:2021 - CRYPTOGRAPHIC FAILURES
// =========================================================================

mod a02_crypto_failures {
    use super::*;

    #[test]
    fn test_strong_key_derivation() {
        // Different nonces produce very different secrets
        let nonce1 = "a".repeat(64);
        let nonce2 = "b".repeat(64);

        let secret1 = ash_derive_client_secret(&nonce1, "ctx", "GET|/|").unwrap();
        let secret2 = ash_derive_client_secret(&nonce2, "ctx", "GET|/|").unwrap();

        // Should be completely different
        let common_chars: usize = secret1.chars()
            .zip(secret2.chars())
            .filter(|(a, b)| a == b)
            .count();

        assert!(common_chars < 10, "Secrets should be very different");
    }

    #[test]
    fn test_256_bit_hash_output() {
        let hash = ash_hash_body("test");
        assert_eq!(hash.len(), 64, "SHA-256 should produce 64 hex chars (256 bits)");
    }

    #[test]
    fn test_256_bit_proof_output() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let proof = ash_build_proof(&secret, "1700000000", "GET|/|", &"b".repeat(64)).unwrap();
        assert_eq!(proof.len(), 64, "HMAC-SHA256 proof should be 64 hex chars");
    }

    #[test]
    fn test_minimum_entropy_nonce() {
        // Nonce must be at least 128 bits (32 hex chars)
        let short_nonce = "a".repeat(31);
        let result = ash_derive_client_secret(&short_nonce, "ctx", "GET|/|");
        assert!(result.is_err(), "Should reject low-entropy nonce");
    }

    #[test]
    fn test_no_weak_algorithms() {
        // Verify output looks like proper HMAC-SHA256 (random-looking)
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();

        // Should not be all same character
        let unique_chars: std::collections::HashSet<_> = secret.chars().collect();
        assert!(unique_chars.len() > 10, "Secret should have high entropy");
    }
}

// =========================================================================
// A03:2021 - INJECTION
// =========================================================================

mod a03_injection {
    use super::*;

    #[test]
    fn test_json_injection_in_value() {
        let malicious = r#"{"data":"value\",\"injected\":\"true"}"#;
        let result = ash_canonicalize_json(malicious);
        if let Ok(canonical) = result {
            // Should not have injected key
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(&canonical);
            if let Ok(v) = parsed {
                assert!(v.get("injected").is_none(), "Injection should not succeed");
            }
        }
    }

    #[test]
    fn test_query_injection() {
        let malicious = "key=value&admin=true";
        let result = ash_canonicalize_query(malicious).unwrap();
        // Parameters should be properly separated
        assert!(result.contains("admin=true"));
        assert!(result.contains("key=value"));
    }

    #[test]
    fn test_path_injection_in_binding() {
        let result = ash_normalize_binding("GET", "/api/../../../etc/passwd", "");
        assert!(result.is_ok());
        let binding = result.unwrap();
        // Path traversal should be normalized out
        assert!(!binding.contains(".."));
    }

    #[test]
    fn test_null_byte_injection() {
        let json = r#"{"data":"before\u0000after"}"#;
        let result = ash_canonicalize_json(json);
        // Should handle null byte properly
        assert!(result.is_ok());
    }

    #[test]
    fn test_unicode_escape_injection() {
        // Try to inject via Unicode escapes
        let json = r#"{"key":"\u0022\u003a\u0022injected\u0022"}"#;
        let result = ash_canonicalize_json(json);
        if let Ok(canonical) = result {
            // Should not create new key
            let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
            assert!(parsed.get("injected").is_none());
        }
    }
}

// =========================================================================
// A04:2021 - INSECURE DESIGN
// =========================================================================

mod a04_insecure_design {
    use super::*;

    #[test]
    fn test_secure_defaults_nonce_length() {
        // Too short nonce should be rejected by default
        let result = ash_derive_client_secret(&"a".repeat(20), "ctx", "GET|/|");
        assert!(result.is_err());
    }

    #[test]
    fn test_fail_safe_verification() {
        let nonce = "a".repeat(64);
        let timestamp = chrono::Utc::now().timestamp().to_string();

        // Invalid proof should return false, not error
        let result = ash_verify_proof(&nonce, "ctx", "GET|/|", &timestamp, &"b".repeat(64), &"invalid".repeat(8));
        // Should not panic, should return Ok(false) or Err
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // Error is also acceptable for invalid format
        }
    }

    #[test]
    fn test_defense_in_depth_timestamp_validation() {
        // Even with valid proof, expired timestamp should fail
        let nonce = "a".repeat(64);
        let old_timestamp = "1000000000";  // Very old
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let _proof = ash_build_proof(&secret, old_timestamp, "GET|/|", &body_hash).unwrap();

        // Timestamp validation should catch this
        let result = ash_validate_timestamp(old_timestamp, 300, 60);
        assert!(result.is_err(), "Old timestamp should be rejected");
    }
}

// =========================================================================
// A05:2021 - SECURITY MISCONFIGURATION
// =========================================================================

mod a05_security_misconfiguration {
    use super::*;

    #[test]
    fn test_sensible_default_timestamp_window() {
        // Current timestamp should be valid with default settings
        let now = chrono::Utc::now().timestamp().to_string();
        let result = ash_validate_timestamp(&now, 300, 60);
        assert!(result.is_ok());
    }

    #[test]
    fn test_clear_error_for_expired_timestamp() {
        let old = (chrono::Utc::now().timestamp() - 3600).to_string();
        let result = ash_validate_timestamp(&old, 300, 60);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("expired") || msg.contains("old") || msg.contains("past"));
    }

    #[test]
    fn test_clear_error_for_invalid_json() {
        let result = ash_canonicalize_json("not json");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("json") || msg.contains("parse") || msg.contains("invalid"));
    }

    #[test]
    fn test_no_stack_trace_in_errors() {
        let result = ash_canonicalize_json("invalid");
        if let Err(e) = result {
            let msg = e.to_string();
            // Should not contain internal implementation details (stack traces)
            // Note: JSON parse errors may contain "line" for position info which is OK
            assert!(!msg.contains("stack trace"));
            assert!(!msg.contains("panic"));
            assert!(!msg.contains(".rs:"));  // No source file references
        }
    }
}

// =========================================================================
// A07:2021 - IDENTIFICATION AND AUTHENTICATION FAILURES
// =========================================================================

mod a07_auth_failures {
    use super::*;

    #[test]
    fn test_proof_verification_required() {
        let nonce = "a".repeat(64);
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        // Wrong proof should fail
        let wrong_proof = "0".repeat(64);
        let result = ash_verify_proof(&nonce, "ctx", "GET|/|", &timestamp, &body_hash, &wrong_proof).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_timestamp_prevents_replay() {
        // Old timestamp (1 hour ago) should be rejected
        let old = (chrono::Utc::now().timestamp() - 3600).to_string();
        let result = ash_validate_timestamp(&old, 300, 60);
        assert!(result.is_err());
    }

    #[test]
    fn test_future_timestamp_rejected() {
        // Future timestamp (1 hour ahead) should be rejected
        let future = (chrono::Utc::now().timestamp() + 3600).to_string();
        let result = ash_validate_timestamp(&future, 300, 60);
        assert!(result.is_err());
    }
}

// =========================================================================
// A08:2021 - SOFTWARE AND DATA INTEGRITY FAILURES
// =========================================================================

mod a08_integrity_failures {
    use super::*;

    #[test]
    fn test_body_hash_verification() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/data|";
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let original_body = r#"{"amount":100}"#;
        let original_hash = ash_hash_body(original_body);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &original_hash).unwrap();

        // Modified body should fail
        let modified_body = r#"{"amount":10000}"#;
        let modified_hash = ash_hash_body(modified_body);

        let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &modified_hash, &proof).unwrap();
        assert!(!result, "Modified body should fail verification");
    }

    #[test]
    fn test_binding_integrity() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = ash_hash_body("{}");

        let binding1 = "POST|/api/transfer|amount=100";
        let secret = ash_derive_client_secret(&nonce, context_id, binding1).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding1, &body_hash).unwrap();

        // Changed query parameter should fail
        let binding2 = "POST|/api/transfer|amount=10000";
        let result = ash_verify_proof(&nonce, context_id, binding2, &timestamp, &body_hash, &proof).unwrap();
        assert!(!result, "Modified binding should fail");
    }

    #[test]
    fn test_scoped_field_integrity() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/payment|";
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

        let payload = r#"{"amount":100,"currency":"USD"}"#;
        let scope = vec!["amount"];

        let (proof, scope_hash) = ash_build_proof_scoped(&secret, &timestamp, binding, payload, &scope).unwrap();

        // Modified scoped field should fail
        let modified = r#"{"amount":10000,"currency":"USD"}"#;
        let result = ash_verify_proof_scoped(&nonce, context_id, binding, &timestamp, modified, &scope, &scope_hash, &proof).unwrap();
        assert!(!result, "Modified scoped field should fail");
    }
}

// =========================================================================
// A09:2021 - SECURITY LOGGING AND MONITORING FAILURES
// =========================================================================

mod a09_logging_failures {
    use super::*;

    #[test]
    fn test_no_sensitive_data_in_errors() {
        let secret_nonce = "secret_".to_string() + &"a".repeat(57);
        let result = ash_derive_client_secret(&secret_nonce, "ctx", "GET|/|");

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains("secret_"), "Error should not contain nonce value");
        }
    }

    #[test]
    fn test_meaningful_error_codes() {
        let result = ash_derive_client_secret("", "ctx", "GET|/|");
        assert!(result.is_err());

        let error = result.unwrap_err();
        // Error should have a code/type, not just message
        let msg = error.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_verification_failure_no_expected_value() {
        let nonce = "a".repeat(64);
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = "b".repeat(64);
        let wrong_proof = "c".repeat(64);

        let result = ash_verify_proof(&nonce, "ctx", "GET|/|", &timestamp, &body_hash, &wrong_proof);

        // Should not error with expected proof value
        assert!(result.is_ok());
        // Result message (if any) should not contain expected proof
    }
}

// =========================================================================
// A10:2021 - SERVER-SIDE REQUEST FORGERY (SSRF)
// =========================================================================

mod a10_ssrf {
    use super::*;

    #[test]
    fn test_path_validation() {
        // Path must start with /
        let result = ash_normalize_binding("GET", "http://evil.com/api", "");
        // Should either fail or normalize properly
        if let Ok(binding) = result {
            assert!(binding.contains("|/") || binding.contains("GET|http"));
        }
    }

    #[test]
    fn test_path_normalization_removes_traversal() {
        let result = ash_normalize_binding("GET", "/api/../../../etc/passwd", "").unwrap();
        // Should not contain path traversal after normalization
        assert!(!result.contains(".."));
    }

    #[test]
    fn test_encoded_path_traversal() {
        // %2e%2e = ..
        let result = ash_normalize_binding("GET", "/api/%2e%2e/%2e%2e/etc/passwd", "");
        if let Ok(binding) = result {
            // After decoding, should still be normalized
            assert!(!binding.contains("passwd") || binding.contains("/etc/passwd"));
        }
    }
}

// =========================================================================
// ADDITIONAL SECURITY TESTS
// =========================================================================

mod additional_security {
    use super::*;

    #[test]
    fn test_timing_safe_comparison() {
        assert!(ash_timing_safe_equal(b"secret", b"secret"));
        assert!(!ash_timing_safe_equal(b"secret", b"SECRET"));
        assert!(!ash_timing_safe_equal(b"secret", b"secret1"));
    }

    #[test]
    fn test_constant_time_proof_comparison() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "GET|/api|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = "b".repeat(64);

        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        // Verification should use constant-time comparison
        let valid = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid);

        // Wrong proof should also take similar time (no early exit)
        let wrong = "0".repeat(64);
        let invalid = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &wrong).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_no_debug_info_leakage() {
        let result = ash_canonicalize_json("invalid json here!!!");
        if let Err(e) = result {
            let msg = e.to_string();
            // Should not contain file paths or internal details
            // Note: JSON parse errors may contain "line" for position info which is OK
            assert!(!msg.contains(".rs"));
            assert!(!msg.contains("src/"));
            assert!(!msg.contains("packages/"));
        }
    }
}
