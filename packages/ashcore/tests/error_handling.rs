//! Error Handling Tests for ASH Rust SDK
//!
//! Tests error messages, error codes, and graceful failure handling.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_validate_timestamp,
    ash_extract_scoped_fields, ash_extract_scoped_fields_strict,
};

// =========================================================================
// ERROR MESSAGE QUALITY
// =========================================================================

mod error_messages {
    use super::*;

    #[test]
    fn test_meaningful_error_for_empty_nonce() {
        let result = ash_derive_client_secret("", "ctx", "GET|/|");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("nonce") || msg.contains("empty") || msg.contains("required"),
            "Error should mention nonce: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_invalid_nonce_format() {
        let result = ash_derive_client_secret("not-hex-characters!!", "ctx", "GET|/|");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("nonce") || msg.contains("hex") || msg.contains("invalid"),
            "Error should mention nonce format: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_short_nonce() {
        let result = ash_derive_client_secret("abc123", "ctx", "GET|/|");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("nonce") || msg.contains("length") || msg.contains("short") || msg.contains("32"),
            "Error should mention nonce length: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_empty_context_id() {
        let nonce = "a".repeat(64);
        let result = ash_derive_client_secret(&nonce, "", "GET|/|");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("context") || msg.contains("empty") || msg.contains("required"),
            "Error should mention context_id: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_empty_binding() {
        let nonce = "a".repeat(64);
        // PT-001: ash_derive_client_secret now validates empty binding
        let result = ash_derive_client_secret(&nonce, "ctx", "");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("binding") || msg.contains("empty") || msg.contains("required"),
            "Error should mention binding: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_invalid_json() {
        let result = ash_canonicalize_json("not json");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("json") || msg.contains("parse") || msg.contains("invalid") || msg.contains("syntax"),
            "Error should mention JSON: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_invalid_timestamp() {
        let result = ash_validate_timestamp("not-a-number", 300, 60);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("timestamp") || msg.contains("invalid") || msg.contains("format"),
            "Error should mention timestamp: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_expired_timestamp() {
        let old_ts = (chrono::Utc::now().timestamp() - 3600).to_string();
        let result = ash_validate_timestamp(&old_ts, 300, 60);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("expired") || msg.contains("old") || msg.contains("past"),
            "Error should mention expiration: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_future_timestamp() {
        let future_ts = (chrono::Utc::now().timestamp() + 3600).to_string();
        let result = ash_validate_timestamp(&future_ts, 300, 60);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("future") || msg.contains("ahead"),
            "Error should mention future timestamp: {}", error);
    }
}

// =========================================================================
// RESOURCE LIMIT ERRORS
// =========================================================================

mod resource_limits {
    use super::*;

    #[test]
    fn test_meaningful_error_for_oversized_json() {
        let large_data = "x".repeat(11 * 1024 * 1024);
        let large_json = format!(r#"{{"data":"{}"}}"#, large_data);

        let result = ash_canonicalize_json(&large_json);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("size") || msg.contains("large") || msg.contains("maximum") || msg.contains("exceed"),
            "Error should mention size: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_deeply_nested_json() {
        let mut deep_json = String::from("1");
        for _ in 0..100 {
            deep_json = format!(r#"{{"a":{}}}"#, deep_json);
        }

        let result = ash_canonicalize_json(&deep_json);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("depth") || msg.contains("nested") || msg.contains("deep") || msg.contains("recursion"),
            "Error should mention nesting depth: {}", error);
    }

    #[test]
    fn test_meaningful_error_for_oversized_nonce() {
        // MAX_NONCE_LENGTH is now 512 hex characters (256 bytes decoded)
        let long_nonce = "a".repeat(513); // Over the limit
        let result = ash_derive_client_secret(&long_nonce, "ctx", "GET|/|");
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("nonce") || msg.contains("length") || msg.contains("long") || msg.contains("maximum"),
            "Error should mention nonce length: {}", error);
    }
}

// =========================================================================
// SCOPE EXTRACTION ERRORS
// =========================================================================

mod scope_errors {
    use super::*;

    #[test]
    fn test_dangerous_keys_handling() {
        // Note: Rust SDK doesn't specifically reject __proto__ as dangerous
        // It simply won't find the field and returns empty result
        let payload = serde_json::json!({"a": 1});
        let result = ash_extract_scoped_fields(&payload, &["__proto__"]);
        // Result should be Ok with empty/missing field, not an error
        assert!(result.is_ok());
        let extracted = result.unwrap();
        // The field shouldn't exist in the result since it's not in payload
        assert!(extracted.get("__proto__").is_none());
    }

    #[test]
    fn test_error_for_missing_field_strict() {
        let payload = serde_json::json!({"a": 1});
        // The strict version takes (payload, scope, strict_bool)
        let result = ash_extract_scoped_fields_strict(&payload, &["b"], true);
        assert!(result.is_err());

        let error = result.unwrap_err();
        let msg = error.to_string().to_lowercase();
        assert!(msg.contains("missing") || msg.contains("not found") || msg.contains("field") || msg.contains("path"),
            "Error should mention missing field: {}", error);
    }

    #[test]
    fn test_error_for_invalid_array_index() {
        let payload = serde_json::json!({"items": [1, 2]});
        let result = ash_extract_scoped_fields(&payload, &["items[999999999]"]);
        // Should either error or return empty object (index out of bounds)
        if let Ok(extracted) = result {
            // Value doesn't have is_empty/contains_key, check if it's an empty object
            let is_empty = extracted.as_object().map(|o| o.is_empty()).unwrap_or(true);
            let has_key = extracted.get("items[999999999]").is_some();
            assert!(is_empty || !has_key);
        }
    }
}

// =========================================================================
// NO SENSITIVE DATA LEAKAGE
// =========================================================================

mod no_leakage {
    use super::*;

    #[test]
    fn test_no_nonce_in_error() {
        let secret_nonce = format!("secret_nonce_{}", "a".repeat(51));
        let result = ash_derive_client_secret(&secret_nonce, "ctx", "GET|/|");

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains("secret_nonce_"),
                "Error should not contain nonce value");
        }
    }

    #[test]
    fn test_no_secret_in_error() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx_test", "POST|/api|").unwrap();

        // Try to trigger an error with the secret
        let result = ash_build_proof(&secret, "invalid", "POST|/api|", "invalid-hash");

        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains(&secret),
                "Error should not contain client secret");
        }
    }

    #[test]
    fn test_verification_failure_no_expected_proof() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = "b".repeat(64);
        let wrong_proof = "c".repeat(64);

        let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &wrong_proof);

        // Should succeed with false, not error
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

// =========================================================================
// GRACEFUL FALLBACK
// =========================================================================

mod graceful_handling {
    use super::*;

    #[test]
    fn test_verification_returns_false_not_throw() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = "b".repeat(64);
        let invalid_proof = "x".repeat(64);  // Invalid hex

        // Should return Ok(false) or Err, not panic
        let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &invalid_proof);
        // Either false or error, but no panic
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_empty_body_hash() {
        let hash = ash_hash_body("");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_empty_query_canonicalization() {
        let result = ash_canonicalize_query("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_empty_json_canonicalization() {
        let result = ash_canonicalize_json("{}").unwrap();
        assert_eq!(result, "{}");
    }
}

// =========================================================================
// RECOVERY SCENARIOS
// =========================================================================

mod recovery {
    use super::*;

    #[test]
    fn test_recover_after_multiple_failures() {
        // Multiple failures
        for _ in 0..10 {
            let _ = ash_canonicalize_json("invalid json");
        }

        // Should still work after failures
        let result = ash_canonicalize_json(r#"{"valid":"json"}"#);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"valid":"json"}"#);
    }

    #[test]
    fn test_recover_after_verification_failures() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "POST|/api/test|";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body_hash = "b".repeat(64);

        // Multiple failed verifications
        for _ in 0..10 {
            let _ = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &"c".repeat(64));
        }

        // Should still work
        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();
        let valid = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(valid);
    }
}

// =========================================================================
// ERROR CODES
// =========================================================================

mod error_codes {
    use super::*;

    #[test]
    fn test_error_code_accessible() {
        let result = ash_derive_client_secret("", "ctx", "GET|/|");
        if let Err(e) = result {
            // Should have an error code
            let _ = e.code();
        }
    }

    #[test]
    fn test_error_display() {
        let result = ash_derive_client_secret("", "ctx", "GET|/|");
        if let Err(e) = result {
            // Should be displayable
            let msg = format!("{}", e);
            assert!(!msg.is_empty());
        }
    }
}
