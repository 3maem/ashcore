//! Context Store Tests for ASH Rust SDK
//!
//! Tests for context-related functionality and AshMode type.

use ashcore::{
    ash_generate_nonce, ash_generate_context_id,
    ash_derive_client_secret, ash_build_proof, ash_verify_proof,
    ash_hash_body, ash_normalize_binding,
    AshMode,
};

// =========================================================================
// CONTEXT ID GENERATION
// =========================================================================

mod context_id_generation {
    use super::*;

    #[test]
    fn test_context_id_format() {
        let context_id = ash_generate_context_id().unwrap();
        assert!(context_id.starts_with("ash_"), "Context ID should start with ash_");
        assert!(context_id.len() > 4, "Context ID should have content after prefix");
    }

    #[test]
    fn test_context_id_length() {
        let context_id = ash_generate_context_id().unwrap();
        // ash_ prefix + 32 hex chars
        assert!(context_id.len() >= 36, "Context ID should have sufficient length");
    }

    #[test]
    fn test_context_id_hex_suffix() {
        let context_id = ash_generate_context_id().unwrap();
        let suffix = &context_id[4..]; // After "ash_"
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()),
                "Context ID suffix should be hex");
    }

    #[test]
    fn test_multiple_context_ids_unique() {
        let ids: Vec<String> = (0..100)
            .map(|_| ash_generate_context_id().unwrap())
            .collect();

        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "All context IDs should be unique");
    }

    #[test]
    fn test_context_id_can_be_used_for_secret_derivation() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = "GET|/api/test|";

        let result = ash_derive_client_secret(&nonce, &context_id, binding);
        assert!(result.is_ok(), "Context ID should work for secret derivation");
    }
}

// =========================================================================
// NONCE GENERATION
// =========================================================================

mod nonce_generation {
    use super::*;

    #[test]
    fn test_nonce_length() {
        let nonce = ash_generate_nonce(32).unwrap();
        assert_eq!(nonce.len(), 64, "Nonce should be 64 hex characters");
    }

    #[test]
    fn test_nonce_is_hex() {
        let nonce = ash_generate_nonce(32).unwrap();
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()),
                "Nonce should be valid hex");
    }

    #[test]
    fn test_nonce_is_lowercase() {
        let nonce = ash_generate_nonce(32).unwrap();
        assert!(nonce.chars().all(|c| !c.is_uppercase()),
                "Nonce should be lowercase hex");
    }

    #[test]
    fn test_multiple_nonces_unique() {
        let nonces: Vec<String> = (0..100)
            .map(|_| ash_generate_nonce(32).unwrap())
            .collect();

        let unique: std::collections::HashSet<&String> = nonces.iter().collect();
        assert_eq!(unique.len(), nonces.len(), "All nonces should be unique");
    }

    #[test]
    fn test_nonce_minimum_size() {
        let result = ash_generate_nonce(16);
        assert!(result.is_ok(), "16 bytes should be minimum valid size");
    }

    #[test]
    fn test_nonce_below_minimum_fails() {
        let result = ash_generate_nonce(15);
        assert!(result.is_err(), "Below 16 bytes should fail");
    }

    #[test]
    fn test_nonce_various_sizes() {
        for size in [16, 24, 32, 48, 64] {
            let nonce = ash_generate_nonce(size).unwrap();
            assert_eq!(nonce.len(), size * 2, "Nonce length should be 2x bytes");
        }
    }

    #[test]
    fn test_nonce_entropy() {
        let nonces: Vec<String> = (0..1000)
            .map(|_| ash_generate_nonce(32).unwrap())
            .collect();

        let unique: std::collections::HashSet<&String> = nonces.iter().collect();
        assert_eq!(unique.len(), 1000, "All nonces should be unique (entropy check)");
    }
}

// =========================================================================
// CONTEXT WITH PROOF VERIFICATION
// =========================================================================

mod context_with_proofs {
    use super::*;

    #[test]
    fn test_context_can_be_used_for_proof_verification() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/test", "").unwrap();

        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
        let body_hash = ash_hash_body("{}");
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

        let is_valid = ash_verify_proof(&nonce, &context_id, &binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(is_valid, "Proof with context should verify");
    }

    #[test]
    fn test_proof_fails_with_wrong_context_id() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let wrong_context = ash_generate_context_id().unwrap();
        let binding = "POST|/api/test|";

        let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
        let body_hash = ash_hash_body("{}");
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let is_valid = ash_verify_proof(&nonce, &wrong_context, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(!is_valid, "Proof with wrong context should not verify");
    }

    #[test]
    fn test_proof_fails_with_wrong_nonce() {
        let nonce = ash_generate_nonce(32).unwrap();
        let wrong_nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = "POST|/api/test|";

        let secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
        let body_hash = ash_hash_body("{}");
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

        let is_valid = ash_verify_proof(&wrong_nonce, &context_id, binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(!is_valid, "Proof with wrong nonce should not verify");
    }

    #[test]
    fn test_proof_fails_with_wrong_binding() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let correct_binding = ash_normalize_binding("POST", "/api/test", "").unwrap();
        let wrong_binding = ash_normalize_binding("GET", "/api/other", "").unwrap();

        let secret = ash_derive_client_secret(&nonce, &context_id, &correct_binding).unwrap();
        let body_hash = ash_hash_body("{}");
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let proof = ash_build_proof(&secret, &timestamp, &correct_binding, &body_hash).unwrap();

        let is_valid = ash_verify_proof(&nonce, &context_id, &wrong_binding, &timestamp, &body_hash, &proof).unwrap();
        assert!(!is_valid, "Proof with wrong binding should not verify");
    }

    #[test]
    fn test_multiple_proofs_with_same_context() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/test", "").unwrap();

        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        for i in 0..10 {
            let body = format!("{{\"index\":{}}}", i);
            let body_hash = ash_hash_body(&body);
            let timestamp = (chrono::Utc::now().timestamp() + i).to_string();
            let proof = ash_build_proof(&secret, &timestamp, &binding, &body_hash).unwrap();

            let is_valid = ash_verify_proof(&nonce, &context_id, &binding, &timestamp, &body_hash, &proof).unwrap();
            assert!(is_valid, "All proofs with same context should verify");
        }
    }
}

// =========================================================================
// ASH MODE TESTS
// =========================================================================

mod ash_mode {
    use super::*;

    #[test]
    fn test_ash_mode_default() {
        let mode = AshMode::default();
        assert!(matches!(mode, AshMode::Balanced), "Default mode should be Balanced");
    }

    #[test]
    fn test_ash_mode_strict() {
        let mode = AshMode::Strict;
        assert!(matches!(mode, AshMode::Strict));
    }

    #[test]
    fn test_ash_mode_minimal() {
        let mode = AshMode::Minimal;
        assert!(matches!(mode, AshMode::Minimal));
    }

    #[test]
    fn test_ash_mode_balanced() {
        let mode = AshMode::Balanced;
        assert!(matches!(mode, AshMode::Balanced));
    }

    #[test]
    fn test_ash_mode_from_str() {
        assert!(matches!("strict".parse::<AshMode>().unwrap(), AshMode::Strict));
        assert!(matches!("minimal".parse::<AshMode>().unwrap(), AshMode::Minimal));
        assert!(matches!("balanced".parse::<AshMode>().unwrap(), AshMode::Balanced));
    }

    #[test]
    fn test_ash_mode_from_str_case_insensitive() {
        assert!(matches!("STRICT".parse::<AshMode>().unwrap(), AshMode::Strict));
        assert!(matches!("MINIMAL".parse::<AshMode>().unwrap(), AshMode::Minimal));
        assert!(matches!("BALANCED".parse::<AshMode>().unwrap(), AshMode::Balanced));
    }

    #[test]
    fn test_ash_mode_display() {
        assert_eq!(format!("{}", AshMode::Strict), "strict");
        assert_eq!(format!("{}", AshMode::Minimal), "minimal");
        assert_eq!(format!("{}", AshMode::Balanced), "balanced");
    }

    #[test]
    fn test_ash_mode_invalid_str() {
        let result = "invalid".parse::<AshMode>();
        assert!(result.is_err(), "Invalid mode string should error");
    }

    #[test]
    fn test_ash_mode_clone() {
        let mode = AshMode::Strict;
        let cloned = mode.clone();
        assert!(matches!(cloned, AshMode::Strict));
    }

    #[test]
    fn test_ash_mode_copy() {
        let mode = AshMode::Strict;
        let copied: AshMode = mode;
        assert!(matches!(copied, AshMode::Strict));
        assert!(matches!(mode, AshMode::Strict));
    }

    #[test]
    fn test_ash_mode_eq() {
        assert_eq!(AshMode::Strict, AshMode::Strict);
        assert_eq!(AshMode::Minimal, AshMode::Minimal);
        assert_eq!(AshMode::Balanced, AshMode::Balanced);
        assert_ne!(AshMode::Strict, AshMode::Minimal);
    }
}

// =========================================================================
// BINDING VALIDATION
// =========================================================================

mod binding_validation {
    use super::*;

    #[test]
    fn test_binding_with_simple_path() {
        let binding = ash_normalize_binding("GET", "/api/users", "").unwrap();
        assert_eq!(binding, "GET|/api/users|");
    }

    #[test]
    fn test_binding_with_query() {
        let binding = ash_normalize_binding("GET", "/api/users", "page=1&limit=10").unwrap();
        assert!(binding.contains("limit=10"));
        assert!(binding.contains("page=1"));
    }

    #[test]
    fn test_binding_with_trailing_slash() {
        let binding = ash_normalize_binding("GET", "/api/users/", "").unwrap();
        assert!(binding.contains("/api/users"));
    }

    #[test]
    fn test_binding_method_uppercased() {
        let binding = ash_normalize_binding("get", "/api/users", "").unwrap();
        assert!(binding.starts_with("GET|"), "Method should be uppercased");
    }

    #[test]
    fn test_binding_query_sorted() {
        let binding = ash_normalize_binding("GET", "/api", "z=3&a=1&m=2").unwrap();
        let parts: Vec<&str> = binding.split('|').collect();
        assert!(parts[2].starts_with("a=1"), "Query should be sorted");
    }

    #[test]
    fn test_binding_empty_query() {
        let binding = ash_normalize_binding("POST", "/api/data", "").unwrap();
        assert_eq!(binding, "POST|/api/data|");
    }

    #[test]
    fn test_binding_root_path() {
        let binding = ash_normalize_binding("GET", "/", "").unwrap();
        assert_eq!(binding, "GET|/|");
    }

    #[test]
    fn test_binding_with_unicode_path() {
        let binding = ash_normalize_binding("GET", "/api/users", "name=用户").unwrap();
        // Unicode in query values is URL-encoded
        assert!(binding.contains("name="));
    }

    #[test]
    fn test_binding_consistency() {
        let binding1 = ash_normalize_binding("POST", "/api/test", "a=1&b=2").unwrap();
        let binding2 = ash_normalize_binding("POST", "/api/test", "a=1&b=2").unwrap();
        assert_eq!(binding1, binding2, "Same inputs should produce same binding");
    }

    #[test]
    fn test_binding_query_order_independence() {
        let binding1 = ash_normalize_binding("GET", "/api", "a=1&b=2").unwrap();
        let binding2 = ash_normalize_binding("GET", "/api", "b=2&a=1").unwrap();
        assert_eq!(binding1, binding2, "Query param order should not matter");
    }
}
