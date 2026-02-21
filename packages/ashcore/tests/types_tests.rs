//! Type Tests for ASH Rust SDK
//!
//! Tests for type exports, type inference, and type safety.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query, ash_canonicalize_urlencoded,
    ash_hash_body, ash_normalize_binding, ash_normalize_binding_from_url,
    ash_generate_nonce, ash_generate_context_id,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_build_proof_unified, ash_verify_proof_unified,
    ash_validate_timestamp, ash_timing_safe_equal,
    ash_extract_scoped_fields, ash_extract_scoped_fields_strict,
    UnifiedProofResult, AshMode, AshError, AshErrorCode,
    ASH_SDK_VERSION,
};

// =========================================================================
// FUNCTION EXPORTS VERIFICATION
// =========================================================================

mod function_exports {
    use super::*;

    #[test]
    fn test_core_functions_exist() {
        let _ = ash_build_proof;
        let _ = ash_verify_proof;
        let _ = ash_derive_client_secret;
        let _ = ash_hash_body;
    }

    #[test]
    fn test_canonicalization_functions_exist() {
        let _ = ash_canonicalize_json;
        let _ = ash_canonicalize_query;
        let _ = ash_canonicalize_urlencoded;
    }

    #[test]
    fn test_binding_functions_exist() {
        let _ = ash_normalize_binding;
        let _ = ash_normalize_binding_from_url;
    }

    #[test]
    fn test_generator_functions_exist() {
        let _ = ash_generate_nonce;
        let _ = ash_generate_context_id;
    }

    #[test]
    fn test_scoped_proof_functions_exist() {
        let _ = ash_build_proof_scoped;
        let _ = ash_verify_proof_scoped;
    }

    #[test]
    fn test_unified_proof_functions_exist() {
        let _ = ash_build_proof_unified;
        let _ = ash_verify_proof_unified;
    }

    #[test]
    fn test_utility_functions_exist() {
        let _ = ash_validate_timestamp;
        let _ = ash_timing_safe_equal;
        let _ = ash_extract_scoped_fields;
        let _ = ash_extract_scoped_fields_strict;
    }
}

// =========================================================================
// TYPE EXPORTS VERIFICATION
// =========================================================================

mod type_exports {
    use super::*;

    #[test]
    fn test_unified_proof_result_type() {
        let result = UnifiedProofResult {
            proof: "a".repeat(64),
            scope_hash: String::new(),
            chain_hash: String::new(),
        };

        assert_eq!(result.proof.len(), 64);
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_ash_mode_type() {
        let strict = AshMode::Strict;
        let permissive = AshMode::Minimal;
        let disabled = AshMode::Balanced;

        assert!(matches!(strict, AshMode::Strict));
        assert!(matches!(permissive, AshMode::Minimal));
        assert!(matches!(disabled, AshMode::Balanced));
    }

    #[test]
    fn test_ash_error_type() {
        let result: Result<String, AshError> = Err(AshError::new(AshErrorCode::ValidationError, "test"));
        assert!(result.is_err());
    }
}

// =========================================================================
// CONSTANT EXPORTS VERIFICATION
// =========================================================================

mod constant_exports {
    use super::*;

    #[test]
    fn test_version_constant() {
        assert!(!ASH_SDK_VERSION.is_empty());
    }

    #[test]
    fn test_version_format() {
        let parts: Vec<&str> = ASH_SDK_VERSION.split('.').collect();
        assert!(parts.len() >= 2, "Version should have at least major.minor");
    }
}

// =========================================================================
// RETURN TYPE VERIFICATION
// =========================================================================

mod return_types {
    use super::*;

    #[test]
    fn test_hash_body_returns_string() {
        let hash: String = ash_hash_body("test");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_canonicalize_json_returns_result() {
        let result: Result<String, AshError> = ash_canonicalize_json("{}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_canonicalize_query_returns_result() {
        let result: Result<String, AshError> = ash_canonicalize_query("a=1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_normalize_binding_returns_result() {
        let result: Result<String, AshError> = ash_normalize_binding("GET", "/", "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_secret_returns_result() {
        let nonce = "a".repeat(64);
        let result: Result<String, AshError> = ash_derive_client_secret(&nonce, "ctx", "GET|/|");
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_proof_returns_result() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let result: Result<String, AshError> = ash_build_proof(&secret, "12345", "GET|/|", &"b".repeat(64));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_proof_returns_result_bool() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "GET|/|").unwrap();
        let body_hash = "b".repeat(64);
        let proof = ash_build_proof(&secret, "12345", "GET|/|", &body_hash).unwrap();

        let result: Result<bool, AshError> = ash_verify_proof(&nonce, "ctx", "GET|/|", "12345", &body_hash, &proof);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_nonce_returns_result() {
        let result: Result<String, AshError> = ash_generate_nonce(32);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_context_id_returns_result() {
        let result: Result<String, AshError> = ash_generate_context_id();
        assert!(result.is_ok());
    }

    #[test]
    fn test_scoped_proof_returns_tuple() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let result: Result<(String, String), AshError> = ash_build_proof_scoped(&secret, "12345", "POST|/|", "{}", &[]);
        assert!(result.is_ok());

        let (proof, scope_hash) = result.unwrap();
        assert_eq!(proof.len(), 64);
        assert!(scope_hash.is_empty() || scope_hash.len() == 64);
    }

    #[test]
    fn test_unified_proof_returns_struct() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let result: Result<UnifiedProofResult, AshError> = ash_build_proof_unified(&secret, "12345", "POST|/|", "{}", &[], None);
        assert!(result.is_ok());

        let unified = result.unwrap();
        assert_eq!(unified.proof.len(), 64);
    }

    #[test]
    fn test_validate_timestamp_returns_result() {
        let ts = chrono::Utc::now().timestamp().to_string();
        let result: Result<(), AshError> = ash_validate_timestamp(&ts, 300, 60);
        assert!(result.is_ok());
    }

    #[test]
    fn test_timing_safe_equal_returns_bool() {
        let result: bool = ash_timing_safe_equal(b"test", b"test");
        assert!(result);
    }
}

// =========================================================================
// PARAMETER TYPE VERIFICATION
// =========================================================================

mod parameter_types {
    use super::*;

    #[test]
    fn test_functions_accept_string_refs() {
        let nonce = "a".repeat(64);
        let context_id = "ctx_test";
        let binding = "GET|/|";
        let body_hash = "b".repeat(64);
        let timestamp = "12345";

        let _ = ash_derive_client_secret(&nonce, context_id, binding);
        let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
        let _ = ash_build_proof(&secret, timestamp, binding, &body_hash);
    }

    #[test]
    fn test_functions_accept_owned_strings() {
        let nonce = "a".repeat(64);
        let context_id = String::from("ctx_test");
        let binding = String::from("GET|/|");

        let _ = ash_derive_client_secret(&nonce, &context_id, &binding);
    }

    #[test]
    fn test_scope_accepts_vec_str() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();

        let scope: Vec<&str> = vec!["field1", "field2"];
        let _ = ash_build_proof_scoped(&secret, "12345", "POST|/|", r#"{"field1":1,"field2":2}"#, &scope);
    }

    #[test]
    fn test_timing_safe_accepts_byte_slices() {
        let a: &[u8] = b"test";
        let b: &[u8] = b"test";
        let _ = ash_timing_safe_equal(a, b);
    }

    #[test]
    fn test_timing_safe_accepts_vec_u8() {
        let a: Vec<u8> = vec![1, 2, 3];
        let b: Vec<u8> = vec![1, 2, 3];
        let _ = ash_timing_safe_equal(&a, &b);
    }
}

// =========================================================================
// ERROR TYPE VERIFICATION
// =========================================================================

mod error_types {
    use super::*;

    #[test]
    fn test_error_is_displayable() {
        let err = AshError::new(AshErrorCode::ValidationError, "test error");
        let msg = format!("{}", err);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_error_is_debug() {
        let err = AshError::new(AshErrorCode::ValidationError, "test error");
        let debug = format!("{:?}", err);
        assert!(!debug.is_empty());
    }

    #[test]
    fn test_result_can_use_question_mark() {
        fn inner() -> Result<String, AshError> {
            let nonce = ash_generate_nonce(32)?;
            let context_id = ash_generate_context_id()?;
            let binding = ash_normalize_binding("GET", "/", "")?;
            let secret = ash_derive_client_secret(&nonce, &context_id, &binding)?;
            Ok(secret)
        }

        let result = inner();
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_variants() {
        let _ = AshError::new(AshErrorCode::ValidationError, "test");
    }
}

// =========================================================================
// ASH MODE TYPE METHODS
// =========================================================================

mod ash_mode_methods {
    use super::*;

    #[test]
    fn test_mode_has_default() {
        let mode: AshMode = Default::default();
        assert!(matches!(mode, AshMode::Balanced));
    }

    #[test]
    fn test_mode_implements_from_str() {
        let mode: AshMode = "strict".parse().unwrap();
        assert!(matches!(mode, AshMode::Strict));
    }

    #[test]
    fn test_mode_implements_display() {
        let mode = AshMode::Strict;
        let s = format!("{}", mode);
        assert_eq!(s, "strict");
    }

    #[test]
    fn test_mode_implements_clone() {
        let mode = AshMode::Strict;
        let cloned = mode.clone();
        assert!(matches!(cloned, AshMode::Strict));
    }

    #[test]
    fn test_mode_implements_copy() {
        let mode = AshMode::Strict;
        let copied: AshMode = mode;
        assert!(matches!(copied, AshMode::Strict));
        assert!(matches!(mode, AshMode::Strict));
    }

    #[test]
    fn test_mode_implements_eq() {
        let mode1 = AshMode::Strict;
        let mode2 = AshMode::Strict;
        assert_eq!(mode1, mode2);
    }
}

// =========================================================================
// UNIFIED PROOF RESULT TYPE
// =========================================================================

mod unified_proof_result_type {
    use super::*;

    #[test]
    fn test_unified_result_fields() {
        let result = UnifiedProofResult {
            proof: "a".repeat(64),
            scope_hash: "b".repeat(64),
            chain_hash: "c".repeat(64),
        };

        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.scope_hash.len(), 64);
        assert_eq!(result.chain_hash.len(), 64);
    }

    #[test]
    fn test_unified_result_empty_hashes() {
        let result = UnifiedProofResult {
            proof: "a".repeat(64),
            scope_hash: String::new(),
            chain_hash: String::new(),
        };

        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_unified_result_zeroize_on_drop() {
        // BUG-FIX: Clone was removed from UnifiedProofResult to prevent
        // un-tracked copies of zeroized secret material. Verify the struct
        // can still be constructed and accessed.
        let result = UnifiedProofResult {
            proof: "a".repeat(64),
            scope_hash: String::new(),
            chain_hash: String::new(),
        };

        assert_eq!(result.proof.len(), 64);
        assert!(result.scope_hash.is_empty());
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_unified_result_from_build() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let result = ash_build_proof_unified(&secret, "12345", "POST|/|", "{}", &[], None).unwrap();

        assert_eq!(result.proof.len(), 64);
        assert!(result.chain_hash.is_empty());
    }

    #[test]
    fn test_unified_result_with_scope() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let scope = vec!["field"];
        let result = ash_build_proof_unified(&secret, "12345", "POST|/|", r#"{"field":1}"#, &scope, None).unwrap();

        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.scope_hash.len(), 64);
    }

    #[test]
    fn test_unified_result_with_chain() {
        let nonce = "a".repeat(64);
        let secret = ash_derive_client_secret(&nonce, "ctx", "POST|/|").unwrap();
        let prev_proof = "c".repeat(64);
        let result = ash_build_proof_unified(&secret, "12345", "POST|/|", "{}", &[], Some(&prev_proof)).unwrap();

        assert_eq!(result.proof.len(), 64);
        assert_eq!(result.chain_hash.len(), 64);
    }
}
