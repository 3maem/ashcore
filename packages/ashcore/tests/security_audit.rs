//! Security Audit Tests for ASH Rust SDK
//!
//! Tests security vulnerabilities, attack vectors, and hardening measures.
//! Based on TEST-DOCUMENTATION.md security requirements.

use ashcore::{
    ash_build_proof, ash_verify_proof, ash_derive_client_secret,
    ash_canonicalize_json, ash_canonicalize_query,
    ash_hash_body, ash_timing_safe_equal, ash_normalize_binding,
    ash_build_proof_scoped, ash_verify_proof_scoped,
    ash_build_proof_unified, ash_verify_proof_unified,
    ash_extract_scoped_fields, ash_validate_timestamp,
};
use std::collections::HashSet;

// =========================================================================
// INPUT VALIDATION SECURITY
// =========================================================================

#[test]
fn test_rejects_empty_nonce() {
    let result = ash_derive_client_secret("", "ctx_test", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn test_rejects_short_nonce() {
    // Nonce must be at least 32 hex chars (16 bytes)
    let result = ash_derive_client_secret("abcd1234", "ctx_test", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn test_rejects_non_hex_nonce() {
    let result = ash_derive_client_secret("ghijklmnopqrstuvwxyz123456789012", "ctx_test", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn test_rejects_empty_context_id() {
    let nonce = "a".repeat(64);
    let result = ash_derive_client_secret(&nonce, "", "POST|/api|");
    assert!(result.is_err());
}

#[test]
fn test_rejects_empty_binding() {
    let nonce = "a".repeat(64);
    // PT-001: ash_derive_client_secret now validates empty binding
    let result = ash_derive_client_secret(&nonce, "ctx_test", "");
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("binding"));
}

#[test]
fn test_rejects_invalid_json() {
    let result = ash_canonicalize_json("not valid json");
    assert!(result.is_err());
}

#[test]
fn test_rejects_json_with_nan() {
    // NaN is not valid JSON per RFC 8785
    let result = ash_canonicalize_json(r#"{"value": NaN}"#);
    assert!(result.is_err());
}

#[test]
fn test_rejects_json_with_infinity() {
    let result = ash_canonicalize_json(r#"{"value": Infinity}"#);
    assert!(result.is_err());
}

// =========================================================================
// INJECTION PREVENTION
// =========================================================================

#[test]
fn test_json_injection_prevented() {
    // Attempting to inject via special characters
    let payload = r#"{"key": "value\", \"injected\": \"true"}"#;
    let result = ash_canonicalize_json(payload);
    // Should either fail or properly escape
    if let Ok(canonical) = result {
        // If it succeeds, verify no injection occurred
        assert!(!canonical.contains(r#""injected""#));
    }
}

#[test]
fn test_prototype_pollution_in_scope() {
    // Note: Rust SDK doesn't specifically reject __proto__ as dangerous
    // It treats it like any other field name
    let payload = serde_json::json!({"__proto__": {"polluted": true}, "safe": 1});
    let result = ash_extract_scoped_fields(&payload, &["__proto__"]);
    // In Rust, this is OK - the field is extracted if it exists
    assert!(result.is_ok());
    // The field should be in the result
    let extracted = result.unwrap();
    assert!(extracted.get("__proto__").is_some());
}

#[test]
fn test_constructor_field_in_scope() {
    // Note: Rust SDK doesn't specifically reject constructor as dangerous
    // It treats it like any other field name
    let payload = serde_json::json!({"constructor": {"polluted": true}, "safe": 1});
    let result = ash_extract_scoped_fields(&payload, &["constructor"]);
    // In Rust, this is OK - the field is extracted if it exists
    assert!(result.is_ok());
    let extracted = result.unwrap();
    assert!(extracted.get("constructor").is_some());
}

#[test]
fn test_path_traversal_in_scope_prevented() {
    let payload = serde_json::json!({"data": {"nested": 1}});
    // Path traversal attempts should be handled safely
    let result = ash_extract_scoped_fields(&payload, &["../etc/passwd"]);
    // Should either fail or return empty (field not found)
    // Value doesn't have is_empty, check as_object
    if let Ok(extracted) = result {
        let is_empty = extracted.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }
}

// =========================================================================
// CRYPTOGRAPHIC SECURITY
// =========================================================================

#[test]
fn test_nonce_uniqueness() {
    // Generate many nonces and ensure uniqueness
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let nonce = format!("{:064x}", rand::random::<u128>());
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 1000, "Nonces should be unique");
}

#[test]
fn test_proof_is_deterministic() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = "1700000000";
    let body_hash = "b".repeat(64);

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

    let proof1 = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();
    let proof2 = ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    assert_eq!(proof1, proof2, "Same inputs should produce same proof");
}

#[test]
fn test_different_inputs_produce_different_proofs() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = "1700000000";

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

    let proof1 = ash_build_proof(&secret, timestamp, binding, &"a".repeat(64)).unwrap();
    let proof2 = ash_build_proof(&secret, timestamp, binding, &"b".repeat(64)).unwrap();

    assert_ne!(proof1, proof2, "Different inputs should produce different proofs");
}

#[test]
fn test_timing_safe_comparison() {
    // Verify timing-safe comparison works correctly
    assert!(ash_timing_safe_equal(b"abc", b"abc"));
    assert!(!ash_timing_safe_equal(b"abc", b"abd"));
    assert!(!ash_timing_safe_equal(b"abc", b"abcd"));
    assert!(!ash_timing_safe_equal(b"", b"a"));
}

// =========================================================================
// REPLAY PREVENTION
// =========================================================================

#[test]
fn test_timestamp_validation_rejects_old() {
    // Timestamp from 1 hour ago should be rejected
    let old_timestamp = (chrono::Utc::now().timestamp() - 3600).to_string();
    let result = ash_validate_timestamp(&old_timestamp, 300, 60);
    assert!(result.is_err());
}

#[test]
fn test_timestamp_validation_rejects_future() {
    // Timestamp 1 hour in future should be rejected
    let future_timestamp = (chrono::Utc::now().timestamp() + 3600).to_string();
    let result = ash_validate_timestamp(&future_timestamp, 300, 60);
    assert!(result.is_err());
}

#[test]
fn test_timestamp_validation_accepts_current() {
    let current_timestamp = chrono::Utc::now().timestamp().to_string();
    let result = ash_validate_timestamp(&current_timestamp, 300, 60);
    assert!(result.is_ok());
}

// =========================================================================
// INFORMATION DISCLOSURE PREVENTION
// =========================================================================

#[test]
fn test_error_messages_do_not_leak_secrets() {
    let nonce = "secret_nonce_".to_string() + &"a".repeat(51);

    // Try to use invalid nonce
    let result = ash_derive_client_secret(&nonce, "ctx", "POST|/|");

    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(!error_msg.contains("secret_nonce_"),
            "Error message should not contain the nonce");
    }
}

#[test]
fn test_verification_failure_does_not_leak_expected_proof() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let body_hash = "b".repeat(64);
    let wrong_proof = "c".repeat(64);

    let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &wrong_proof);

    // Should return false, not error with expected proof
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

// =========================================================================
// SIZE LIMIT ENFORCEMENT
// =========================================================================

#[test]
fn test_rejects_oversized_json() {
    // Create JSON larger than 10MB limit
    let large_data = "x".repeat(11 * 1024 * 1024);
    let large_json = format!(r#"{{"data": "{}"}}"#, large_data);

    let result = ash_canonicalize_json(&large_json);
    assert!(result.is_err());
}

#[test]
fn test_rejects_deeply_nested_json() {
    // Create deeply nested JSON (> 64 levels)
    let mut json = String::from("1");
    for _ in 0..100 {
        json = format!(r#"{{"a": {}}}"#, json);
    }

    let result = ash_canonicalize_json(&json);
    assert!(result.is_err());
}

#[test]
fn test_rejects_oversized_nonce() {
    // Nonce longer than max allowed (MAX_NONCE_LENGTH = 512 hex chars)
    let long_nonce = "a".repeat(513);
    let result = ash_derive_client_secret(&long_nonce, "ctx", "POST|/|");
    assert!(result.is_err());
}

#[test]
fn test_rejects_oversized_binding() {
    // Binding longer than 8KB - size limit is checked during ash_normalize_binding (BUG-075)
    let long_path = "/".to_string() + &"a".repeat(9000);
    let result = ash_normalize_binding("POST", &long_path, "");
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("exceeds maximum length"));
}

// =========================================================================
// SCOPE SECURITY
// =========================================================================

#[test]
fn test_scope_rejects_too_many_fields() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

    // Create payload with many fields
    let mut payload_map = serde_json::Map::new();
    for i in 0..150 {
        payload_map.insert(format!("field{}", i), serde_json::json!(i));
    }
    let payload = serde_json::Value::Object(payload_map);
    let payload_str = serde_json::to_string(&payload).unwrap();

    // Create scope with too many fields
    let scope: Vec<&str> = (0..150).map(|i| Box::leak(format!("field{}", i).into_boxed_str()) as &str).collect();

    let result = ash_build_proof_scoped(&secret, &timestamp, binding, &payload_str, &scope);
    assert!(result.is_err());
}

#[test]
fn test_scope_field_name_length_limit() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

    // Field name longer than 64 chars
    let long_field = "a".repeat(100);
    let payload = serde_json::json!({&long_field: 1});
    let payload_str = serde_json::to_string(&payload).unwrap();

    let result = ash_build_proof_scoped(&secret, &timestamp, binding, &payload_str, &[&long_field]);
    assert!(result.is_err());
}

// =========================================================================
// ENCODING ATTACKS
// =========================================================================

#[test]
fn test_double_encoding_handled() {
    // %252F is double-encoded /
    let query = "key=%252F";
    let result = ash_canonicalize_query(query);
    assert!(result.is_ok());
    // Should preserve double encoding, not decode twice
    assert!(result.unwrap().contains("%252F"));
}

#[test]
fn test_mixed_case_hex_normalized() {
    // Mix of uppercase and lowercase hex should normalize
    let query = "key=%2f";  // lowercase
    let canonical = ash_canonicalize_query(query).unwrap();
    assert!(canonical.contains("%2F"), "Should uppercase hex digits");
}

#[test]
fn test_unicode_normalization_nfc() {
    // NFD form (e + combining accent) should normalize to NFC (é)
    let nfd = r#"{"text": "cafe\u0301"}"#;  // café in NFD
    let nfc = r#"{"text": "café"}"#;         // café in NFC

    let canonical_nfd = ash_canonicalize_json(nfd).unwrap();
    let canonical_nfc = ash_canonicalize_json(nfc).unwrap();

    assert_eq!(canonical_nfd, canonical_nfc, "Unicode should normalize to NFC");
}

// =========================================================================
// VERIFICATION SECURITY
// =========================================================================

#[test]
fn test_verify_rejects_tampered_binding() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let body_hash = ash_hash_body("{}");

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
    let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

    // Try to verify with different binding
    let tampered_binding = "POST|/api/admin|";
    let result = ash_verify_proof(&nonce, context_id, tampered_binding, &timestamp, &body_hash, &proof).unwrap();

    assert!(!result, "Tampered binding should fail verification");
}

#[test]
fn test_verify_rejects_tampered_body() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let body_hash = ash_hash_body(r#"{"amount": 100}"#);

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();
    let proof = ash_build_proof(&secret, &timestamp, binding, &body_hash).unwrap();

    // Try to verify with different body
    let tampered_body_hash = ash_hash_body(r#"{"amount": 10000}"#);
    let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &tampered_body_hash, &proof).unwrap();

    assert!(!result, "Tampered body should fail verification");
}

#[test]
fn test_verify_rejects_wrong_proof_format() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let body_hash = "b".repeat(64);

    // Wrong length proof
    let short_proof = "abc123";
    let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, short_proof);
    assert!(result.is_err() || !result.unwrap());

    // Non-hex proof
    let invalid_proof = "g".repeat(64);
    let result = ash_verify_proof(&nonce, context_id, binding, &timestamp, &body_hash, &invalid_proof);
    assert!(result.is_err() || !result.unwrap());
}

// =========================================================================
// SCOPED PROOF SECURITY
// =========================================================================

#[test]
fn test_scoped_proof_protects_specified_fields() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let binding = "POST|/api/test|";
    let timestamp = chrono::Utc::now().timestamp().to_string();

    let secret = ash_derive_client_secret(&nonce, context_id, binding).unwrap();

    let payload = r#"{"amount": 100, "memo": "test"}"#;
    let scope = vec!["amount"];

    let (proof, scope_hash) = ash_build_proof_scoped(&secret, &timestamp, binding, payload, &scope).unwrap();

    // Modify memo (unscoped) - should still verify
    let modified_payload = r#"{"amount": 100, "memo": "modified"}"#;
    let result = ash_verify_proof_scoped(&nonce, context_id, binding, &timestamp, modified_payload, &scope, &scope_hash, &proof).unwrap();
    assert!(result, "Unscoped field change should verify");

    // Modify amount (scoped) - should fail
    let tampered_payload = r#"{"amount": 10000, "memo": "test"}"#;
    let result = ash_verify_proof_scoped(&nonce, context_id, binding, &timestamp, tampered_payload, &scope, &scope_hash, &proof).unwrap();
    assert!(!result, "Scoped field change should fail verification");
}

// =========================================================================
// CHAINED PROOF SECURITY
// =========================================================================

#[test]
fn test_chained_proof_integrity() {
    let nonce = "a".repeat(64);
    let context_id = "ctx_test";
    let timestamp = chrono::Utc::now().timestamp().to_string();

    // Step 1
    let binding1 = "POST|/api/step1|";
    let secret1 = ash_derive_client_secret(&nonce, context_id, binding1).unwrap();
    let payload1 = r#"{"step": 1}"#;
    let result1 = ash_build_proof_unified(&secret1, &timestamp, binding1, payload1, &[], None).unwrap();

    // Step 2 chained to step 1
    let binding2 = "POST|/api/step2|";
    let secret2 = ash_derive_client_secret(&nonce, context_id, binding2).unwrap();
    let payload2 = r#"{"step": 2}"#;
    let result2 = ash_build_proof_unified(&secret2, &timestamp, binding2, payload2, &[], Some(&result1.proof)).unwrap();

    // Verify step 2 with correct chain
    let scope: &[&str] = &[];
    let valid = ash_verify_proof_unified(
        &nonce, context_id, binding2, &timestamp, payload2,
        &result2.proof, scope, &result2.scope_hash,
        Some(&result1.proof), &result2.chain_hash
    ).unwrap();
    assert!(valid, "Valid chain should verify");

    // Verify step 2 with wrong previous proof
    let wrong_proof = "d".repeat(64);
    let invalid = ash_verify_proof_unified(
        &nonce, context_id, binding2, &timestamp, payload2,
        &result2.proof, scope, &result2.scope_hash,
        Some(&wrong_proof), &result2.chain_hash
    ).unwrap();
    assert!(!invalid, "Wrong chain should fail verification");
}
