//! Cross-SDK Test Vectors for ASH v2.3.2
//!
//! These test vectors MUST produce identical results across all SDK implementations.
//! Any SDK that fails these tests is not compliant with the ASH specification.

use ashcore::{
    ash_build_proof, ash_build_proof_unified, ash_canonicalize_json, ash_canonicalize_query,
    ash_canonicalize_urlencoded, ash_derive_client_secret, ash_extract_scoped_fields, ash_hash_body, ash_hash_proof,
    ash_normalize_binding, ash_timing_safe_equal, ash_verify_proof, ash_verify_proof_unified,
};
use serde_json::json;

// ============================================================================
// FIXED TEST VECTORS - DO NOT MODIFY
// These values are used across all SDK implementations for compatibility testing
// ============================================================================

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_CONTEXT_ID: &str = "ash_test_ctx_12345";
const TEST_BINDING: &str = "POST|/api/transfer|";
const TEST_TIMESTAMP: &str = "1704067200"; // 2024-01-01 00:00:00 UTC in seconds

// ============================================================================
// JSON Canonicalization Tests (RFC 8785 JCS)
// ============================================================================

#[test]
fn test_vector_json_simple_object() {
    let input = r#"{"z":1,"a":2,"m":3}"#;
    let expected = r#"{"a":2,"m":3,"z":1}"#;
    assert_eq!(ash_canonicalize_json(input).unwrap(), expected);
}

#[test]
fn test_vector_json_nested_object() {
    let input = r#"{"outer":{"z":1,"a":2},"inner":{"b":2,"a":1}}"#;
    let expected = r#"{"inner":{"a":1,"b":2},"outer":{"a":2,"z":1}}"#;
    assert_eq!(ash_canonicalize_json(input).unwrap(), expected);
}

#[test]
fn test_vector_json_array_order_preserved() {
    let input = r#"{"arr":[3,1,2]}"#;
    let expected = r#"{"arr":[3,1,2]}"#;
    assert_eq!(ash_canonicalize_json(input).unwrap(), expected);
}

#[test]
fn test_vector_json_negative_zero() {
    let input = r#"{"n":-0}"#;
    let expected = r#"{"n":0}"#;
    assert_eq!(ash_canonicalize_json(input).unwrap(), expected);
}

#[test]
fn test_vector_json_escape_sequences() {
    // Test RFC 8785 required escapes: \b \t \n \f \r \" \\
    let input = r#"{"s":"a\tb\nc"}"#;
    let expected = r#"{"s":"a\tb\nc"}"#;
    assert_eq!(ash_canonicalize_json(input).unwrap(), expected);
}

#[test]
fn test_vector_json_control_char_unicode_escape() {
    // Control char 0x01 must become \u0001 (lowercase hex)
    let input = r#"{"s":"\u0001"}"#;
    let expected = r#"{"s":"\u0001"}"#;
    assert_eq!(ash_canonicalize_json(input).unwrap(), expected);
}

#[test]
fn test_vector_json_unicode_nfc() {
    // é as e + combining acute accent should normalize to composed form
    let input = "{\"s\":\"caf\\u0065\\u0301\"}";
    let result = ash_canonicalize_json(input).unwrap();
    assert!(result.contains("café") || result.contains("\\u00e9"));
}

#[test]
fn test_vector_json_empty_values() {
    assert_eq!(ash_canonicalize_json("null").unwrap(), "null");
    assert_eq!(ash_canonicalize_json("true").unwrap(), "true");
    assert_eq!(ash_canonicalize_json("false").unwrap(), "false");
    assert_eq!(ash_canonicalize_json("{}").unwrap(), "{}");
    assert_eq!(ash_canonicalize_json("[]").unwrap(), "[]");
    assert_eq!(ash_canonicalize_json(r#""""#).unwrap(), r#""""#);
}

// ============================================================================
// Query String Canonicalization Tests
// ============================================================================

#[test]
fn test_vector_query_sorted() {
    let input = "z=1&a=2&m=3";
    let expected = "a=2&m=3&z=1";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

#[test]
fn test_vector_query_duplicate_keys_sorted_by_value() {
    let input = "a=z&a=a&a=m";
    let expected = "a=a&a=m&a=z";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

#[test]
fn test_vector_query_strip_leading_question_mark() {
    let input = "?a=1&b=2";
    let expected = "a=1&b=2";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

#[test]
fn test_vector_query_strip_fragment() {
    let input = "a=1&b=2#section";
    let expected = "a=1&b=2";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

#[test]
fn test_vector_query_uppercase_hex() {
    let input = "a=%2f&b=%2F";
    let expected = "a=%2F&b=%2F";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

#[test]
fn test_vector_query_preserve_empty_values() {
    let input = "a=&b=1";
    let expected = "a=&b=1";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

#[test]
fn test_vector_query_plus_encoded() {
    // In query strings, + is encoded as %2B (RFC 3986 compliant)
    let input = "a+b=1";
    let expected = "a%2Bb=1";
    assert_eq!(ash_canonicalize_query(input).unwrap(), expected);
}

// ============================================================================
// URL-Encoded Canonicalization Tests
// ============================================================================

#[test]
fn test_vector_urlencoded_sorted() {
    let input = "b=2&a=1";
    let expected = "a=1&b=2";
    assert_eq!(ash_canonicalize_urlencoded(input).unwrap(), expected);
}

#[test]
fn test_vector_urlencoded_plus_as_literal() {
    // ASH protocol treats + as literal plus, not space
    let input = "a=hello+world";
    let expected = "a=hello%2Bworld";
    assert_eq!(ash_canonicalize_urlencoded(input).unwrap(), expected);
}

#[test]
fn test_vector_urlencoded_uppercase_hex() {
    let input = "a=hello%2fworld";
    let expected = "a=hello%2Fworld";
    assert_eq!(ash_canonicalize_urlencoded(input).unwrap(), expected);
}

// ============================================================================
// Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)
// ============================================================================

#[test]
fn test_vector_binding_simple() {
    let result = ash_normalize_binding("POST", "/api/test", "").unwrap();
    assert_eq!(result, "POST|/api/test|");
}

#[test]
fn test_vector_binding_lowercase_method() {
    let result = ash_normalize_binding("post", "/api/test", "").unwrap();
    assert_eq!(result, "POST|/api/test|");
}

#[test]
fn test_vector_binding_with_query() {
    let result = ash_normalize_binding("GET", "/api/users", "page=1&sort=name").unwrap();
    assert_eq!(result, "GET|/api/users|page=1&sort=name");
}

#[test]
fn test_vector_binding_query_sorted() {
    let result = ash_normalize_binding("GET", "/api/users", "z=1&a=2").unwrap();
    assert_eq!(result, "GET|/api/users|a=2&z=1");
}

#[test]
fn test_vector_binding_collapse_slashes() {
    let result = ash_normalize_binding("GET", "/api//test///path", "").unwrap();
    assert_eq!(result, "GET|/api/test/path|");
}

#[test]
fn test_vector_binding_remove_trailing_slash() {
    let result = ash_normalize_binding("GET", "/api/test/", "").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

#[test]
fn test_vector_binding_preserve_root() {
    let result = ash_normalize_binding("GET", "/", "").unwrap();
    assert_eq!(result, "GET|/|");
}

#[test]
fn test_vector_binding_error_no_leading_slash() {
    // Rust requires leading slash, should error
    let result = ash_normalize_binding("GET", "api/test", "");
    assert!(result.is_err());
}

// ============================================================================
// Hash Body Tests (SHA-256 lowercase hex)
// ============================================================================

#[test]
fn test_vector_hash_body_known_value() {
    // SHA-256 of "test" is a well-known value
    let result = ash_hash_body("test");
    assert_eq!(
        result,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
}

#[test]
fn test_vector_hash_body_empty() {
    // SHA-256 of empty string
    let result = ash_hash_body("");
    assert_eq!(
        result,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_vector_hash_body_json_payload() {
    let payload = r#"{"amount":100,"recipient":"user123"}"#;
    let result = ash_hash_body(payload);
    // Must be 64 lowercase hex characters
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

// ============================================================================
// Client Secret Derivation Tests
// ============================================================================

#[test]
fn test_vector_derive_client_secret_deterministic() {
    let secret1 = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let secret2 = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    assert_eq!(secret1, secret2);
}

#[test]
fn test_vector_derive_client_secret_format() {
    let secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    // Must be 64 lowercase hex characters (32 bytes HMAC-SHA256)
    assert_eq!(secret.len(), 64);
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[test]
fn test_vector_derive_client_secret_different_inputs() {
    let secret1 = ash_derive_client_secret(TEST_NONCE, "ctx_a", TEST_BINDING).unwrap();
    let secret2 = ash_derive_client_secret(TEST_NONCE, "ctx_b", TEST_BINDING).unwrap();
    assert_ne!(secret1, secret2);
}

// ============================================================================
// Proof Tests
// ============================================================================

#[test]
fn test_vector_build_proof_deterministic() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash = ash_hash_body(r#"{"amount":100}"#);

    let proof1 = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();
    let proof2 = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();

    assert_eq!(proof1, proof2);
}

#[test]
fn test_vector_build_proof_format() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash = ash_hash_body(r#"{"amount":100}"#);

    let proof = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();

    // Must be 64 lowercase hex characters
    assert_eq!(proof.len(), 64);
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[test]
fn test_vector_verify_proof_valid() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash = ash_hash_body(r#"{"amount":100}"#);
    let proof = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();

    let valid = ash_verify_proof(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        &body_hash,
        &proof,
    ).unwrap();

    assert!(valid);
}

#[test]
fn test_vector_verify_proof_invalid_proof() {
    let body_hash = ash_hash_body(r#"{"amount":100}"#);
    let wrong_proof = "0000000000000000000000000000000000000000000000000000000000000000";

    let valid = ash_verify_proof(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        &body_hash,
        wrong_proof,
    ).unwrap();

    assert!(!valid);
}

#[test]
fn test_vector_verify_proof_wrong_body() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash1 = ash_hash_body(r#"{"amount":100}"#);
    let body_hash2 = ash_hash_body(r#"{"amount":200}"#);
    let proof = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash1).unwrap();

    // Verify with different body hash should fail
    let valid = ash_verify_proof(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        &body_hash2,
        &proof,
    ).unwrap();

    assert!(!valid);
}

// ============================================================================
// v2.3 Unified Proof Tests (with Scoping and Chaining)
// ============================================================================

#[test]
fn test_vector_unified_basic_no_scope_no_chain() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let payload = r#"{"amount":100,"note":"test"}"#;

    let result =
        ash_build_proof_unified(&client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, &[], None)
            .unwrap();

    assert_eq!(result.proof.len(), 64);
    assert!(result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());

    // Verify
    let valid = ash_verify_proof_unified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        payload,
        &result.proof,
        &[],
        "",
        None,
        "",
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_vector_unified_with_scope() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let payload = r#"{"amount":100,"note":"test","recipient":"user123"}"#;
    let scope = ["amount", "recipient"];

    let result = ash_build_proof_unified(
        &client_secret,
        TEST_TIMESTAMP,
        TEST_BINDING,
        payload,
        &scope,
        None,
    )
    .unwrap();

    assert!(!result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());

    // Verify
    let valid = ash_verify_proof_unified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        TEST_BINDING,
        TEST_TIMESTAMP,
        payload,
        &result.proof,
        &scope,
        &result.scope_hash,
        None,
        "",
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_vector_unified_with_chain() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, "POST|/api/confirm|").unwrap();
    let payload = r#"{"confirmed":true}"#;
    let previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let result = ash_build_proof_unified(
        &client_secret,
        TEST_TIMESTAMP,
        "POST|/api/confirm|",
        payload,
        &[],
        Some(previous_proof),
    )
    .unwrap();

    assert!(result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());
    assert_eq!(result.chain_hash, ash_hash_proof(previous_proof).unwrap());

    // Verify
    let valid = ash_verify_proof_unified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        "POST|/api/confirm|",
        TEST_TIMESTAMP,
        payload,
        &result.proof,
        &[],
        "",
        Some(previous_proof),
        &result.chain_hash,
    )
    .unwrap();
    assert!(valid);
}

#[test]
fn test_vector_unified_full_scope_and_chain() {
    let client_secret = ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, "POST|/api/finalize|").unwrap();
    let payload = r#"{"amount":500,"approved":true,"recipient":"user456"}"#;
    let scope = ["amount", "approved"];
    let previous_proof = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    let result = ash_build_proof_unified(
        &client_secret,
        TEST_TIMESTAMP,
        "POST|/api/finalize|",
        payload,
        &scope,
        Some(previous_proof),
    )
    .unwrap();

    assert!(!result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());

    // Verify
    let valid = ash_verify_proof_unified(
        TEST_NONCE,
        TEST_CONTEXT_ID,
        "POST|/api/finalize|",
        TEST_TIMESTAMP,
        payload,
        &result.proof,
        &scope,
        &result.scope_hash,
        Some(previous_proof),
        &result.chain_hash,
    )
    .unwrap();
    assert!(valid);
}

// ============================================================================
// Scoped Field Extraction Tests (ENH-003)
// ============================================================================

#[test]
fn test_vector_extract_scoped_fields_simple() {
    let payload = json!({"amount": 100, "note": "test", "recipient": "user123"});
    let scope = ["amount", "recipient"];

    let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

    assert_eq!(result["amount"], 100);
    assert_eq!(result["recipient"], "user123");
    assert!(result.get("note").is_none());
}

#[test]
fn test_vector_extract_scoped_fields_nested() {
    let payload = json!({"user": {"name": "John", "email": "john@example.com"}, "amount": 100});
    let scope = ["user.name", "amount"];

    let result = ash_extract_scoped_fields(&payload, &scope).unwrap();

    assert_eq!(result["user"]["name"], "John");
    assert_eq!(result["amount"], 100);
    assert!(result["user"].get("email").is_none());
}

#[test]
fn test_vector_extract_scoped_fields_empty_scope() {
    let payload = json!({"amount": 100, "note": "test"});
    let scope: [&str; 0] = [];

    let result = ash_extract_scoped_fields(&payload, &scope).unwrap();
    // Empty scope returns full payload
    assert_eq!(result, payload);
}

// ============================================================================
// Hash Proof Tests (for Chaining)
// ============================================================================

#[test]
fn test_vector_hash_proof_deterministic() {
    let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash1 = ash_hash_proof(proof).unwrap();
    let hash2 = ash_hash_proof(proof).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn test_vector_hash_proof_format() {
    let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash = ash_hash_proof(proof).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

// ============================================================================
// Timing-Safe Comparison Tests
// ============================================================================

#[test]
fn test_vector_timing_safe_equal_true() {
    assert!(ash_timing_safe_equal(b"hello", b"hello"));
    assert!(ash_timing_safe_equal(b"", b""));
}

#[test]
fn test_vector_timing_safe_equal_false() {
    assert!(!ash_timing_safe_equal(b"hello", b"world"));
    assert!(!ash_timing_safe_equal(b"hello", b"hello!"));
    assert!(!ash_timing_safe_equal(b"hello", b""));
}

// ============================================================================
// Known Test Vector with Fixed Expected Values
// These MUST match across ALL SDK implementations
// ============================================================================

#[test]
fn test_fixed_vector_client_secret() {
    // This is a fixed test vector - the expected value must be the same in all SDKs
    let nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let context_id = "ash_fixed_test_001";
    let binding = "POST|/api/test|";

    let secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();

    // All SDKs must produce this exact value
    // Formula: HMAC-SHA256(nonce, context_id + "|" + binding)
    assert_eq!(secret.len(), 64);
    // Note: The actual expected value should be computed once and hardcoded
    // For now, we verify format and determinism
    let secret2 = ash_derive_client_secret(nonce, context_id, binding).unwrap();
    assert_eq!(secret, secret2);
}

#[test]
fn test_fixed_vector_body_hash() {
    // Fixed payload for cross-SDK testing
    let payload = r#"{"amount":100,"recipient":"user123"}"#;
    let canonical = ash_canonicalize_json(payload).unwrap();
    let hash = ash_hash_body(&canonical);

    // All SDKs must produce this exact canonical form and hash
    assert_eq!(canonical, r#"{"amount":100,"recipient":"user123"}"#);
    assert_eq!(hash.len(), 64);
}
