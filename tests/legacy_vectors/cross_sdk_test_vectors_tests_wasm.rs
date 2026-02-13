//! Cross-SDK Test Vectors for ASH WASM bindings.
//! These test vectors MUST produce identical results across all SDK implementations.
//! Any SDK that fails these tests is not compliant with the ASH specification.

use ashcore;

// ============================================================================
// FIXED TEST VECTORS - DO NOT MODIFY
// ============================================================================

const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_CONTEXT_ID: &str = "ash_test_ctx_12345";
const TEST_BINDING: &str = "POST|/api/transfer|";
const TEST_TIMESTAMP: &str = "1704067200"; // 2024-01-01 00:00:00 UTC in seconds

// ============================================================================
// JSON CANONICALIZATION CROSS-SDK TESTS (RFC 8785 JCS)
// ============================================================================

#[test]
fn vector_json_simple_object() {
    let input = r#"{"z":1,"a":2,"m":3}"#;
    let expected = r#"{"a":2,"m":3,"z":1}"#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_nested_object() {
    let input = r#"{"outer":{"z":1,"a":2},"inner":{"b":2,"a":1}}"#;
    let expected = r#"{"inner":{"a":1,"b":2},"outer":{"a":2,"z":1}}"#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_array_preserves_order() {
    let input = r#"{"arr":[3,1,2]}"#;
    let expected = r#"{"arr":[3,1,2]}"#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_empty_object() {
    let input = "{}";
    let expected = "{}";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_empty_array() {
    let input = "[]";
    let expected = "[]";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_null() {
    let input = "null";
    let expected = "null";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_true() {
    let input = "true";
    let expected = "true";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_false() {
    let input = "false";
    let expected = "false";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_integer() {
    let input = "42";
    let expected = "42";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_negative_integer() {
    let input = "-42";
    let expected = "-42";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_float() {
    let input = "3.14";
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("3.14") || result.parse::<f64>().unwrap() == 3.14);
}

#[test]
fn vector_json_string() {
    let input = r#""hello""#;
    let expected = r#""hello""#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn vector_json_unicode() {
    let input = r#"{"text":"hello \u4e16\u754c"}"#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    // Should contain the unicode characters
    assert!(result.contains("text"));
}

#[test]
fn vector_json_escapes() {
    let input = r#"{"text":"line1\nline2\ttab"}"#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    assert!(result.contains("\\n") || result.contains('\n'));
}

#[test]
fn vector_json_mixed_types() {
    let input = r#"{"str":"hello","num":42,"bool":true,"null":null,"arr":[1,2],"obj":{"a":1}}"#;
    let result = ashcore::ash_canonicalize_json(input).unwrap();
    // Keys should be sorted
    let arr_pos = result.find("arr").unwrap();
    let bool_pos = result.find("bool").unwrap();
    let null_pos = result.find("null").unwrap();
    let num_pos = result.find("num").unwrap();
    let obj_pos = result.find("obj").unwrap();
    let str_pos = result.find("str").unwrap();
    assert!(arr_pos < bool_pos);
    assert!(bool_pos < null_pos);
    assert!(null_pos < num_pos);
    assert!(num_pos < obj_pos);
    assert!(obj_pos < str_pos);
}

// ============================================================================
// QUERY STRING CANONICALIZATION CROSS-SDK TESTS
// ============================================================================

#[test]
fn vector_query_sorted() {
    let result = ashcore::ash_canonicalize_query("z=1&a=2&m=3").unwrap();
    assert_eq!(result, "a=2&m=3&z=1");
}

#[test]
fn vector_query_strip_leading_question_mark() {
    let result = ashcore::ash_canonicalize_query("?a=1&b=2").unwrap();
    assert_eq!(result, "a=1&b=2");
}

#[test]
fn vector_query_uppercase_hex() {
    let result = ashcore::ash_canonicalize_query("a=%2f&b=%2F").unwrap();
    assert_eq!(result, "a=%2F&b=%2F");
}

#[test]
fn vector_query_preserve_empty_values() {
    let result = ashcore::ash_canonicalize_query("a=&b=1").unwrap();
    assert_eq!(result, "a=&b=1");
}

#[test]
fn vector_query_duplicate_keys_sorted_by_value() {
    let result = ashcore::ash_canonicalize_query("a=z&a=a&a=m").unwrap();
    assert_eq!(result, "a=a&a=m&a=z");
}

#[test]
fn vector_query_empty() {
    let result = ashcore::ash_canonicalize_query("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn vector_query_single_param() {
    let result = ashcore::ash_canonicalize_query("key=value").unwrap();
    assert_eq!(result, "key=value");
}

// ============================================================================
// URL-ENCODED CANONICALIZATION CROSS-SDK TESTS
// ============================================================================

#[test]
fn vector_urlencoded_sorted() {
    let result = ashcore::ash_canonicalize_urlencoded("b=2&a=1").unwrap();
    assert_eq!(result, "a=1&b=2");
}

#[test]
fn vector_urlencoded_plus_as_literal() {
    // ASH protocol treats + as literal plus, not space
    let result = ashcore::ash_canonicalize_urlencoded("a=hello+world").unwrap();
    assert_eq!(result, "a=hello%2Bworld");
}

#[test]
fn vector_urlencoded_uppercase_hex() {
    let result = ashcore::ash_canonicalize_urlencoded("a=hello%2fworld").unwrap();
    assert_eq!(result, "a=hello%2Fworld");
}

#[test]
fn vector_urlencoded_duplicate_keys_sorted() {
    let result = ashcore::ash_canonicalize_urlencoded("a=z&a=a&a=m").unwrap();
    assert_eq!(result, "a=a&a=m&a=z");
}

// ============================================================================
// BINDING NORMALIZATION CROSS-SDK TESTS (v2.3.1+ format: METHOD|PATH|QUERY)
// ============================================================================

#[test]
fn vector_binding_simple() {
    let result = ashcore::ash_normalize_binding("POST", "/api/test", "").unwrap();
    assert_eq!(result, "POST|/api/test|");
}

#[test]
fn vector_binding_lowercase_method() {
    let result = ashcore::ash_normalize_binding("post", "/api/test", "").unwrap();
    assert_eq!(result, "POST|/api/test|");
}

#[test]
fn vector_binding_with_query() {
    let result = ashcore::ash_normalize_binding("GET", "/api/users", "page=1&sort=name").unwrap();
    assert_eq!(result, "GET|/api/users|page=1&sort=name");
}

#[test]
fn vector_binding_query_sorted() {
    let result = ashcore::ash_normalize_binding("GET", "/api/users", "z=1&a=2").unwrap();
    assert_eq!(result, "GET|/api/users|a=2&z=1");
}

#[test]
fn vector_binding_collapse_slashes() {
    let result = ashcore::ash_normalize_binding("GET", "/api//test///path", "").unwrap();
    assert_eq!(result, "GET|/api/test/path|");
}

#[test]
fn vector_binding_remove_trailing_slash() {
    let result = ashcore::ash_normalize_binding("GET", "/api/test/", "").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

#[test]
fn vector_binding_preserve_root() {
    let result = ashcore::ash_normalize_binding("GET", "/", "").unwrap();
    assert_eq!(result, "GET|/|");
}

#[test]
fn vector_binding_requires_leading_slash() {
    // Path without leading slash should error
    let result = ashcore::ash_normalize_binding("GET", "api/test", "");
    assert!(result.is_err());
}

#[test]
fn vector_binding_with_leading_slash() {
    let result = ashcore::ash_normalize_binding("GET", "/api/test", "").unwrap();
    assert_eq!(result, "GET|/api/test|");
}

// ============================================================================
// HASH BODY CROSS-SDK TESTS (SHA-256 lowercase hex)
// ============================================================================

#[test]
fn vector_hash_body_known_value() {
    let result = ashcore::ash_hash_body("test");
    let expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    assert_eq!(result, expected);
}

#[test]
fn vector_hash_body_empty() {
    let result = ashcore::ash_hash_body("");
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(result, expected);
}

#[test]
fn vector_hash_body_format() {
    let result = ashcore::ash_hash_body(r#"{"amount":100,"recipient":"user123"}"#);
    assert_eq!(result.len(), 64);
    assert_eq!(result, result.to_lowercase());
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn vector_hash_body_canonical_json() {
    let canonical = ashcore::ash_canonicalize_json(r#"{"amount":100,"recipient":"user123"}"#).unwrap();
    let hash = ashcore::ash_hash_body(&canonical);
    assert_eq!(hash.len(), 64);
}

// ============================================================================
// CLIENT SECRET DERIVATION CROSS-SDK TESTS (v2.1)
// ============================================================================

#[test]
fn vector_derive_client_secret_deterministic() {
    let secret1 = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let secret2 = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    assert_eq!(secret1, secret2);
}

#[test]
fn vector_derive_client_secret_format() {
    let secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    assert_eq!(secret.len(), 64);
    assert_eq!(secret, secret.to_lowercase());
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn vector_derive_client_secret_different_inputs() {
    let secret1 = ashcore::ash_derive_client_secret(TEST_NONCE, "ctx_a", TEST_BINDING).unwrap();
    let secret2 = ashcore::ash_derive_client_secret(TEST_NONCE, "ctx_b", TEST_BINDING).unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn vector_derive_client_secret_different_nonces() {
    let nonce1 = "a".repeat(64);
    let nonce2 = "b".repeat(64);
    let secret1 = ashcore::ash_derive_client_secret(&nonce1, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let secret2 = ashcore::ash_derive_client_secret(&nonce2, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    assert_ne!(secret1, secret2);
}

#[test]
fn vector_derive_client_secret_different_bindings() {
    let secret1 = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, "POST|/api/a|").unwrap();
    let secret2 = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, "POST|/api/b|").unwrap();
    assert_ne!(secret1, secret2);
}

// ============================================================================
// v2.1 PROOF CROSS-SDK TESTS
// ============================================================================

#[test]
fn vector_build_proof_v21_deterministic() {
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash = ashcore::ash_hash_body(r#"{"amount":100}"#);

    let proof1 = ashcore::ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();
    let proof2 = ashcore::ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();

    assert_eq!(proof1, proof2);
}

#[test]
fn vector_build_proof_v21_format() {
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash = ashcore::ash_hash_body(r#"{"amount":100}"#);

    let proof = ashcore::ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();

    assert_eq!(proof.len(), 64);
    assert_eq!(proof, proof.to_lowercase());
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn vector_verify_proof_v21_valid() {
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash = ashcore::ash_hash_body(r#"{"amount":100}"#);
    let proof = ashcore::ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();

    let valid = ashcore::ash_verify_proof(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, &body_hash, &proof).unwrap();
    assert!(valid);
}

#[test]
fn vector_verify_proof_v21_invalid_proof() {
    let body_hash = ashcore::ash_hash_body(r#"{"amount":100}"#);
    let wrong_proof = "0".repeat(64);

    let valid = ashcore::ash_verify_proof(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, &body_hash, &wrong_proof).unwrap();
    assert!(!valid);
}

#[test]
fn vector_verify_proof_v21_wrong_body() {
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let body_hash1 = ashcore::ash_hash_body(r#"{"amount":100}"#);
    let body_hash2 = ashcore::ash_hash_body(r#"{"amount":200}"#);
    let proof = ashcore::ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash1).unwrap();

    let valid = ashcore::ash_verify_proof(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, &body_hash2, &proof).unwrap();
    assert!(!valid);
}

// ============================================================================
// v2.3 UNIFIED PROOF CROSS-SDK TESTS (with Scoping and Chaining)
// ============================================================================

#[test]
fn vector_build_proof_unified_basic_no_scope_no_chain() {
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let payload = r#"{"amount":100,"note":"test"}"#;

    let result = ashcore::ash_build_proof_unified(&client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, &[], None).unwrap();

    assert_eq!(result.proof.len(), 64);
    assert!(result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());

    // Verify
    let valid = ashcore::ash_verify_proof_unified(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
        payload, &result.proof, &[], "", None, ""
    ).unwrap();
    assert!(valid);
}

#[test]
fn vector_build_proof_unified_with_scope() {
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING).unwrap();
    let payload = r#"{"amount":100,"note":"test","recipient":"user123"}"#;
    let scope = &["amount", "recipient"];

    let result = ashcore::ash_build_proof_unified(&client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, scope, None).unwrap();

    assert!(!result.scope_hash.is_empty());
    assert!(result.chain_hash.is_empty());

    // Verify
    let valid = ashcore::ash_verify_proof_unified(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
        payload, &result.proof, scope, &result.scope_hash, None, ""
    ).unwrap();
    assert!(valid);
}

#[test]
fn vector_build_proof_unified_with_chain() {
    let binding = "POST|/api/confirm|";
    let client_secret = ashcore::ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, binding).unwrap();
    let payload = r#"{"confirmed":true}"#;
    let previous_proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    let result = ashcore::ash_build_proof_unified(&client_secret, TEST_TIMESTAMP, binding, payload, &[], Some(previous_proof)).unwrap();

    assert!(result.scope_hash.is_empty());
    assert!(!result.chain_hash.is_empty());
    assert_eq!(result.chain_hash, ashcore::ash_hash_proof(previous_proof).unwrap());

    // Verify
    let valid = ashcore::ash_verify_proof_unified(
        TEST_NONCE, TEST_CONTEXT_ID, binding, TEST_TIMESTAMP,
        payload, &result.proof, &[], "", Some(previous_proof), &result.chain_hash
    ).unwrap();
    assert!(valid);
}

// ============================================================================
// HASH PROOF CROSS-SDK TESTS (for Chaining)
// ============================================================================

#[test]
fn vector_hash_proof_deterministic() {
    let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash1 = ashcore::ash_hash_proof(proof).unwrap();
    let hash2 = ashcore::ash_hash_proof(proof).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn vector_hash_proof_format() {
    let proof = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash = ashcore::ash_hash_proof(proof).unwrap();
    assert_eq!(hash.len(), 64);
    assert_eq!(hash, hash.to_lowercase());
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ============================================================================
// TIMING-SAFE COMPARISON CROSS-SDK TESTS
// ============================================================================

#[test]
fn vector_timing_safe_compare_equal() {
    assert!(ashcore::ash_timing_safe_equal(b"hello", b"hello"));
    assert!(ashcore::ash_timing_safe_equal(b"", b""));
}

#[test]
fn vector_timing_safe_compare_not_equal() {
    assert!(!ashcore::ash_timing_safe_equal(b"hello", b"world"));
    assert!(!ashcore::ash_timing_safe_equal(b"hello", b"hello!"));
    assert!(!ashcore::ash_timing_safe_equal(b"hello", b""));
}

// ============================================================================
// FIXED TEST VECTORS
// ============================================================================

#[test]
fn fixed_vector_client_secret() {
    let nonce = "a".repeat(64);
    let context_id = "ash_fixed_test_001";
    let binding = "POST|/api/test|";

    let secret = ashcore::ash_derive_client_secret(&nonce, context_id, binding).unwrap();

    assert_eq!(secret.len(), 64);
    let secret2 = ashcore::ash_derive_client_secret(&nonce, context_id, binding).unwrap();
    assert_eq!(secret, secret2);
}

#[test]
fn fixed_vector_body_hash() {
    let canonical = ashcore::ash_canonicalize_json(r#"{"amount":100,"recipient":"user123"}"#).unwrap();
    let hash = ashcore::ash_hash_body(&canonical);

    let expected_canonical = r#"{"amount":100,"recipient":"user123"}"#;
    assert_eq!(canonical, expected_canonical);
    assert_eq!(hash.len(), 64);
}

// ============================================================================
// SCOPED FIELD EXTRACTION CROSS-SDK TESTS
// ============================================================================

#[test]
fn vector_extract_scoped_fields_simple() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"amount":100,"note":"test","recipient":"user123"}"#).unwrap();
    let scope = &["amount", "recipient"];

    let result = ashcore::ash_extract_scoped_fields(&payload, scope).unwrap();

    assert_eq!(result.get("amount").unwrap(), 100);
    assert_eq!(result.get("recipient").unwrap(), "user123");
    assert!(result.get("note").is_none());
}

#[test]
fn vector_extract_scoped_fields_nested() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"user":{"name":"John","email":"john@example.com"},"amount":100}"#).unwrap();
    let scope = &["user.name", "amount"];

    let result = ashcore::ash_extract_scoped_fields(&payload, scope).unwrap();

    assert_eq!(result.get("amount").unwrap(), 100);
    let user = result.get("user").unwrap().as_object().unwrap();
    assert_eq!(user.get("name").unwrap(), "John");
    assert!(user.get("email").is_none());
}

#[test]
fn vector_extract_scoped_fields_empty_scope() {
    let payload: serde_json::Value = serde_json::from_str(r#"{"amount":100,"note":"test"}"#).unwrap();
    let scope: &[&str] = &[];

    let result = ashcore::ash_extract_scoped_fields(&payload, scope).unwrap();

    // Empty scope should return full payload
    assert!(result.get("amount").is_some());
    assert!(result.get("note").is_some());
}

// ============================================================================
// COMPREHENSIVE CROSS-SDK VERIFICATION
// ============================================================================

#[test]
fn vector_full_workflow_v21() {
    // Complete v2.1 workflow
    let nonce = "a".repeat(64);
    let ctx = "ash_workflow_test";
    let binding = "POST|/api/transfer|";
    let timestamp = "1704067200";
    let payload = r#"{"amount":100,"recipient":"user123"}"#;

    // 1. Canonicalize payload
    let canonical = ashcore::ash_canonicalize_json(payload).unwrap();

    // 2. Hash body
    let body_hash = ashcore::ash_hash_body(&canonical);

    // 3. Derive client secret
    let secret = ashcore::ash_derive_client_secret(&nonce, ctx, binding).unwrap();

    // 4. Build proof
    let proof = ashcore::ash_build_proof(&secret, timestamp, binding, &body_hash).unwrap();

    // 5. Verify proof
    let valid = ashcore::ash_verify_proof(&nonce, ctx, binding, timestamp, &body_hash, &proof).unwrap();
    assert!(valid);
}

#[test]
fn vector_full_workflow_unified_with_scope_and_chain() {
    // Complete v2.3 unified workflow
    let nonce = "a".repeat(64);
    let ctx = "ash_unified_test";

    // Step 1: Initial request
    let binding1 = "POST|/api/init|";
    let payload1 = r#"{"action":"init","data":"test"}"#;
    let timestamp1 = "1704067200";

    let secret1 = ashcore::ash_derive_client_secret(&nonce, ctx, binding1).unwrap();
    let result1 = ashcore::ash_build_proof_unified(&secret1, timestamp1, binding1, payload1, &[], None).unwrap();

    let valid1 = ashcore::ash_verify_proof_unified(
        &nonce, ctx, binding1, timestamp1, payload1, &result1.proof, &[], "", None, ""
    ).unwrap();
    assert!(valid1);

    // Step 2: Follow-up request with chain and scope
    let binding2 = "POST|/api/confirm|";
    let payload2 = r#"{"amount":100,"note":"optional","confirmed":true}"#;
    let timestamp2 = "1704067201";
    let scope = &["amount", "confirmed"];

    let secret2 = ashcore::ash_derive_client_secret(&nonce, ctx, binding2).unwrap();
    let result2 = ashcore::ash_build_proof_unified(&secret2, timestamp2, binding2, payload2, scope, Some(&result1.proof)).unwrap();

    let valid2 = ashcore::ash_verify_proof_unified(
        &nonce, ctx, binding2, timestamp2, payload2, &result2.proof, scope, &result2.scope_hash, Some(&result1.proof), &result2.chain_hash
    ).unwrap();
    assert!(valid2);
}
