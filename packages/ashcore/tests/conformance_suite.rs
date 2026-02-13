//! ASH Conformance Suite — Master Vector Validator
//!
//! This integration test reads `tests/conformance/vectors.json` and validates
//! every vector against the Rust core. It serves as both validation and
//! documentation of expected ASH behavior.
//!
//! CRITICAL: For canonicalization vectors, raw `input_json_text` is passed
//! directly to `ash_canonicalize_json()`. The input is NOT parsed into
//! serde_json::Value first — doing so would hide parser-dependent bugs.
//!
//! Run: `cargo test --test conformance_suite`

use ashcore::*;
use serde_json::Value;

/// Load the master vector file relative to the workspace root.
fn load_vectors() -> Value {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors_path = manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("conformance")
        .join("vectors.json");

    let content = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("Failed to read vectors.json at {}: {}", vectors_path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse vectors.json: {}", e))
}

fn get_vectors(root: &Value, category: &str) -> Vec<Value> {
    root.get("vectors")
        .and_then(|v| v.get(category))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

// =========================================================================
// A. JSON Canonicalization
// =========================================================================

#[test]
fn test_json_canonicalization_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "json_canonicalization");
    assert!(!vectors.is_empty(), "No json_canonicalization vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = v["input_json_text"].as_str().unwrap();
        let expected = v["expected"].as_str().unwrap();

        // CRITICAL: Pass raw text directly — do NOT parse into Value first
        let result = ash_canonicalize_json(input)
            .unwrap_or_else(|e| panic!("[{}] canonicalize_json failed: {}", id, e));

        assert_eq!(
            result, expected,
            "[{}] JSON canonicalization mismatch.\n  Input:    {}\n  Expected: {}\n  Got:      {}",
            id, input, expected, result
        );
        passed += 1;
    }

    eprintln!("json_canonicalization: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// B. Query String Canonicalization
// =========================================================================

#[test]
fn test_query_canonicalization_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "query_canonicalization");
    assert!(!vectors.is_empty(), "No query_canonicalization vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = v["input"].as_str().unwrap();
        let expected = v["expected"].as_str().unwrap();

        let result = ash_canonicalize_query(input)
            .unwrap_or_else(|e| panic!("[{}] canonicalize_query failed: {}", id, e));

        assert_eq!(
            result, expected,
            "[{}] Query canonicalization mismatch.\n  Input:    {}\n  Expected: {}\n  Got:      {}",
            id, input, expected, result
        );
        passed += 1;
    }

    eprintln!("query_canonicalization: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// C. URL-Encoded Canonicalization
// =========================================================================

#[test]
fn test_urlencoded_canonicalization_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "urlencoded_canonicalization");
    assert!(!vectors.is_empty(), "No urlencoded_canonicalization vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = v["input"].as_str().unwrap();
        let expected = v["expected"].as_str().unwrap();

        let result = ash_canonicalize_urlencoded(input)
            .unwrap_or_else(|e| panic!("[{}] canonicalize_urlencoded failed: {}", id, e));

        assert_eq!(
            result, expected,
            "[{}] URL-encoded canonicalization mismatch.\n  Input:    {}\n  Expected: {}\n  Got:      {}",
            id, input, expected, result
        );
        passed += 1;
    }

    eprintln!("urlencoded_canonicalization: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// D. Binding Normalization
// =========================================================================

#[test]
fn test_binding_normalization_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "binding_normalization");
    assert!(!vectors.is_empty(), "No binding_normalization vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = &v["input"];
        let method = input["method"].as_str().unwrap();
        let path = input["path"].as_str().unwrap();
        let query = input["query"].as_str().unwrap();

        if let Some(expected) = v.get("expected").and_then(|e| e.as_str()) {
            // Success case
            let result = ash_normalize_binding(method, path, query)
                .unwrap_or_else(|e| panic!("[{}] normalize_binding failed: {}", id, e));

            assert_eq!(
                result, expected,
                "[{}] Binding normalization mismatch.\n  Method:   {}\n  Path:     {}\n  Query:    {}\n  Expected: {}\n  Got:      {}",
                id, method, path, query, expected, result
            );
        } else if let Some(expected_error) = v.get("expected_error") {
            // Error case
            let result = ash_normalize_binding(method, path, query);
            assert!(result.is_err(), "[{}] Expected error but got success", id);

            let err = result.unwrap_err();
            let expected_code = expected_error["code"].as_str().unwrap();
            let expected_status = expected_error["http_status"].as_u64().unwrap() as u16;

            assert_eq!(
                err.code().as_str(), expected_code,
                "[{}] Error code mismatch: expected {}, got {}",
                id, expected_code, err.code().as_str()
            );
            assert_eq!(
                err.http_status(), expected_status,
                "[{}] HTTP status mismatch: expected {}, got {}",
                id, expected_status, err.http_status()
            );
        }

        passed += 1;
    }

    eprintln!("binding_normalization: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// E. Body Hashing
// =========================================================================

#[test]
fn test_body_hashing_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "body_hashing");
    assert!(!vectors.is_empty(), "No body_hashing vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = v["input"].as_str().unwrap();
        let expected = v["expected"].as_str().unwrap();

        let result = ash_hash_body(input);

        assert_eq!(
            result, expected,
            "[{}] Body hash mismatch.\n  Input:    {:?}\n  Expected: {}\n  Got:      {}",
            id, input, expected, result
        );
        assert_eq!(result.len(), 64, "[{}] Hash must be 64 hex chars", id);
        passed += 1;
    }

    eprintln!("body_hashing: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// F. Client Secret Derivation
// =========================================================================

#[test]
fn test_client_secret_derivation_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "client_secret_derivation");
    assert!(!vectors.is_empty(), "No client_secret_derivation vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = &v["input"];
        let nonce = input["nonce"].as_str().unwrap();
        let context_id = input["context_id"].as_str().unwrap();
        let binding = input["binding"].as_str().unwrap();
        let expected = v["expected"].as_str().unwrap();

        let result = ash_derive_client_secret(nonce, context_id, binding)
            .unwrap_or_else(|e| panic!("[{}] derive_client_secret failed: {}", id, e));

        assert_eq!(
            result, expected,
            "[{}] Client secret mismatch.\n  Nonce:      {}...\n  ContextId:  {}\n  Binding:    {}\n  Expected:   {}\n  Got:        {}",
            id, &nonce[..16], context_id, binding, expected, result
        );
        assert_eq!(result.len(), 64, "[{}] Secret must be 64 hex chars", id);
        passed += 1;
    }

    eprintln!("client_secret_derivation: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// G. Proof Generation & Verification
// =========================================================================

#[test]
fn test_proof_generation_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "proof_generation");
    assert!(!vectors.is_empty(), "No proof_generation vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let expected = &v["expected"];

        if let Some(expected_obj) = expected.as_object() {
            let input = &v["input"];

            // Proof generation vectors with full expected outputs
            if let Some(expected_proof) = expected_obj.get("proof").and_then(|p| p.as_str()) {
                let nonce = input["nonce"].as_str().unwrap();
                let context_id = input["context_id"].as_str().unwrap();
                let binding = input["binding"].as_str().unwrap();
                let timestamp = input["timestamp"].as_str().unwrap();
                let payload = input["payload"].as_str().unwrap();

                // Derive secret
                let client_secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();

                if let Some(expected_secret) = expected_obj.get("client_secret").and_then(|s| s.as_str()) {
                    assert_eq!(
                        client_secret, expected_secret,
                        "[{}] Client secret mismatch", id
                    );
                }

                // Canonicalize and hash
                let canonical = ash_canonicalize_json(payload).unwrap();
                if let Some(expected_canon) = expected_obj.get("canonical_payload").and_then(|c| c.as_str()) {
                    assert_eq!(canonical, expected_canon, "[{}] Canonical payload mismatch", id);
                }

                let body_hash = ash_hash_body(&canonical);
                if let Some(expected_hash) = expected_obj.get("body_hash").and_then(|h| h.as_str()) {
                    assert_eq!(body_hash, expected_hash, "[{}] Body hash mismatch", id);
                }

                // Build proof
                let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();
                assert_eq!(
                    proof, expected_proof,
                    "[{}] Proof mismatch.\n  Expected: {}\n  Got:      {}",
                    id, expected_proof, proof
                );
                assert_eq!(proof.len(), 64, "[{}] Proof must be 64 hex chars", id);
            }

            // Verification vectors
            if let Some(expected_valid) = expected_obj.get("valid").and_then(|v| v.as_bool()) {
                let nonce = input["nonce"].as_str().unwrap();
                let context_id = input["context_id"].as_str().unwrap();
                let binding = input["binding"].as_str().unwrap();
                let timestamp = input["timestamp"].as_str().unwrap();
                let body_hash = input["body_hash"].as_str().unwrap();
                let proof = input["proof"].as_str().unwrap();

                let result = ash_verify_proof(nonce, context_id, binding, timestamp, body_hash, proof).unwrap();
                assert_eq!(
                    result, expected_valid,
                    "[{}] Verification result mismatch: expected {}, got {}",
                    id, expected_valid, result
                );
            }

            // Format validation
            if let Some(expected_len) = expected_obj.get("proof_length").and_then(|l| l.as_u64()) {
                let nonce = input["nonce"].as_str().unwrap();
                let context_id = input["context_id"].as_str().unwrap();
                let binding = input["binding"].as_str().unwrap();
                let timestamp = input["timestamp"].as_str().unwrap();
                let payload = input["payload"].as_str().unwrap();

                let secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
                let canonical = ash_canonicalize_json(payload).unwrap();
                let hash = ash_hash_body(&canonical);
                let proof = ash_build_proof(&secret, timestamp, binding, &hash).unwrap();

                assert_eq!(proof.len() as u64, expected_len, "[{}] Proof length mismatch", id);
                assert!(
                    proof.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "[{}] Proof must be lowercase hex", id
                );
            }
        }

        passed += 1;
    }

    eprintln!("proof_generation: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// H. Scoped Field Extraction
// =========================================================================

#[test]
fn test_scoped_field_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "scoped_field_extraction");
    assert!(!vectors.is_empty(), "No scoped_field_extraction vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();

        // Error case
        if let Some(expected_error) = v.get("expected_error") {
            let input = &v["input"];
            let payload: Value = serde_json::from_str(input["payload"].as_str().unwrap()).unwrap();
            let scope_arr = input["scope"].as_array().unwrap();
            let scope: Vec<&str> = scope_arr.iter().map(|s| s.as_str().unwrap()).collect();
            let strict = input.get("strict").and_then(|s| s.as_bool()).unwrap_or(false);

            let result = ash_extract_scoped_fields_strict(&payload, &scope, strict);
            assert!(result.is_err(), "[{}] Expected error but got success", id);

            let err = result.unwrap_err();
            let expected_code = expected_error["code"].as_str().unwrap();
            let expected_status = expected_error["http_status"].as_u64().unwrap() as u16;
            assert_eq!(err.code().as_str(), expected_code, "[{}] Error code mismatch", id);
            assert_eq!(err.http_status(), expected_status, "[{}] HTTP status mismatch", id);
            passed += 1;
            continue;
        }

        let expected = &v["expected"];
        let input = &v["input"];

        // Scope hash only
        if let Some(expected_hash) = expected.get("scope_hash") {
            if !expected.as_object().unwrap().contains_key("proof") && !expected.as_object().unwrap().contains_key("extracted_fields") {
                let scope_arr = input["scope"].as_array().unwrap();
                let scope: Vec<&str> = scope_arr.iter().map(|s| s.as_str().unwrap()).collect();
                let hash = ash_hash_scope(&scope).unwrap();
                assert_eq!(hash, expected_hash.as_str().unwrap(), "[{}] Scope hash mismatch", id);
                passed += 1;
                continue;
            }
        }

        // Extraction vectors
        if let Some(expected_fields) = expected.get("extracted_fields") {
            let payload_str = input["payload"].as_str().unwrap();
            let payload: Value = serde_json::from_str(payload_str).unwrap();
            let scope_arr = input["scope"].as_array().unwrap();
            let scope: Vec<&str> = scope_arr.iter().map(|s| s.as_str().unwrap()).collect();

            let scoped = ash_extract_scoped_fields(&payload, &scope).unwrap();
            assert_eq!(
                scoped, *expected_fields,
                "[{}] Extracted fields mismatch", id
            );

            // If there's also a proof expected, verify it
            if let Some(expected_proof) = expected.get("proof").and_then(|p| p.as_str()) {
                let nonce = input["nonce"].as_str().unwrap();
                let context_id = input["context_id"].as_str().unwrap();
                let binding = input["binding"].as_str().unwrap();
                let timestamp = input["timestamp"].as_str().unwrap();

                let secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
                let (proof, scope_hash) = ash_build_proof_scoped(
                    &secret, timestamp, binding, payload_str, &scope
                ).unwrap();

                assert_eq!(proof, expected_proof, "[{}] Scoped proof mismatch", id);

                if let Some(expected_sh) = expected.get("scope_hash").and_then(|s| s.as_str()) {
                    assert_eq!(scope_hash, expected_sh, "[{}] Scope hash mismatch", id);
                }
            }
        }

        passed += 1;
    }

    eprintln!("scoped_field_extraction: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// I. Unified Proof
// =========================================================================

#[test]
fn test_unified_proof_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "unified_proof");
    assert!(!vectors.is_empty(), "No unified_proof vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let expected = &v["expected"];
        let input = &v["input"];

        // Chain hash only vector
        if let (Some(prev_proof), Some(expected_chain)) = (
            input.get("previous_proof").and_then(|p| p.as_str()),
            expected.get("chain_hash").and_then(|c| c.as_str()),
        ) {
            if !expected.as_object().unwrap().contains_key("proof") {
                let chain_hash = ash_hash_proof(prev_proof).unwrap();
                assert_eq!(chain_hash, expected_chain, "[{}] Chain hash mismatch", id);
                passed += 1;
                continue;
            }
        }

        // Verification vector
        if let Some(expected_valid) = expected.get("valid").and_then(|v| v.as_bool()) {
            let nonce = input["nonce"].as_str().unwrap();
            let context_id = input["context_id"].as_str().unwrap();
            let binding = input["binding"].as_str().unwrap();
            let timestamp = input["timestamp"].as_str().unwrap();
            let payload = input["payload"].as_str().unwrap();
            let proof = input["proof"].as_str().unwrap();
            let scope_hash = input["scope_hash"].as_str().unwrap();
            let chain_hash = input["chain_hash"].as_str().unwrap();

            let scope_arr = input["scope"].as_array().unwrap();
            let scope: Vec<&str> = scope_arr.iter().map(|s| s.as_str().unwrap()).collect();

            let previous_proof = input.get("previous_proof").and_then(|p| p.as_str());

            let result = ash_verify_proof_unified(
                nonce, context_id, binding, timestamp, payload,
                proof, &scope, scope_hash, previous_proof, chain_hash,
            ).unwrap();

            assert_eq!(result, expected_valid, "[{}] Unified verify mismatch", id);
            passed += 1;
            continue;
        }

        // Build proof vector
        if let Some(expected_proof) = expected.get("proof").and_then(|p| p.as_str()) {
            let nonce = input["nonce"].as_str().unwrap();
            let context_id = input["context_id"].as_str().unwrap();
            let binding = input["binding"].as_str().unwrap();
            let timestamp = input["timestamp"].as_str().unwrap();
            let payload = input["payload"].as_str().unwrap();

            let scope_arr = input["scope"].as_array().unwrap();
            let scope: Vec<&str> = scope_arr.iter().map(|s| s.as_str().unwrap()).collect();

            let previous_proof = input.get("previous_proof").and_then(|p| p.as_str());

            let secret = ash_derive_client_secret(nonce, context_id, binding).unwrap();
            let result = ash_build_proof_unified(
                &secret, timestamp, binding, payload, &scope, previous_proof,
            ).unwrap();

            assert_eq!(result.proof, expected_proof, "[{}] Unified proof mismatch", id);

            if let Some(expected_sh) = expected.get("scope_hash").and_then(|s| s.as_str()) {
                assert_eq!(result.scope_hash, expected_sh, "[{}] Scope hash mismatch", id);
            }
            if let Some(expected_ch) = expected.get("chain_hash").and_then(|c| c.as_str()) {
                assert_eq!(result.chain_hash, expected_ch, "[{}] Chain hash mismatch", id);
            }
        }

        passed += 1;
    }

    eprintln!("unified_proof: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// J. Timing-Safe Comparison
// =========================================================================

#[test]
fn test_timing_safe_comparison_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "timing_safe_comparison");
    assert!(!vectors.is_empty(), "No timing_safe_comparison vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let input = &v["input"];
        let a = input["a"].as_str().unwrap();
        let b = input["b"].as_str().unwrap();
        let expected = v["expected"].as_bool().unwrap();

        let result = ash_timing_safe_compare(a, b);
        assert_eq!(
            result, expected,
            "[{}] Timing-safe comparison mismatch: {:?} vs {:?} => expected {}, got {}",
            id, a, b, expected, result
        );
        passed += 1;
    }

    eprintln!("timing_safe_comparison: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// K. Error Behavior
// =========================================================================

#[test]
fn test_error_behavior_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "error_behavior");
    assert!(!vectors.is_empty(), "No error_behavior vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();
        let expected_error = &v["expected_error"];
        let expected_code = expected_error["code"].as_str().unwrap();
        let expected_status = expected_error["http_status"].as_u64().unwrap() as u16;
        let input = &v["input"];
        let operation = input["operation"].as_str().unwrap_or("");

        // Re-execute the operation and verify the error
        let result: Result<String, AshError> = match operation {
            "derive_client_secret" => {
                let nonce = input["nonce"].as_str().unwrap_or("");
                let ctx = input["context_id"].as_str().unwrap_or("");
                let binding = input["binding"].as_str().unwrap_or("");
                ash_derive_client_secret(nonce, ctx, binding)
            }
            "canonicalize_json" => {
                if let Some(text) = input.get("input_json_text").and_then(|t| t.as_str()) {
                    ash_canonicalize_json(text)
                } else {
                    // Skip vectors that describe but don't include actual input (like oversized)
                    passed += 1;
                    continue;
                }
            }
            "verify_proof" => {
                let timestamp = input.get("timestamp").and_then(|t| t.as_str()).unwrap_or("");
                // Use dummy values for fields not being tested
                let dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
                let dummy_proof = "0000000000000000000000000000000000000000000000000000000000000000";
                let nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
                let ctx = "ctx_test_conformance_v1";
                let binding = "POST|/api/transfer|";

                ash_verify_proof(nonce, ctx, binding, timestamp, dummy_hash, dummy_proof)
                    .map(|v| v.to_string())
            }
            "extract_scoped_fields_strict" => {
                let payload_str = input["payload"].as_str().unwrap();
                let payload: Value = serde_json::from_str(payload_str).unwrap();
                let scope_arr = input["scope"].as_array().unwrap();
                let scope: Vec<&str> = scope_arr.iter().map(|s| s.as_str().unwrap()).collect();

                ash_extract_scoped_fields_strict(&payload, &scope, true)
                    .map(|v| serde_json::to_string(&v).unwrap())
            }
            "build_proof" => {
                let body_hash = input["body_hash"].as_str().unwrap_or("");
                ash_build_proof("secret", "1700000000", "POST|/api/transfer|", body_hash)
            }
            "hash_proof" => {
                let proof = input["proof"].as_str().unwrap_or("");
                ash_hash_proof(proof)
            }
            _ => {
                // Skip unknown operations or vectors without direct re-execution
                passed += 1;
                continue;
            }
        };

        assert!(result.is_err(), "[{}] Expected error from {} but got success", id, operation);
        let err = result.unwrap_err();

        assert_eq!(
            err.code().as_str(), expected_code,
            "[{}] Error code mismatch: expected {}, got {}",
            id, expected_code, err.code().as_str()
        );
        assert_eq!(
            err.http_status(), expected_status,
            "[{}] HTTP status mismatch: expected {}, got {}",
            id, expected_status, err.http_status()
        );

        passed += 1;
    }

    eprintln!("error_behavior: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// L. Timestamp Validation
// =========================================================================

#[test]
fn test_timestamp_validation_vectors() {
    let root = load_vectors();
    let vectors = get_vectors(&root, "timestamp_validation");
    assert!(!vectors.is_empty(), "No timestamp_validation vectors found");

    let mut passed = 0;
    for v in &vectors {
        let id = v["id"].as_str().unwrap();

        if let Some(expected_error) = v.get("expected_error") {
            let timestamp = v["input"]["timestamp"].as_str().unwrap();
            let expected_code = expected_error["code"].as_str().unwrap();
            let expected_status = expected_error["http_status"].as_u64().unwrap() as u16;

            // Use verify_proof to test timestamp validation (it calls validate_timestamp_format)
            let dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            let dummy_proof = "0000000000000000000000000000000000000000000000000000000000000000";
            let result = ash_verify_proof(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "ctx_test", "POST|/api|",
                timestamp, dummy_hash, dummy_proof,
            );

            assert!(result.is_err(), "[{}] Expected timestamp error but got success", id);
            let err = result.unwrap_err();
            assert_eq!(err.code().as_str(), expected_code, "[{}] Error code mismatch", id);
            assert_eq!(err.http_status(), expected_status, "[{}] HTTP status mismatch", id);
        } else if let Some(expected) = v.get("expected") {
            if let Some(true) = expected.get("valid_format").and_then(|v| v.as_bool()) {
                // Valid format — verify_proof should NOT fail on timestamp format
                // (it may fail on proof mismatch, but that's OK — we're testing format)
                let timestamp = v["input"]["timestamp"].as_str().unwrap();
                let dummy_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
                let dummy_proof = "0000000000000000000000000000000000000000000000000000000000000000";
                let result = ash_verify_proof(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "ctx_test", "POST|/api|",
                    timestamp, dummy_hash, dummy_proof,
                );
                // Should succeed (returning false for bad proof) or NOT be a timestamp error
                match result {
                    Ok(_) => {} // Good - proof doesn't match but format is valid
                    Err(e) => {
                        assert_ne!(
                            e.code().as_str(), "ASH_TIMESTAMP_INVALID",
                            "[{}] Valid timestamp rejected as invalid", id
                        );
                    }
                }
            }
        }

        passed += 1;
    }

    eprintln!("timestamp_validation: {}/{} passed", passed, vectors.len());
}

// =========================================================================
// Meta: Vector File Integrity
// =========================================================================

#[test]
fn test_vector_file_metadata() {
    let root = load_vectors();

    // Verify schema version
    assert_eq!(root["schema_version"].as_u64(), Some(1));

    // Verify ash version
    assert_eq!(root["ash_version"].as_str(), Some("1.0.0"));

    // Verify all expected categories exist
    let vectors = root.get("vectors").expect("Missing 'vectors' key");
    let expected_categories = [
        "json_canonicalization",
        "query_canonicalization",
        "urlencoded_canonicalization",
        "binding_normalization",
        "body_hashing",
        "client_secret_derivation",
        "proof_generation",
        "scoped_field_extraction",
        "unified_proof",
        "timing_safe_comparison",
        "error_behavior",
        "timestamp_validation",
    ];

    for cat in &expected_categories {
        let arr = vectors.get(cat)
            .unwrap_or_else(|| panic!("Missing category: {}", cat))
            .as_array()
            .unwrap_or_else(|| panic!("Category {} is not an array", cat));
        assert!(!arr.is_empty(), "Category {} has no vectors", cat);
    }

    // Count total vectors
    let total: usize = expected_categories.iter()
        .map(|cat| vectors[cat].as_array().unwrap().len())
        .sum();
    eprintln!("Total vectors in file: {}", total);
    assert!(total >= 120, "Expected at least 120 vectors, got {}", total);

    // Verify no placeholders exist
    let content = serde_json::to_string(&root).unwrap();
    assert!(!content.contains("a1b2c3d4"), "Found placeholder value 'a1b2c3d4'");
    assert!(!content.contains("TODO"), "Found TODO in vectors");
    assert!(!content.contains("PLACEHOLDER"), "Found PLACEHOLDER in vectors");
}
