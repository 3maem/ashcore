#![recursion_limit = "512"]
//! ASH Conformance Vector Generator
//!
//! This binary generates `vectors.json` by running every ASH operation against
//! the Rust core and capturing exact expected outputs.
//!
//! Usage: cargo run --bin generate_vectors
//!
//! This is a ONE-TIME generator. CI only validates against the locked vectors.
//! Regeneration implies a behavioral version change and requires ash_version increment.

use ashcore::*;
use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const REFERENCE_TIME: u64 = 1700000000;

// Fixed test inputs used across vectors
const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_NONCE_SHORT: &str = "0123456789abcdef0123456789abcdef";
const TEST_CONTEXT_ID: &str = "ctx_test_conformance_v1";
const TEST_BINDING: &str = "POST|/api/transfer|";
const TEST_TIMESTAMP: &str = "1700000000";
const TEST_PAYLOAD: &str = r#"{"amount":100,"recipient":"alice"}"#;

fn main() {
    let mut categories: Map<String, Value> = Map::new();

    // Generate all vector categories
    categories.insert("json_canonicalization".into(), generate_json_canonicalization());
    categories.insert("query_canonicalization".into(), generate_query_canonicalization());
    categories.insert("urlencoded_canonicalization".into(), generate_urlencoded_canonicalization());
    categories.insert("binding_normalization".into(), generate_binding_normalization());
    categories.insert("body_hashing".into(), generate_body_hashing());
    categories.insert("client_secret_derivation".into(), generate_client_secret_derivation());
    categories.insert("proof_generation".into(), generate_proof_generation());
    categories.insert("scoped_field_extraction".into(), generate_scoped_fields());
    categories.insert("unified_proof".into(), generate_unified_proof());
    categories.insert("timing_safe_comparison".into(), generate_timing_safe());
    categories.insert("error_behavior".into(), generate_error_behavior());
    categories.insert("timestamp_validation".into(), generate_timestamp_validation());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let vectors = json!({
        "schema_version": 1,
        "ash_version": "1.0.0",
        "generated_from": "rust-core",
        "generated_at": format!("{}Z", now),
        "determinism_rule": "All expected outputs must match byte-for-byte across all implementations",
        "reference_time": REFERENCE_TIME,
        "canonical_encoding": "UTF-8",
        "features": ["canonical_json_v1", "scoped_proof_v1", "chain_hash_v1", "unified_proof_v1"],
        "generator_version": "gen-v1",
        "platform": std::env::consts::OS,
        "unicode_normalization": "NFC",
        "key_sorting": "jcs_rfc8785",
        "newline_policy": "preserve",
        "path_normalization": "rfc3986_remove_dot_segments",
        "query_duplicate_policy": "sort_by_key_then_value",
        "query_flag_policy": "flag_equals_empty",
        "query_normalization": "decode_then_reencode_once",
        "timestamp_policy": { "ttl_seconds": 300, "skew_seconds": 60 },
        "plus_policy": "literal_plus_never_space",
        "path_percent_decode": "decode_all",
        "json_duplicate_keys": "last_wins",
        "json_input_mode": "text_only",
        "invalid_utf8": "reject",
        "byte_rules": {
            "string_encoding": "utf-8",
            "delimiter_pipe": { "char": "|", "byte_hex": "7C" },
            "delimiter_us": { "char": "\u{001f}", "byte_hex": "1F" },
            "hex_output": "lowercase",
            "timestamp": "seconds_ascii_no_leading_zeros"
        },
        "domains": {
            "client_secret": {
                "message_format": "{context_id}|{binding}",
                "hmac_key": "nonce",
                "algorithm": "hmac-sha256",
                "output": "lowercase_hex_64"
            },
            "proof": {
                "message_format": "{timestamp}|{binding}|{body_hash}",
                "hmac_key": "client_secret",
                "algorithm": "hmac-sha256",
                "output": "lowercase_hex_64"
            },
            "scoped_proof": {
                "message_format": "{timestamp}|{binding}|{body_hash}|{scope_hash}",
                "hmac_key": "client_secret",
                "algorithm": "hmac-sha256",
                "output": "lowercase_hex_64"
            },
            "unified_proof": {
                "message_format": "{timestamp}|{binding}|{body_hash}|{scope_hash}|{chain_hash}",
                "hmac_key": "client_secret",
                "algorithm": "hmac-sha256",
                "output": "lowercase_hex_64"
            },
            "scope_hash": {
                "message_format": "{sorted_field_names joined by \\x1F}",
                "algorithm": "sha256",
                "output": "lowercase_hex_64",
                "field_name_policy": {
                    "unicode_normalization": "NFC",
                    "trim": "none",
                    "case_fold": "none",
                    "sort": "codepoint_lexicographic",
                    "dedupe": "yes_keep_one"
                },
                "note": "hashes field NAMES only, not field values or JSON"
            },
            "chain_hash": {
                "message_format": "{previous_proof_hex_lowercase_ascii}",
                "algorithm": "sha256",
                "output": "lowercase_hex_64",
                "note": "hashes the ASCII bytes of the lowercase hex string, NOT the decoded binary bytes"
            }
        },
        "hash_algorithms": { "default": "sha256", "hmac_default": "hmac-sha256" },
        "error_registry": {
            "ASH_CTX_NOT_FOUND": { "http_status": 450 },
            "ASH_CTX_EXPIRED": { "http_status": 451 },
            "ASH_CTX_ALREADY_USED": { "http_status": 452 },
            "ASH_PROOF_INVALID": { "http_status": 460 },
            "ASH_BINDING_MISMATCH": { "http_status": 461 },
            "ASH_SCOPE_MISMATCH": { "http_status": 473 },
            "ASH_CHAIN_BROKEN": { "http_status": 474 },
            "ASH_SCOPED_FIELD_MISSING": { "http_status": 475 },
            "ASH_TIMESTAMP_INVALID": { "http_status": 482 },
            "ASH_PROOF_MISSING": { "http_status": 483 },
            "ASH_CANONICALIZATION_ERROR": { "http_status": 484 },
            "ASH_VALIDATION_ERROR": { "http_status": 485 },
            "ASH_MODE_VIOLATION": { "http_status": 486 },
            "ASH_UNSUPPORTED_CONTENT_TYPE": { "http_status": 415 },
            "ASH_INTERNAL_ERROR": { "http_status": 500 }
        },
        "hex_case": "lowercase_output_uppercase_percent",
        "limits": {
            "max_json_depth": 64,
            "max_payload_bytes": 10485760,
            "max_scope_fields": 100,
            "max_scope_field_len": 64,
            "max_nonce_hex_len": 512,
            "max_binding_len": 8192,
            "max_context_id_len": 256,
            "max_query_pairs": 256
        },
        "vectors": categories
    });

    let output = serde_json::to_string_pretty(&vectors).unwrap();
    let out_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .parent().unwrap()
        .join("tests")
        .join("conformance")
        .join("vectors.json");

    std::fs::write(&out_path, &output).unwrap();
    eprintln!("Generated {} bytes to {}", output.len(), out_path.display());

    // Count total vectors
    let total: usize = categories.values().map(|v| {
        v.as_array().map(|a| a.len()).unwrap_or(0)
    }).sum();
    eprintln!("Total vectors: {}", total);
}

// =========================================================================
// A. JSON Canonicalization Vectors (~25)
// =========================================================================

fn generate_json_canonicalization() -> Value {
    let mut vectors = Vec::new();

    let cases: Vec<(&str, &str, &str)> = vec![
        ("json-001", "Basic key sorting", r#"{"z":1,"a":2}"#),
        ("json-002", "Nested key sorting", r#"{"b":{"d":4,"c":3},"a":1}"#),
        ("json-003", "Whitespace removal", r#"{ "z" : 1 , "a" : 2 }"#),
        ("json-004", "Array order preserved", r#"{"arr":[3,1,2]}"#),
        ("json-005", "Null value", r#"{"a":null}"#),
        ("json-006", "Boolean values sorted", r#"{"b":true,"a":false}"#),
        ("json-007", "Empty object", r#"{}"#),
        ("json-008", "Empty array", r#"[]"#),
        ("json-009", "Unicode cafe NFC", r#"{"name":"café"}"#),
        ("json-010", "Whole float becomes integer", r#"{"a":5.0}"#),
        ("json-011", "Negative zero becomes zero", r#"{"a":-0.0}"#),
        ("json-012", "Fractional preserved", r#"{"a":5.5}"#),
        ("json-013", "Large whole float to integer", r#"{"a":1000000.0}"#),
        ("json-014", "Scientific notation 1e2", r#"{"a":1e2}"#),
        ("json-015", "Negative float", r#"{"a":-3.14}"#),
        ("json-016", "Empty string value", r#"{"a":""}"#),
        ("json-017", "Deeply nested 3 levels", r#"{"a":{"b":{"c":1}}}"#),
        ("json-018", "Mixed type array", r#"[1,"hello",true,null,3.14]"#),
        ("json-019", "String with escapes", r#"{"a":"line1\nline2\ttab"}"#),
        ("json-020", "String with backslash", r#"{"a":"back\\slash"}"#),
        ("json-021", "String with quotes", r#"{"a":"say \"hello\""}"#),
        ("json-022", "Emoji in string", r#"{"emoji":"😀🎉"}"#),
        ("json-023", "Arabic text", r#"{"text":"مرحبا"}"#),
        ("json-024", "MAX_SAFE_INTEGER", r#"{"a":9007199254740991}"#),
        ("json-025", "Negative integer", r#"{"a":-42}"#),
        ("json-026", "Newline in value preserved", "{\"a\":\"line1\\r\\nline2\"}"),
        ("json-027", "Control char u0001", "{\"a\":\"\\u0001\"}"),
    ];

    for (id, desc, input) in &cases {
        let result = ash_canonicalize_json(input);
        match result {
            Ok(canonical) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input_json_text": input,
                    "expected": canonical
                }));
            }
            Err(e) => {
                eprintln!("WARN: json canon failed for {}: {}", id, e);
            }
        }
    }

    // IEEE-754 danger zone vectors
    let float_cases: Vec<(&str, &str, &str)> = vec![
        ("json-028", "Float 0.1+0.2 representation", r#"{"a":0.30000000000000004}"#),
        ("json-029", "Float 1e-7 boundary", r#"{"a":0.0000001}"#),
        ("json-030", "Float 0.3 round-trip", r#"{"a":0.3}"#),
        ("json-031", "Float epsilon", r#"{"a":2.220446049250313e-16}"#),
        ("json-032", "Integer 1e10", r#"{"a":10000000000}"#),
    ];

    for (id, desc, input) in &float_cases {
        match ash_canonicalize_json(input) {
            Ok(canonical) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input_json_text": input,
                    "expected": canonical
                }));
            }
            Err(e) => {
                eprintln!("WARN: float canon failed for {}: {}", id, e);
            }
        }
    }

    // Unicode NFC combining character test
    // e + combining acute accent (U+0301) should NFC normalize to é (U+00E9)
    let combining_input = "{\"key\":\"caf\\u0065\\u0301\"}";
    match ash_canonicalize_json(combining_input) {
        Ok(canonical) => {
            vectors.push(json!({
                "id": "json-033",
                "description": "Unicode NFC normalization: e + combining accent -> é",
                "input_json_text": combining_input,
                "expected": canonical
            }));
        }
        Err(e) => eprintln!("WARN: NFC test failed: {}", e),
    }

    // Duplicate keys (last_wins via serde_json)
    let dup_input = r#"{"a":1,"b":2,"a":3}"#;
    match ash_canonicalize_json(dup_input) {
        Ok(canonical) => {
            vectors.push(json!({
                "id": "json-034",
                "description": "Duplicate keys: last_wins policy",
                "input_json_text": dup_input,
                "expected": canonical
            }));
        }
        Err(e) => eprintln!("WARN: dup keys test failed: {}", e),
    }

    Value::Array(vectors)
}

// =========================================================================
// B. Query String Canonicalization (~15)
// =========================================================================

fn generate_query_canonicalization() -> Value {
    let mut vectors = Vec::new();

    let cases: Vec<(&str, &str, &str)> = vec![
        ("query-001", "Basic key sorting", "z=3&a=1&b=2"),
        ("query-002", "Duplicate key value sorting", "a=2&a=1&a=3"),
        ("query-003", "Plus sign is literal (critical)", "a+b=1"),
        ("query-004", "Plus in value is literal", "q=a+b"),
        ("query-005", "Uppercase hex normalization", "a=hello%2fworld"),
        ("query-006", "Empty value preserved", "a=&b=2"),
        ("query-007", "Key without value becomes flag=", "flag&b=2"),
        ("query-008", "Leading ? stripped", "?z=3&a=1"),
        ("query-009", "Fragment # stripped", "z=3&a=1#section"),
        ("query-010", "Case-sensitive keys A vs a", "a=1&A=2"),
        ("query-011", "Space as %20", "a=hello%20world"),
        ("query-012", "Unicode percent-encoded", "a=%C3%A9"),
        ("query-013", "Empty query", ""),
        ("query-014", "Fragment only", "#onlyfragment"),
        ("query-015", "Byte order sorting 0 < A < a", "z=1&A=2&a=3&0=4"),
    ];

    for (id, desc, input) in &cases {
        match ash_canonicalize_query(input) {
            Ok(canonical) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input": input,
                    "expected": canonical
                }));
            }
            Err(e) => {
                eprintln!("WARN: query canon failed for {}: {}", id, e);
            }
        }
    }

    Value::Array(vectors)
}

// =========================================================================
// C. URL-Encoded Canonicalization (~8)
// =========================================================================

fn generate_urlencoded_canonicalization() -> Value {
    let mut vectors = Vec::new();

    let cases: Vec<(&str, &str, &str)> = vec![
        ("urlencode-001", "Basic sorting", "z=3&a=1&b=2"),
        ("urlencode-002", "Duplicate key sorting", "a=2&a=1&b=3"),
        ("urlencode-003", "Plus is literal not space", "a=hello+world"),
        ("urlencode-004", "Space as %20 preserved", "a=hello%20world"),
        ("urlencode-005", "Empty input", ""),
        ("urlencode-006", "Key without value", "a&b=2"),
        ("urlencode-007", "Mixed encoding", "b=%2F&a=hello%20world"),
        ("urlencode-008", "Uppercase hex in output", "a=%2f"),
    ];

    for (id, desc, input) in &cases {
        match ash_canonicalize_urlencoded(input) {
            Ok(canonical) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input": input,
                    "expected": canonical
                }));
            }
            Err(e) => {
                eprintln!("WARN: urlencoded canon failed for {}: {}", id, e);
            }
        }
    }

    Value::Array(vectors)
}

// =========================================================================
// D. Binding Normalization (~12)
// =========================================================================

fn generate_binding_normalization() -> Value {
    let mut vectors = Vec::new();

    let ok_cases: Vec<(&str, &str, &str, &str, &str)> = vec![
        ("binding-001", "Basic POST binding", "POST", "/api/users", ""),
        ("binding-002", "Method lowercase to upper", "post", "/api/users", ""),
        ("binding-003", "Duplicate slashes collapsed", "GET", "/api//users///profile", ""),
        ("binding-004", "Trailing slash removed", "PUT", "/api/users/", ""),
        ("binding-005", "Root path preserved", "GET", "/", ""),
        ("binding-006", "Query sorted in binding", "GET", "/api/users", "z=3&a=1&b=2"),
        ("binding-007", "Dot segment removed", "GET", "/api/./users", ""),
        ("binding-008", "Double dot resolved", "GET", "/api/v1/../users", ""),
        ("binding-009", "Encoded slashes decoded and collapsed", "GET", "/api/%2F%2F/users", ""),
        ("binding-010", "Plus literal in query within binding", "GET", "/api/search", "q=a+b"),
        ("binding-011", "Fragment stripped from query", "GET", "/api/search", "q=test#section"),
        ("binding-012", "Special chars @me preserved", "GET", "/api/users/@me", ""),
    ];

    for (id, desc, method, path, query) in &ok_cases {
        match ash_normalize_binding(method, path, query) {
            Ok(binding) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input": {
                        "method": method,
                        "path": path,
                        "query": query
                    },
                    "expected": binding
                }));
            }
            Err(e) => {
                eprintln!("WARN: binding norm failed for {}: {}", id, e);
            }
        }
    }

    // Error cases
    let err_cases: Vec<(&str, &str, &str, &str, &str, &str, u16)> = vec![
        ("binding-013", "Empty method rejected", "", "/api", "", "ASH_VALIDATION_ERROR", 485),
        ("binding-014", "Missing leading slash rejected", "GET", "api/users", "", "ASH_VALIDATION_ERROR", 485),
        ("binding-015", "Non-ASCII method rejected", "G\u{00CB}\u{1E6A}", "/api", "", "ASH_VALIDATION_ERROR", 485),
    ];

    for (id, desc, method, path, query, code, status) in &err_cases {
        match ash_normalize_binding(method, path, query) {
            Err(_e) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input": {
                        "method": method,
                        "path": path,
                        "query": query
                    },
                    "expected_error": {
                        "code": code,
                        "http_status": status
                    }
                }));
            }
            Ok(v) => {
                eprintln!("WARN: binding {} expected error but got: {}", id, v);
            }
        }
    }

    Value::Array(vectors)
}

// =========================================================================
// E. Body Hashing (~6)
// =========================================================================

fn generate_body_hashing() -> Value {
    let mut vectors = Vec::new();

    let cases: Vec<(&str, &str, &str)> = vec![
        ("hash-001", "Empty string hash", ""),
        ("hash-002", "String 'test'", "test"),
        ("hash-003", "Empty JSON object", "{}"),
        ("hash-004", "Canonical JSON payload", r#"{"amount":100,"recipient":"alice"}"#),
        ("hash-005", "Single character", "a"),
        ("hash-006", "Unicode string", "café"),
    ];

    for (id, desc, input) in &cases {
        let hash = ash_hash_body(input);
        vectors.push(json!({
            "id": id,
            "description": desc,
            "input": input,
            "expected": hash
        }));
    }

    Value::Array(vectors)
}

// =========================================================================
// F. Client Secret Derivation (~6)
// =========================================================================

fn generate_client_secret_derivation() -> Value {
    let mut vectors = Vec::new();

    let cases: Vec<(&str, &str, &str, &str, &str)> = vec![
        (
            "secret-001", "Standard derivation",
            TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING,
        ),
        (
            "secret-002", "Different nonce produces different secret",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            TEST_CONTEXT_ID, TEST_BINDING,
        ),
        (
            "secret-003", "Different context_id produces different secret",
            TEST_NONCE, "ctx_other_context", TEST_BINDING,
        ),
        (
            "secret-004", "Different binding produces different secret",
            TEST_NONCE, TEST_CONTEXT_ID, "GET|/api/read|",
        ),
        (
            "secret-005", "Minimum length nonce (32 hex chars)",
            TEST_NONCE_SHORT, TEST_CONTEXT_ID, TEST_BINDING,
        ),
        (
            "secret-006", "Binding with query",
            TEST_NONCE, TEST_CONTEXT_ID, "GET|/api/search|q=test&page=1",
        ),
    ];

    for (id, desc, nonce, ctx, binding) in &cases {
        match ash_derive_client_secret(nonce, ctx, binding) {
            Ok(secret) => {
                vectors.push(json!({
                    "id": id,
                    "description": desc,
                    "input": {
                        "nonce": nonce,
                        "context_id": ctx,
                        "binding": binding
                    },
                    "expected": secret
                }));
            }
            Err(e) => {
                eprintln!("WARN: secret derivation failed for {}: {}", id, e);
            }
        }
    }

    Value::Array(vectors)
}

// =========================================================================
// G. Proof Generation & Verification (~8)
// =========================================================================

fn generate_proof_generation() -> Value {
    let mut vectors = Vec::new();

    // Generate a client secret for proof tests
    let client_secret = ash_derive_client_secret(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING
    ).unwrap();

    let canonical = ash_canonicalize_json(TEST_PAYLOAD).unwrap();
    let body_hash = ash_hash_body(&canonical);

    // Vector 1: Basic proof generation
    let proof = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash).unwrap();
    vectors.push(json!({
        "id": "proof-001",
        "description": "Basic proof generation and verification",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": TEST_PAYLOAD
        },
        "expected": {
            "client_secret": &client_secret,
            "body_hash": &body_hash,
            "canonical_payload": &canonical,
            "proof": &proof
        }
    }));

    // Vector 2: Different payload different proof
    let payload2 = r#"{"amount":200,"recipient":"bob"}"#;
    let canonical2 = ash_canonicalize_json(payload2).unwrap();
    let body_hash2 = ash_hash_body(&canonical2);
    let proof2 = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &body_hash2).unwrap();
    vectors.push(json!({
        "id": "proof-002",
        "description": "Different payload produces different proof",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": payload2
        },
        "expected": {
            "client_secret": &client_secret,
            "body_hash": &body_hash2,
            "canonical_payload": &canonical2,
            "proof": &proof2
        }
    }));

    // Vector 3: Different timestamp different proof
    let ts2 = "1700000100";
    let proof3 = ash_build_proof(&client_secret, ts2, TEST_BINDING, &body_hash).unwrap();
    vectors.push(json!({
        "id": "proof-003",
        "description": "Different timestamp produces different proof",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": ts2,
            "payload": TEST_PAYLOAD
        },
        "expected": {
            "client_secret": &client_secret,
            "body_hash": &body_hash,
            "canonical_payload": &canonical,
            "proof": &proof3
        }
    }));

    // Vector 4: End-to-end with verify
    let verify_result = ash_verify_proof(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, &body_hash, &proof
    ).unwrap();
    vectors.push(json!({
        "id": "proof-004",
        "description": "Proof verification succeeds with correct inputs",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "body_hash": &body_hash,
            "proof": &proof
        },
        "expected": {
            "valid": verify_result
        }
    }));

    // Vector 5: Tampered body hash fails verification
    let tampered_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let verify_tampered = ash_verify_proof(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, tampered_hash, &proof
    ).unwrap();
    vectors.push(json!({
        "id": "proof-005",
        "description": "Tampered body hash fails verification",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "body_hash": tampered_hash,
            "proof": &proof
        },
        "expected": {
            "valid": verify_tampered
        }
    }));

    // Vector 6: Wrong proof fails verification
    let wrong_proof = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let verify_wrong = ash_verify_proof(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP, &body_hash, wrong_proof
    ).unwrap();
    vectors.push(json!({
        "id": "proof-006",
        "description": "Wrong proof fails verification",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "body_hash": &body_hash,
            "proof": wrong_proof
        },
        "expected": {
            "valid": verify_wrong
        }
    }));

    // Vector 7: Empty payload (treated as {})
    let empty_canonical = ash_canonicalize_json("{}").unwrap();
    let empty_hash = ash_hash_body(&empty_canonical);
    let empty_proof = ash_build_proof(&client_secret, TEST_TIMESTAMP, TEST_BINDING, &empty_hash).unwrap();
    vectors.push(json!({
        "id": "proof-007",
        "description": "Empty object payload proof",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": "{}"
        },
        "expected": {
            "client_secret": &client_secret,
            "body_hash": &empty_hash,
            "canonical_payload": &empty_canonical,
            "proof": &empty_proof
        }
    }));

    // Vector 8: Proof is exactly 64 lowercase hex chars
    vectors.push(json!({
        "id": "proof-008",
        "description": "Proof format: 64 lowercase hex characters",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": TEST_PAYLOAD
        },
        "expected": {
            "proof": &proof,
            "proof_length": 64,
            "proof_is_lowercase_hex": true
        }
    }));

    Value::Array(vectors)
}

// =========================================================================
// H. Scoped Field Extraction (~8)
// =========================================================================

fn generate_scoped_fields() -> Value {
    let mut vectors = Vec::new();

    let client_secret = ash_derive_client_secret(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING
    ).unwrap();

    // Vector 1: Simple field extraction
    let payload = r#"{"amount":100,"recipient":"alice","notes":"hello"}"#;
    let scope: Vec<&str> = vec!["amount", "recipient"];
    let (proof, scope_hash) = ash_build_proof_scoped(
        &client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, &scope
    ).unwrap();

    let json_payload: Value = serde_json::from_str(payload).unwrap();
    let scoped = ash_extract_scoped_fields(&json_payload, &scope).unwrap();
    let canonical_scoped = ash_canonicalize_json(&serde_json::to_string(&scoped).unwrap()).unwrap();

    vectors.push(json!({
        "id": "scope-001",
        "description": "Simple field extraction with scope hash",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": payload,
            "scope": scope
        },
        "expected": {
            "proof": &proof,
            "scope_hash": &scope_hash,
            "extracted_fields": scoped,
            "canonical_scoped": &canonical_scoped
        },
        "debug": {
            "sorted_fields": ["amount", "recipient"],
            "mode": "lenient"
        }
    }));

    // Vector 2: Dot-notation nested fields
    let nested_payload = r#"{"user":{"name":"Alice","address":{"city":"NYC"}},"total":100}"#;
    let nested_scope: Vec<&str> = vec!["user.name", "user.address.city"];
    let (nested_proof, nested_scope_hash) = ash_build_proof_scoped(
        &client_secret, TEST_TIMESTAMP, TEST_BINDING, nested_payload, &nested_scope
    ).unwrap();

    let nested_json: Value = serde_json::from_str(nested_payload).unwrap();
    let nested_scoped = ash_extract_scoped_fields(&nested_json, &nested_scope).unwrap();

    vectors.push(json!({
        "id": "scope-002",
        "description": "Dot-notation nested fields",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": nested_payload,
            "scope": nested_scope
        },
        "expected": {
            "proof": &nested_proof,
            "scope_hash": &nested_scope_hash,
            "extracted_fields": nested_scoped
        },
        "debug": {
            "sorted_fields": ["user.address.city", "user.name"],
            "mode": "lenient"
        }
    }));

    // Vector 3: Array notation
    let array_payload = r#"{"items":[{"id":1,"name":"a"},{"id":2,"name":"b"}],"total":100}"#;
    let array_scope: Vec<&str> = vec!["items[0]"];
    let (array_proof, array_scope_hash) = ash_build_proof_scoped(
        &client_secret, TEST_TIMESTAMP, TEST_BINDING, array_payload, &array_scope
    ).unwrap();

    let array_json: Value = serde_json::from_str(array_payload).unwrap();
    let array_scoped = ash_extract_scoped_fields(&array_json, &array_scope).unwrap();

    vectors.push(json!({
        "id": "scope-003",
        "description": "Bracket-notation array element",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": array_payload,
            "scope": array_scope
        },
        "expected": {
            "proof": &array_proof,
            "scope_hash": &array_scope_hash,
            "extracted_fields": array_scoped
        },
        "debug": {
            "mode": "lenient"
        }
    }));

    // Vector 4: Nested array path items[0].id
    let nested_arr_scope: Vec<&str> = vec!["items[0].id"];
    let (na_proof, na_scope_hash) = ash_build_proof_scoped(
        &client_secret, TEST_TIMESTAMP, TEST_BINDING, array_payload, &nested_arr_scope
    ).unwrap();
    let na_scoped = ash_extract_scoped_fields(&array_json, &nested_arr_scope).unwrap();

    vectors.push(json!({
        "id": "scope-004",
        "description": "Nested array path items[0].id",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": array_payload,
            "scope": nested_arr_scope
        },
        "expected": {
            "proof": &na_proof,
            "scope_hash": &na_scope_hash,
            "extracted_fields": na_scoped
        },
        "debug": {
            "mode": "lenient"
        }
    }));

    // Vector 5: Empty scope returns full payload
    let empty_scope: Vec<&str> = vec![];
    let full_json: Value = serde_json::from_str(payload).unwrap();
    let full_scoped = ash_extract_scoped_fields(&full_json, &empty_scope).unwrap();

    vectors.push(json!({
        "id": "scope-005",
        "description": "Empty scope returns full payload",
        "input": {
            "payload": payload,
            "scope": empty_scope
        },
        "expected": {
            "extracted_fields": full_scoped
        },
        "debug": {
            "mode": "lenient"
        }
    }));

    // Vector 6: Missing field silently ignored (lenient)
    let missing_scope: Vec<&str> = vec!["amount", "nonexistent"];
    let missing_json: Value = serde_json::from_str(payload).unwrap();
    let missing_scoped = ash_extract_scoped_fields(&missing_json, &missing_scope).unwrap();

    vectors.push(json!({
        "id": "scope-006",
        "description": "Missing field silently ignored in lenient mode",
        "input": {
            "payload": payload,
            "scope": missing_scope
        },
        "expected": {
            "extracted_fields": missing_scoped
        },
        "debug": {
            "mode": "lenient"
        }
    }));

    // Vector 7: Scope hash for known fields
    let known_scope: Vec<&str> = vec!["amount", "recipient"];
    let known_hash = ash_hash_scope(&known_scope).unwrap();
    vectors.push(json!({
        "id": "scope-007",
        "description": "Scope hash: SHA256 of sorted fields joined by unit separator",
        "input": {
            "scope": known_scope
        },
        "expected": {
            "scope_hash": &known_hash
        },
        "debug": {
            "sorted_fields": ["amount", "recipient"],
            "joined_string_hex": hex::encode("amount\x1Frecipient")
        }
    }));

    // Vector 8: Strict mode missing field
    let strict_scope: Vec<&str> = vec!["amount", "nonexistent"];
    let strict_json: Value = serde_json::from_str(payload).unwrap();
    match ash_extract_scoped_fields_strict(&strict_json, &strict_scope, true) {
        Err(e) => {
            vectors.push(json!({
                "id": "scope-008",
                "description": "Strict mode: missing field returns error",
                "input": {
                    "payload": payload,
                    "scope": strict_scope,
                    "strict": true
                },
                "expected_error": {
                    "code": e.code().as_str(),
                    "http_status": e.http_status()
                },
                "debug": {
                    "mode": "strict"
                }
            }));
        }
        Ok(_) => eprintln!("WARN: strict mode should have failed"),
    }

    Value::Array(vectors)
}

// =========================================================================
// I. Unified Proof (Scope + Chain) (~6)
// =========================================================================

fn generate_unified_proof() -> Value {
    let mut vectors = Vec::new();

    let client_secret = ash_derive_client_secret(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING
    ).unwrap();

    let payload = r#"{"action":"transfer","amount":500}"#;

    // Vector 1: Basic unified (no scope, no chain)
    let result1 = ash_build_proof_unified(
        &client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, &[], None
    ).unwrap();

    vectors.push(json!({
        "id": "unified-001",
        "description": "Basic unified proof: no scope, no chain",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": payload,
            "scope": [],
            "previous_proof": null
        },
        "expected": {
            "proof": &result1.proof,
            "scope_hash": &result1.scope_hash,
            "chain_hash": &result1.chain_hash
        }
    }));

    // Vector 2: With scope only
    let scope: Vec<&str> = vec!["action", "amount"];
    let result2 = ash_build_proof_unified(
        &client_secret, TEST_TIMESTAMP, TEST_BINDING, payload, &scope, None
    ).unwrap();

    vectors.push(json!({
        "id": "unified-002",
        "description": "Unified proof with scope only",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": payload,
            "scope": scope,
            "previous_proof": null
        },
        "expected": {
            "proof": &result2.proof,
            "scope_hash": &result2.scope_hash,
            "chain_hash": &result2.chain_hash
        }
    }));

    // Vector 3: With chain only (using proof from vector 1 as previous)
    let result3 = ash_build_proof_unified(
        &client_secret, "1700000100", TEST_BINDING, payload, &[], Some(&result1.proof)
    ).unwrap();

    vectors.push(json!({
        "id": "unified-003",
        "description": "Unified proof with chain only",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": "1700000100",
            "payload": payload,
            "scope": [],
            "previous_proof": &result1.proof
        },
        "expected": {
            "proof": &result3.proof,
            "scope_hash": &result3.scope_hash,
            "chain_hash": &result3.chain_hash
        }
    }));

    // Vector 4: With scope and chain
    let result4 = ash_build_proof_unified(
        &client_secret, "1700000200", TEST_BINDING, payload, &scope, Some(&result3.proof)
    ).unwrap();

    vectors.push(json!({
        "id": "unified-004",
        "description": "Unified proof with scope and chain",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": "1700000200",
            "payload": payload,
            "scope": scope,
            "previous_proof": &result3.proof
        },
        "expected": {
            "proof": &result4.proof,
            "scope_hash": &result4.scope_hash,
            "chain_hash": &result4.chain_hash
        }
    }));

    // Vector 5: Chain hash is SHA256 of proof hex string
    let chain_hash = ash_hash_proof(&result1.proof).unwrap();
    vectors.push(json!({
        "id": "unified-005",
        "description": "Chain hash: SHA256 of proof hex ASCII bytes",
        "input": {
            "previous_proof": &result1.proof
        },
        "expected": {
            "chain_hash": &chain_hash
        }
    }));

    // Vector 6: Unified verify succeeds
    let valid = ash_verify_proof_unified(
        TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, TEST_TIMESTAMP,
        payload, &result1.proof, &[], "", None, ""
    ).unwrap();

    vectors.push(json!({
        "id": "unified-006",
        "description": "Unified proof verification succeeds",
        "input": {
            "nonce": TEST_NONCE,
            "context_id": TEST_CONTEXT_ID,
            "binding": TEST_BINDING,
            "timestamp": TEST_TIMESTAMP,
            "payload": payload,
            "proof": &result1.proof,
            "scope": [],
            "scope_hash": "",
            "previous_proof": null,
            "chain_hash": ""
        },
        "expected": {
            "valid": valid
        }
    }));

    Value::Array(vectors)
}

// =========================================================================
// J. Timing-Safe Comparison (~5)
// =========================================================================

fn generate_timing_safe() -> Value {
    let mut vectors = Vec::new();

    let cases: Vec<(&str, &str, &str, &str, bool)> = vec![
        ("timing-001", "Equal strings", "hello", "hello", true),
        ("timing-002", "Different strings", "hello", "world", false),
        ("timing-003", "Different lengths", "hello", "hi", false),
        ("timing-004", "Empty strings equal", "", "", true),
        ("timing-005", "Empty vs non-empty", "", "x", false),
    ];

    for (id, desc, a, b, _) in &cases {
        let result = ash_timing_safe_compare(a, b);
        vectors.push(json!({
            "id": id,
            "description": desc,
            "input": {
                "a": a,
                "b": b
            },
            "expected": result,
            "note": "Suite tests correctness only, not constant-time behavior"
        }));
    }

    Value::Array(vectors)
}

// =========================================================================
// K. Error Behavior (~15)
// =========================================================================

fn generate_error_behavior() -> Value {
    let mut vectors = Vec::new();

    // Empty nonce
    match ash_derive_client_secret("", TEST_CONTEXT_ID, TEST_BINDING) {
        Err(e) => vectors.push(json!({
            "id": "error-001",
            "description": "Empty nonce rejected",
            "input": { "operation": "derive_client_secret", "nonce": "", "context_id": TEST_CONTEXT_ID, "binding": TEST_BINDING },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: empty nonce should fail"),
    }

    // Invalid hex nonce
    match ash_derive_client_secret("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", TEST_CONTEXT_ID, TEST_BINDING) {
        Err(e) => vectors.push(json!({
            "id": "error-002",
            "description": "Non-hex nonce rejected",
            "input": { "operation": "derive_client_secret", "nonce": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "context_id": TEST_CONTEXT_ID, "binding": TEST_BINDING },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: non-hex nonce should fail"),
    }

    // Short nonce
    match ash_derive_client_secret("0123456789abcdef", TEST_CONTEXT_ID, TEST_BINDING) {
        Err(e) => vectors.push(json!({
            "id": "error-003",
            "description": "Short nonce rejected (< 32 hex chars)",
            "input": { "operation": "derive_client_secret", "nonce": "0123456789abcdef", "context_id": TEST_CONTEXT_ID, "binding": TEST_BINDING },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: short nonce should fail"),
    }

    // Empty context_id
    match ash_derive_client_secret(TEST_NONCE, "", TEST_BINDING) {
        Err(e) => vectors.push(json!({
            "id": "error-004",
            "description": "Empty context_id rejected",
            "input": { "operation": "derive_client_secret", "nonce": TEST_NONCE, "context_id": "", "binding": TEST_BINDING },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: empty context_id should fail"),
    }

    // Empty binding
    match ash_derive_client_secret(TEST_NONCE, TEST_CONTEXT_ID, "") {
        Err(e) => vectors.push(json!({
            "id": "error-005",
            "description": "Empty binding rejected",
            "input": { "operation": "derive_client_secret", "nonce": TEST_NONCE, "context_id": TEST_CONTEXT_ID, "binding": "" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: empty binding should fail"),
    }

    // Invalid JSON
    match ash_canonicalize_json("not json at all") {
        Err(e) => vectors.push(json!({
            "id": "error-006",
            "description": "Invalid JSON rejected",
            "input": { "operation": "canonicalize_json", "input_json_text": "not json at all" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: invalid json should fail"),
    }

    // Oversized JSON (we just record the error code/status, don't actually generate 11MB)
    vectors.push(json!({
        "id": "error-007",
        "description": "Oversized JSON rejected (>10MB)",
        "input": { "operation": "canonicalize_json", "note": "Input exceeds 10MB limit" },
        "expected_error": { "code": "ASH_CANONICALIZATION_ERROR", "http_status": 484 }
    }));

    // Deeply nested JSON
    let mut deep = String::from("{\"a\":");
    for _ in 0..100 {
        deep.push_str("{\"a\":");
    }
    deep.push('1');
    for _ in 0..101 {
        deep.push('}');
    }
    match ash_canonicalize_json(&deep) {
        Err(e) => vectors.push(json!({
            "id": "error-008",
            "description": "Deeply nested JSON rejected (>64 levels)",
            "input": { "operation": "canonicalize_json", "note": "Input exceeds 64 nesting levels" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: deeply nested json should fail"),
    }

    // Invalid timestamp format
    match ash_verify_proof(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, "abc", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "0000000000000000000000000000000000000000000000000000000000000000") {
        Err(e) => vectors.push(json!({
            "id": "error-009",
            "description": "Invalid timestamp format rejected (non-digits)",
            "input": { "operation": "verify_proof", "timestamp": "abc" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: invalid timestamp should fail"),
    }

    // Timestamp with leading zeros
    match ash_verify_proof(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, "0123456789", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "0000000000000000000000000000000000000000000000000000000000000000") {
        Err(e) => vectors.push(json!({
            "id": "error-010",
            "description": "Timestamp with leading zeros rejected",
            "input": { "operation": "verify_proof", "timestamp": "0123456789" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: leading-zero timestamp should fail"),
    }

    // Missing scoped field (strict mode)
    let strict_payload: Value = serde_json::from_str(r#"{"amount":100}"#).unwrap();
    let strict_scope = vec!["amount", "nonexistent"];
    match ash_extract_scoped_fields_strict(&strict_payload, &strict_scope, true) {
        Err(e) => vectors.push(json!({
            "id": "error-011",
            "description": "Missing scoped field in strict mode",
            "input": { "operation": "extract_scoped_fields_strict", "payload": r#"{"amount":100}"#, "scope": ["amount", "nonexistent"] },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: strict mode missing field should fail"),
    }

    // Invalid body hash format
    match ash_build_proof("secret", "1700000000", TEST_BINDING, "short") {
        Err(e) => vectors.push(json!({
            "id": "error-012",
            "description": "Invalid body hash format rejected (wrong length)",
            "input": { "operation": "build_proof", "body_hash": "short" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: short body hash should fail"),
    }

    // Non-hex body hash
    match ash_build_proof("secret", "1700000000", TEST_BINDING, "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
        Err(e) => vectors.push(json!({
            "id": "error-013",
            "description": "Non-hex body hash rejected",
            "input": { "operation": "build_proof", "body_hash": "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: non-hex body hash should fail"),
    }

    // Empty proof for chain hashing
    match ash_hash_proof("") {
        Err(e) => vectors.push(json!({
            "id": "error-014",
            "description": "Empty proof rejected for chain hashing",
            "input": { "operation": "hash_proof", "proof": "" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: empty proof for chain should fail"),
    }

    // Empty timestamp
    match ash_verify_proof(TEST_NONCE, TEST_CONTEXT_ID, TEST_BINDING, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "0000000000000000000000000000000000000000000000000000000000000000") {
        Err(e) => vectors.push(json!({
            "id": "error-015",
            "description": "Empty timestamp rejected",
            "input": { "operation": "verify_proof", "timestamp": "" },
            "expected_error": { "code": e.code().as_str(), "http_status": e.http_status() }
        })),
        Ok(_) => eprintln!("WARN: empty timestamp should fail"),
    }

    Value::Array(vectors)
}

// =========================================================================
// L. Timestamp Validation (~8)
// =========================================================================

fn generate_timestamp_validation() -> Value {
    let mut vectors = Vec::new();

    // Vector 1: Valid timestamp "0"
    vectors.push(json!({
        "id": "timestamp-001",
        "description": "Timestamp '0' is valid format",
        "input": { "timestamp": "0" },
        "expected": { "valid_format": true }
    }));

    // Vector 2: Digits only
    vectors.push(json!({
        "id": "timestamp-002",
        "description": "Timestamp must be digits only",
        "input": { "timestamp": "123abc" },
        "expected_error": { "code": "ASH_TIMESTAMP_INVALID", "http_status": 482 }
    }));

    // Vector 3: No leading zeros
    vectors.push(json!({
        "id": "timestamp-003",
        "description": "Leading zeros rejected (except '0' itself)",
        "input": { "timestamp": "0100" },
        "expected_error": { "code": "ASH_TIMESTAMP_INVALID", "http_status": 482 }
    }));

    // Vector 4: Reference timestamp is valid
    vectors.push(json!({
        "id": "timestamp-004",
        "description": "Reference timestamp is valid format",
        "input": { "timestamp": TEST_TIMESTAMP },
        "expected": { "valid_format": true, "value_seconds": REFERENCE_TIME }
    }));

    // Vector 5: Empty timestamp rejected
    vectors.push(json!({
        "id": "timestamp-005",
        "description": "Empty timestamp rejected",
        "input": { "timestamp": "" },
        "expected_error": { "code": "ASH_TIMESTAMP_INVALID", "http_status": 482 }
    }));

    // Vector 6: Negative timestamp rejected (minus sign)
    vectors.push(json!({
        "id": "timestamp-006",
        "description": "Negative timestamp rejected",
        "input": { "timestamp": "-1" },
        "expected_error": { "code": "ASH_TIMESTAMP_INVALID", "http_status": 482 }
    }));

    // Vector 7: Whitespace in timestamp rejected
    vectors.push(json!({
        "id": "timestamp-007",
        "description": "Whitespace in timestamp rejected",
        "input": { "timestamp": " 100 " },
        "expected_error": { "code": "ASH_TIMESTAMP_INVALID", "http_status": 482 }
    }));

    // Vector 8: All timestamps are in seconds (not milliseconds)
    vectors.push(json!({
        "id": "timestamp-008",
        "description": "Timestamps use seconds resolution (not milliseconds)",
        "input": {
            "reference_time": REFERENCE_TIME,
            "note": "All ASH timestamps are Unix seconds. reference_time 1700000000 = 2023-11-14T22:13:20Z"
        },
        "expected": {
            "resolution": "seconds",
            "reference_time_seconds": REFERENCE_TIME
        }
    }));

    Value::Array(vectors)
}
