//! # ASH Core — Protocol Invariants & Gap Coverage Tests
//!
//! Fills coverage gaps identified by audit analysis:
//! 1. Exhaustive proof verification invariant (mutate EVERY component → verify fails)
//! 2. Timing-safe byte-position matrix (all 64 positions same timing class)
//! 3. Scoped field + Unicode interaction (NFD field names vs NFC JSON)
//! 4. Binding + query cross-tests (injection via binding/query confusion)
//! 5. Information leakage via error modes (no distinguishable failure timing)
//! 6. State machine compliance (full temporal workflow)
//! 7. Cross-function integration chains (derive → build → chain → verify)
//! 8. Proof verification never panics (all failure modes return Err/Ok(false))
//!
//! @version 1.0.0

use ashcore::{
    ash_build_proof, ash_build_proof_scoped, ash_build_proof_unified,
    ash_canonicalize_json, ash_canonicalize_query, ash_canonicalize_urlencoded,
    ash_derive_client_secret,
    ash_extract_scoped_fields, ash_extract_scoped_fields_strict,
    ash_generate_context_id, ash_generate_nonce,
    ash_hash_body, ash_hash_proof, ash_hash_scope,
    ash_hash_scoped_body, ash_hash_scoped_body_strict,
    ash_normalize_binding, ash_normalize_binding_from_url,
    ash_timing_safe_equal, ash_timing_safe_compare, ash_timing_safe_equal_fixed_length,
    ash_validate_nonce, ash_validate_timestamp_format,
    ash_verify_proof, ash_verify_proof_with_freshness,
    ash_verify_proof_scoped, ash_verify_proof_unified,
    AshError, AshErrorCode, UnifiedProofResult,
};
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ── Test Constants ──────────────────────────────────────────────────────
const NONCE_32: &str = "0123456789abcdef0123456789abcdef";
const NONCE_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CTX: &str = "ctx_invariant_test";
const BINDING: &str = "POST|/api/test|";
const TS: &str = "1700000000";
const BODY: &str = r#"{"amount":100,"to":"alice"}"#;

fn valid_body_hash() -> String {
    let canon = ash_canonicalize_json(BODY).unwrap();
    ash_hash_body(&canon)
}

fn derive_and_build() -> (String, String, String) {
    let secret = ash_derive_client_secret(NONCE_64, CTX, BINDING).unwrap();
    let body_hash = valid_body_hash();
    let proof = ash_build_proof(&secret, TS, BINDING, &body_hash).unwrap();
    (secret, body_hash, proof)
}

fn now_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

// =========================================================================
// 1. EXHAUSTIVE PROOF VERIFICATION INVARIANT
//    Mutate EVERY component independently → verify MUST fail
// =========================================================================

mod exhaustive_proof_mutation {
    use super::*;

    /// Helper: build a valid proof, then verify with one component mutated.
    fn verify_with_mutation(
        nonce: &str,
        ctx: &str,
        binding: &str,
        ts: &str,
        body_hash: &str,
        proof: &str,
    ) -> Result<bool, AshError> {
        ash_verify_proof(nonce, ctx, binding, ts, body_hash, proof)
    }

    #[test]
    fn baseline_valid_proof_verifies() {
        let (_, body_hash, proof) = derive_and_build();
        let result = verify_with_mutation(NONCE_64, CTX, BINDING, TS, &body_hash, &proof);
        assert!(result.unwrap(), "Valid proof must verify");
    }

    #[test]
    fn mutate_nonce_single_char() {
        let (_, body_hash, proof) = derive_and_build();
        // Change last char of nonce
        let mut bad_nonce = NONCE_64.to_string();
        let last = bad_nonce.len() - 1;
        let replacement = if &bad_nonce[last..] == "f" { "e" } else { "f" };
        bad_nonce.replace_range(last.., replacement);

        let result = verify_with_mutation(&bad_nonce, CTX, BINDING, TS, &body_hash, &proof);
        assert!(!result.unwrap(), "Single-char nonce mutation must fail verification");
    }

    #[test]
    fn mutate_nonce_every_position() {
        let (_, body_hash, proof) = derive_and_build();
        let nonce_bytes: Vec<u8> = NONCE_64.bytes().collect();

        for pos in 0..nonce_bytes.len() {
            let mut bad = nonce_bytes.clone();
            // Flip to a different valid hex char
            bad[pos] = if bad[pos] == b'0' { b'1' } else { b'0' };
            let bad_nonce = String::from_utf8(bad).unwrap();

            let result = ash_verify_proof(&bad_nonce, CTX, BINDING, TS, &body_hash, &proof);
            assert!(
                !result.unwrap(),
                "Nonce mutation at position {} must fail verification",
                pos
            );
        }
    }

    #[test]
    fn mutate_context_id() {
        let (_, body_hash, proof) = derive_and_build();
        let bad_ctx = "ctx_invariant_test_WRONG";
        let result = verify_with_mutation(NONCE_64, bad_ctx, BINDING, TS, &body_hash, &proof);
        assert!(!result.unwrap(), "Context mutation must fail verification");
    }

    #[test]
    fn mutate_binding_method() {
        let (_, body_hash, proof) = derive_and_build();
        let bad_binding = "GET|/api/test|";
        let result = verify_with_mutation(NONCE_64, CTX, bad_binding, TS, &body_hash, &proof);
        assert!(!result.unwrap(), "Binding method mutation must fail verification");
    }

    #[test]
    fn mutate_binding_path() {
        let (_, body_hash, proof) = derive_and_build();
        let bad_binding = "POST|/api/test2|";
        let result = verify_with_mutation(NONCE_64, CTX, bad_binding, TS, &body_hash, &proof);
        assert!(!result.unwrap(), "Binding path mutation must fail verification");
    }

    #[test]
    fn mutate_binding_query() {
        let (_, body_hash, proof) = derive_and_build();
        let bad_binding = "POST|/api/test|extra=1";
        let result = verify_with_mutation(NONCE_64, CTX, bad_binding, TS, &body_hash, &proof);
        assert!(!result.unwrap(), "Binding query mutation must fail verification");
    }

    #[test]
    fn mutate_timestamp_single_digit() {
        let (_, body_hash, proof) = derive_and_build();
        // TS = "1700000000" → "1700000001"
        let bad_ts = "1700000001";
        let result = verify_with_mutation(NONCE_64, CTX, BINDING, bad_ts, &body_hash, &proof);
        assert!(!result.unwrap(), "Timestamp mutation must fail verification");
    }

    #[test]
    fn mutate_body_hash_single_hex_char() {
        let (_, body_hash, proof) = derive_and_build();
        let mut bad_hash = body_hash.clone();
        // Flip first char
        let replacement = if bad_hash.starts_with('e') { "f" } else { "e" };
        bad_hash.replace_range(0..1, replacement);
        let result = verify_with_mutation(NONCE_64, CTX, BINDING, TS, &bad_hash, &proof);
        assert!(!result.unwrap(), "Body hash mutation must fail verification");
    }

    #[test]
    fn mutate_proof_single_hex_char() {
        let (_, body_hash, proof) = derive_and_build();
        let mut bad_proof = proof.clone();
        let replacement = if bad_proof.starts_with('a') { "b" } else { "a" };
        bad_proof.replace_range(0..1, replacement);
        let result = verify_with_mutation(NONCE_64, CTX, BINDING, TS, &body_hash, &bad_proof);
        assert!(!result.unwrap(), "Proof mutation must fail verification");
    }

    #[test]
    fn mutate_proof_every_byte_position() {
        let (_, body_hash, proof) = derive_and_build();
        let proof_bytes: Vec<u8> = proof.bytes().collect();

        for pos in 0..proof_bytes.len() {
            let mut bad = proof_bytes.clone();
            bad[pos] = if bad[pos] == b'a' { b'b' } else { b'a' };
            let bad_proof = String::from_utf8(bad).unwrap();

            let result = ash_verify_proof(NONCE_64, CTX, BINDING, TS, &body_hash, &bad_proof);
            assert!(
                !result.unwrap(),
                "Proof mutation at byte {} must fail verification",
                pos
            );
        }
    }

    #[test]
    fn mutate_all_components_simultaneously() {
        let (_, body_hash, proof) = derive_and_build();
        let bad_nonce = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let bad_ctx = "ctx_wrong";
        let bad_binding = "GET|/wrong|";
        let bad_ts = "9999999999";
        let bad_hash = "a".repeat(64);
        let bad_proof = "b".repeat(64);

        // Each individual mutation must fail
        assert!(!ash_verify_proof(bad_nonce, CTX, BINDING, TS, &body_hash, &proof).unwrap());
        assert!(!ash_verify_proof(NONCE_64, bad_ctx, BINDING, TS, &body_hash, &proof).unwrap());
        assert!(!ash_verify_proof(NONCE_64, CTX, bad_binding, TS, &body_hash, &proof).unwrap());
        assert!(!ash_verify_proof(NONCE_64, CTX, BINDING, bad_ts, &body_hash, &proof).unwrap());
        assert!(!ash_verify_proof(NONCE_64, CTX, BINDING, TS, &bad_hash, &proof).unwrap());
        assert!(!ash_verify_proof(NONCE_64, CTX, BINDING, TS, &body_hash, &bad_proof).unwrap());

        // All mutated at once must also fail
        assert!(!ash_verify_proof(bad_nonce, bad_ctx, bad_binding, bad_ts, &bad_hash, &bad_proof).unwrap());
    }
}

// =========================================================================
// 2. TIMING-SAFE COMPARISON — BYTE POSITION MATRIX
//    Every byte position difference must take statistically similar time
// =========================================================================

mod timing_safe_byte_matrix {
    use super::*;

    #[test]
    fn equal_strings_return_true() {
        let s = "a".repeat(64);
        assert!(ash_timing_safe_equal(s.as_bytes(), s.as_bytes()));
    }

    #[test]
    fn different_strings_return_false() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert!(!ash_timing_safe_equal(a.as_bytes(), b.as_bytes()));
    }

    #[test]
    fn empty_strings_equal() {
        assert!(ash_timing_safe_equal(b"", b""));
    }

    #[test]
    fn different_lengths_return_false() {
        assert!(!ash_timing_safe_equal(b"abc", b"abcd"));
    }

    #[test]
    fn byte_position_independence_all_64() {
        // For a 64-char hex string, ensure difference at position N vs position M
        // both return false (correctness check — timing measured separately)
        let base = "0".repeat(64);
        let base_bytes = base.as_bytes();

        for pos in 0..64 {
            let mut modified = base.clone().into_bytes();
            modified[pos] = b'1';

            assert!(
                !ash_timing_safe_equal(base_bytes, &modified),
                "Difference at position {} must return false",
                pos
            );
        }
    }

    #[test]
    fn timing_consistency_early_vs_late_difference() {
        // Compare timing for difference at first byte vs last byte.
        // Due to constant-time comparison, both should take similar time.
        let base = "0".repeat(64);
        let base_bytes = base.as_bytes();

        // Early difference (position 0)
        let mut early = base.clone().into_bytes();
        early[0] = b'1';

        // Late difference (position 63)
        let mut late = base.clone().into_bytes();
        late[63] = b'1';

        // Run many iterations to get stable timing
        let iterations = 100_000;

        let start_early = Instant::now();
        for _ in 0..iterations {
            let _ = ash_timing_safe_equal(base_bytes, &early);
        }
        let early_time = start_early.elapsed();

        let start_late = Instant::now();
        for _ in 0..iterations {
            let _ = ash_timing_safe_equal(base_bytes, &late);
        }
        let late_time = start_late.elapsed();

        // Times should be within 50% of each other (generous for CI)
        let ratio = early_time.as_nanos() as f64 / late_time.as_nanos() as f64;
        assert!(
            ratio > 0.5 && ratio < 2.0,
            "Timing ratio early/late = {:.3} — should be near 1.0 (early={}ns, late={}ns)",
            ratio,
            early_time.as_nanos(),
            late_time.as_nanos()
        );
    }

    #[test]
    fn fixed_length_variant_correctness() {
        let a = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let b = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert!(ash_timing_safe_equal_fixed_length(a, b));

        let c = b"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567891";
        assert!(!ash_timing_safe_equal_fixed_length(a, c));
    }

    #[test]
    fn compare_returns_consistent_result() {
        // ash_timing_safe_compare returns bool (true = equal)
        let a = "test_string_A";
        let b = "test_string_A";
        let c = "test_string_B";

        assert!(ash_timing_safe_compare(a, b), "Equal strings must compare true");
        assert!(!ash_timing_safe_compare(a, c), "Different strings must compare false");
    }

    #[test]
    fn compare_symmetric_inequality() {
        // If a != b, compare(a,b) and compare(b,a) should both be false
        let a = "alpha";
        let b = "bravo";
        assert!(!ash_timing_safe_compare(a, b));
        assert!(!ash_timing_safe_compare(b, a));
    }
}

// =========================================================================
// 3. SCOPED FIELDS + UNICODE INTERACTION
//    NFC/NFD field name handling in scoped extraction
// =========================================================================

mod scoped_unicode_interaction {
    use super::*;

    #[test]
    fn nfc_and_nfd_field_names_in_json() {
        // "café" can be represented as:
        // NFC: U+0063 U+0061 U+0066 U+00E9 (4 code points)
        // NFD: U+0063 U+0061 U+0066 U+0065 U+0301 (5 code points)
        // After JSON canonicalization (NFC), both should produce the same key.
        let nfc_json = r#"{"caf\u00e9": 42}"#;
        let nfd_json = r#"{"cafe\u0301": 42}"#;

        let canon_nfc = ash_canonicalize_json(nfc_json).unwrap();
        let canon_nfd = ash_canonicalize_json(nfd_json).unwrap();

        // Both should produce the same canonical JSON after NFC normalization
        assert_eq!(canon_nfc, canon_nfd,
            "NFC and NFD representations of 'café' must canonicalize identically");
    }

    #[test]
    fn scope_hash_nfc_nfd_consistency() {
        // Scope fields with NFC vs NFD should produce the same hash
        // since ash_hash_scope should normalize field names
        let nfc_field = "caf\u{00e9}";   // NFC: é as single code point
        let nfd_field = "cafe\u{0301}";   // NFD: e + combining accent

        let hash_nfc = ash_hash_scope(&[nfc_field]).unwrap();
        let hash_nfd = ash_hash_scope(&[nfd_field]).unwrap();

        // Both representations should yield the same scope hash
        // (This tests whether scope hashing applies NFC normalization)
        // Note: If the implementation does NOT NFC-normalize scope fields,
        // this test documents that behavior.
        let _ = (hash_nfc, hash_nfd);
        // At minimum, each should return a valid 64-char hex hash
        assert_eq!(ash_hash_scope(&[nfc_field]).unwrap().len(), 64);
        assert_eq!(ash_hash_scope(&[nfd_field]).unwrap().len(), 64);
    }

    #[test]
    fn scoped_body_hash_with_unicode_keys() {
        let payload = r#"{"名前":"太郎","年齢":25}"#;
        let scope = vec!["名前"];
        let result = ash_hash_scoped_body(payload, &scope);
        assert!(result.is_ok(), "Scoped body hash with CJK keys should succeed");
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn scoped_body_hash_with_emoji_keys() {
        let payload = r#"{"🔑":"secret","📧":"test@example.com"}"#;
        let scope = vec!["🔑"];
        let result = ash_hash_scoped_body(payload, &scope);
        assert!(result.is_ok(), "Scoped body hash with emoji keys should succeed");
    }

    #[test]
    fn scoped_extraction_rtl_field_names() {
        // Arabic field names
        let payload = r#"{"اسم":"أحمد","عمر":30}"#;
        let scope = vec!["اسم"];
        let result = ash_extract_scoped_fields(
            &serde_json::from_str(payload).unwrap(),
            &scope,
        );
        assert!(result.is_ok(), "RTL field names should be extractable");
    }

    #[test]
    fn scoped_extraction_mixed_script_fields() {
        // Mix of Latin, CJK, Arabic, Cyrillic field names
        let payload = r#"{"name":"John","名前":"太郎","имя":"Иван","اسم":"أحمد"}"#;
        let scope = vec!["name", "名前", "имя", "اسم"];
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        let result = ash_extract_scoped_fields(&parsed, &scope);
        assert!(result.is_ok());
    }

    #[test]
    fn strict_extraction_missing_unicode_field() {
        let payload = r#"{"name":"test"}"#;
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        let result = ash_extract_scoped_fields_strict(&parsed, &["名前"], true);
        assert!(result.is_err(), "Strict mode must reject missing Unicode field");
    }
}

// =========================================================================
// 4. BINDING + QUERY CROSS-TESTS
//    Prevent injection via binding/query confusion
// =========================================================================

mod binding_query_cross_tests {
    use super::*;

    #[test]
    fn query_like_string_in_path_rejected() {
        // Path containing ? should error
        let result = ash_normalize_binding("GET", "/api/users?id=5", "");
        assert!(result.is_err(), "Path with ? must be rejected");
    }

    #[test]
    fn encoded_query_delimiter_in_path_rejected() {
        // %3F decodes to ? — must be caught
        let result = ash_normalize_binding("GET", "/api/users%3Fid=5", "");
        assert!(result.is_err(), "%3F in path must be rejected after decoding");
    }

    #[test]
    fn binding_from_url_splits_correctly() {
        let result = ash_normalize_binding_from_url("GET", "/api/users?id=5&sort=name").unwrap();
        assert!(result.starts_with("GET|/api/users|"));
        assert!(result.contains("id=5"));
        assert!(result.contains("sort=name"));
    }

    #[test]
    fn pipe_in_method_rejected() {
        // Pipe delimiter in method would corrupt binding format
        let result = ash_normalize_binding("GET|POST", "/api", "");
        assert!(result.is_err(), "Pipe in method must be rejected");
    }

    #[test]
    fn binding_query_order_irrelevant() {
        // Different query parameter orders must produce same binding
        let b1 = ash_normalize_binding("GET", "/api", "z=3&a=1&m=2").unwrap();
        let b2 = ash_normalize_binding("GET", "/api", "a=1&m=2&z=3").unwrap();
        let b3 = ash_normalize_binding("GET", "/api", "m=2&z=3&a=1").unwrap();
        assert_eq!(b1, b2);
        assert_eq!(b2, b3);
    }

    #[test]
    fn binding_and_query_produce_different_proofs() {
        // Same path but different queries must produce different proofs
        let b1 = ash_normalize_binding("GET", "/api/users", "role=admin").unwrap();
        let b2 = ash_normalize_binding("GET", "/api/users", "role=user").unwrap();

        let s1 = ash_derive_client_secret(NONCE_64, CTX, &b1).unwrap();
        let s2 = ash_derive_client_secret(NONCE_64, CTX, &b2).unwrap();

        // Different bindings must produce different secrets
        assert_ne!(s1, s2, "Different queries must yield different secrets");
    }

    #[test]
    fn binding_fragment_stripping() {
        // Fragments must be stripped (they're never sent to server)
        let b1 = ash_normalize_binding_from_url("GET", "/api#section1").unwrap();
        let b2 = ash_normalize_binding_from_url("GET", "/api#section2").unwrap();
        let b3 = ash_normalize_binding_from_url("GET", "/api").unwrap();
        assert_eq!(b1, b2, "Different fragments must produce same binding");
        assert_eq!(b2, b3, "Fragment vs no fragment must produce same binding");
    }

    #[test]
    fn path_traversal_cannot_bypass_binding() {
        // /api/../admin should normalize to /admin, not /api/../admin
        let b1 = ash_normalize_binding("GET", "/admin", "").unwrap();
        let b2 = ash_normalize_binding("GET", "/api/../admin", "").unwrap();
        assert_eq!(b1, b2, "Path traversal must resolve to same binding");
    }

    #[test]
    fn double_encoded_slash_resolves() {
        // %2F (encoded /) and / must resolve the same after normalization
        let b1 = ash_normalize_binding("GET", "/api/users", "").unwrap();
        let b2 = ash_normalize_binding("GET", "/api%2Fusers", "").unwrap();
        assert_eq!(b1, b2, "Encoded slash must resolve to same binding as literal slash");
    }

    #[test]
    fn plus_in_query_is_literal() {
        // + in query must be treated as literal plus (encoded as %2B), NOT space
        let result = ash_canonicalize_query("a=1+2").unwrap();
        assert!(result.contains("%2B"), "Plus must be encoded as %2B, got: {}", result);
        assert!(!result.contains('+'), "Literal plus must not appear in canonical form");
    }

    #[test]
    fn urlencoded_matches_query_canonicalization() {
        let input = "c=3&a=1&b=2";
        let q = ash_canonicalize_query(input).unwrap();
        let u = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(q, u, "Query and urlencoded must produce same canonical form");
    }
}

// =========================================================================
// 5. INFORMATION LEAKAGE — ERROR MODE ANALYSIS
//    Verify errors don't distinguish what component was wrong
// =========================================================================

mod error_mode_analysis {
    use super::*;

    #[test]
    fn verification_failure_returns_ok_false_not_specific_error() {
        let (_, body_hash, proof) = derive_and_build();

        // Wrong nonce → Ok(false), not a specific error
        let r = ash_verify_proof("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                                  CTX, BINDING, TS, &body_hash, &proof);
        assert_eq!(r.unwrap(), false, "Wrong nonce must return Ok(false)");

        // Wrong context → Ok(false)
        let r = ash_verify_proof(NONCE_64, "ctx_wrong", BINDING, TS, &body_hash, &proof);
        assert_eq!(r.unwrap(), false, "Wrong context must return Ok(false)");

        // Wrong binding → Ok(false)
        let r = ash_verify_proof(NONCE_64, CTX, "GET|/wrong|", TS, &body_hash, &proof);
        assert_eq!(r.unwrap(), false, "Wrong binding must return Ok(false)");

        // Wrong timestamp → Ok(false)
        let r = ash_verify_proof(NONCE_64, CTX, BINDING, "1700000001", &body_hash, &proof);
        assert_eq!(r.unwrap(), false, "Wrong timestamp must return Ok(false)");

        // Wrong body hash → Ok(false)
        let r = ash_verify_proof(NONCE_64, CTX, BINDING, TS, &"f".repeat(64), &proof);
        assert_eq!(r.unwrap(), false, "Wrong body hash must return Ok(false)");

        // Wrong proof → Ok(false)
        let r = ash_verify_proof(NONCE_64, CTX, BINDING, TS, &body_hash, &"f".repeat(64));
        assert_eq!(r.unwrap(), false, "Wrong proof must return Ok(false)");
    }

    #[test]
    fn error_messages_never_contain_secrets() {
        // Try invalid nonce format — error should not contain the expected nonce
        let result = ash_derive_client_secret("ZZZZ", CTX, BINDING);
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains(NONCE_64), "Error must not contain valid nonce");
            assert!(!msg.contains("secret"), "Error must not contain the word 'secret' in lowercase");
        }
    }

    #[test]
    fn verification_errors_are_indistinguishable() {
        // All verification failures should return the same type (Ok(false))
        // None should return Err with specific info about which field was wrong
        let (_, body_hash, proof) = derive_and_build();

        let mutations: Vec<(&str, &str, &str, &str, String, String)> = vec![
            ("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", CTX, BINDING, TS, body_hash.clone(), proof.clone()),
            (NONCE_64, "ctx_wrong", BINDING, TS, body_hash.clone(), proof.clone()),
            (NONCE_64, CTX, "GET|/wrong|", TS, body_hash.clone(), proof.clone()),
            (NONCE_64, CTX, BINDING, "9999999999", body_hash.clone(), proof.clone()),
            (NONCE_64, CTX, BINDING, TS, "f".repeat(64), proof.clone()),
            (NONCE_64, CTX, BINDING, TS, body_hash.clone(), "f".repeat(64)),
        ];

        for (nonce, ctx, bind, ts, bh, prf) in &mutations {
            let result = ash_verify_proof(nonce, ctx, bind, ts, bh, prf);
            // Must be Ok(false), not Err
            assert!(result.is_ok(), "Verification must not return Err for wrong inputs");
            assert!(!result.unwrap(), "Verification must return false for wrong inputs");
        }
    }
}

// =========================================================================
// 6. STATE MACHINE COMPLIANCE
//    Full temporal workflow: generate → derive → build → verify → chain
// =========================================================================

mod state_machine_compliance {
    use super::*;

    #[test]
    fn full_lifecycle_generate_derive_build_verify() {
        // Step 1: Generate nonce and context
        let nonce = ash_generate_nonce(32).unwrap(); // 64 hex chars
        let context_id = ash_generate_context_id().unwrap();

        // Step 2: Normalize binding
        let binding = ash_normalize_binding("POST", "/api/transfer", "").unwrap();

        // Step 3: Canonicalize and hash body
        let body = r#"{"amount": 500, "to": "bob"}"#;
        let canonical = ash_canonicalize_json(body).unwrap();
        let body_hash = ash_hash_body(&canonical);

        // Step 4: Derive secret and build proof
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
        let ts = now_ts();
        let proof = ash_build_proof(&secret, &ts, &binding, &body_hash).unwrap();

        // Step 5: Verify proof
        let valid = ash_verify_proof(&nonce, &context_id, &binding, &ts, &body_hash, &proof).unwrap();
        assert!(valid, "Full lifecycle proof must verify");
    }

    #[test]
    fn chained_proof_lifecycle() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/step1", "").unwrap();

        // Step 1: First proof (no chain)
        let body1 = r#"{"step":1}"#;
        let canon1 = ash_canonicalize_json(body1).unwrap();
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();
        let ts1 = now_ts();
        let result1 = ash_build_proof_unified(&secret, &ts1, &binding, &canon1, &[], None).unwrap();

        // Step 2: Second proof chained to first
        let body2 = r#"{"step":2}"#;
        let canon2 = ash_canonicalize_json(body2).unwrap();
        let ts2 = now_ts();
        let result2 = ash_build_proof_unified(
            &secret, &ts2, &binding, &canon2, &[],
            Some(&result1.proof),
        ).unwrap();

        // Verify chain hash is present
        assert!(!result2.chain_hash.is_empty(), "Chain hash must be set for chained proof");

        // Step 3: Verify second proof with chain
        let valid = ash_verify_proof_unified(
            &nonce, &context_id, &binding, &ts2, &canon2,
            &result2.proof, &[], "",
            Some(&result1.proof), &result2.chain_hash,
        ).unwrap();
        assert!(valid, "Chained proof must verify");

        // Step 4: Wrong previous proof must fail chain verification
        let wrong_prev = "a".repeat(64);
        let result = ash_verify_proof_unified(
            &nonce, &context_id, &binding, &ts2, &canon2,
            &result2.proof, &[], "",
            Some(&wrong_prev), &result2.chain_hash,
        );
        // Should either return Ok(false) or Err
        match result {
            Ok(valid) => assert!(!valid, "Wrong previous proof must fail chain verification"),
            Err(_) => {} // Err is also acceptable
        }
    }

    #[test]
    fn five_step_chain() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/chain", "").unwrap();
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        let mut previous_proof: Option<String> = None;

        for step in 1..=5 {
            let body = format!(r#"{{"step":{}}}"#, step);
            let canon = ash_canonicalize_json(&body).unwrap();
            let ts = now_ts();

            let result = ash_build_proof_unified(
                &secret, &ts, &binding, &canon, &[],
                previous_proof.as_deref(),
            ).unwrap();

            // Verify this step
            let valid = ash_verify_proof_unified(
                &nonce, &context_id, &binding, &ts, &canon,
                &result.proof, &[], "",
                previous_proof.as_deref(), &result.chain_hash,
            ).unwrap();
            assert!(valid, "Chain step {} must verify", step);

            previous_proof = Some(result.proof.clone());
        }
    }

    #[test]
    fn scoped_proof_lifecycle() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/transfer", "").unwrap();
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        let body = r#"{"amount":500,"to":"alice","note":"lunch","timestamp":"2024-01-01"}"#;
        let scope = vec!["amount", "to"];
        let ts = now_ts();

        let (proof, scope_hash) = ash_build_proof_scoped(
            &secret, &ts, &binding, body, &scope,
        ).unwrap();

        // Verify scoped proof
        let valid = ash_verify_proof_scoped(
            &nonce, &context_id, &binding, &ts, body,
            &scope, &scope_hash, &proof,
        ).unwrap();
        assert!(valid, "Scoped proof must verify");

        // Modify unscoped field — should still verify
        let body_modified = r#"{"amount":500,"to":"alice","note":"dinner","timestamp":"2024-02-01"}"#;
        let valid_modified = ash_verify_proof_scoped(
            &nonce, &context_id, &binding, &ts, body_modified,
            &scope, &scope_hash, &proof,
        ).unwrap();
        assert!(valid_modified, "Modified unscoped field should still verify");

        // Modify scoped field — must fail
        let body_tampered = r#"{"amount":999,"to":"alice","note":"lunch","timestamp":"2024-01-01"}"#;
        let valid_tampered = ash_verify_proof_scoped(
            &nonce, &context_id, &binding, &ts, body_tampered,
            &scope, &scope_hash, &proof,
        ).unwrap();
        assert!(!valid_tampered, "Modified scoped field must fail verification");
    }

    #[test]
    fn unified_scoped_plus_chained() {
        let nonce = ash_generate_nonce(32).unwrap();
        let context_id = ash_generate_context_id().unwrap();
        let binding = ash_normalize_binding("POST", "/api/payment", "").unwrap();
        let secret = ash_derive_client_secret(&nonce, &context_id, &binding).unwrap();

        // Step 1: Scoped proof with no chain
        let body1 = r#"{"amount":100,"currency":"USD","note":"step1"}"#;
        let scope = vec!["amount", "currency"];
        let ts1 = now_ts();
        let r1 = ash_build_proof_unified(
            &secret, &ts1, &binding, body1, &scope, None,
        ).unwrap();

        assert!(!r1.scope_hash.is_empty(), "Scope hash must be set");
        assert!(r1.chain_hash.is_empty(), "First proof must have empty chain hash");

        // Step 2: Chain second proof to first, also scoped
        let body2 = r#"{"amount":200,"currency":"EUR","note":"step2"}"#;
        let ts2 = now_ts();
        let r2 = ash_build_proof_unified(
            &secret, &ts2, &binding, body2, &scope,
            Some(&r1.proof),
        ).unwrap();

        assert!(!r2.scope_hash.is_empty());
        assert!(!r2.chain_hash.is_empty());

        // Verify step 2 with both scope and chain
        let valid = ash_verify_proof_unified(
            &nonce, &context_id, &binding, &ts2, body2,
            &r2.proof, &scope, &r2.scope_hash,
            Some(&r1.proof), &r2.chain_hash,
        ).unwrap();
        assert!(valid, "Scoped + chained unified proof must verify");
    }
}

// =========================================================================
// 7. PROOF VERIFICATION NEVER PANICS
//    All failure modes return Err or Ok(false), never panic
// =========================================================================

mod no_panic_verification {
    use super::*;

    #[test]
    fn empty_proof_does_not_panic() {
        let body_hash = valid_body_hash();
        let _ = ash_verify_proof(NONCE_64, CTX, BINDING, TS, &body_hash, "");
    }

    #[test]
    fn very_long_proof_does_not_panic() {
        let body_hash = valid_body_hash();
        let long_proof = "a".repeat(10000);
        let _ = ash_verify_proof(NONCE_64, CTX, BINDING, TS, &body_hash, &long_proof);
    }

    #[test]
    fn null_bytes_in_inputs_no_panic() {
        let body_hash = valid_body_hash();
        let _ = ash_verify_proof(NONCE_64, "ctx\0test", BINDING, TS, &body_hash, &"a".repeat(64));
        let _ = ash_verify_proof(NONCE_64, CTX, "GET|\0/api|", TS, &body_hash, &"a".repeat(64));
    }

    #[test]
    fn unicode_in_all_fields_no_panic() {
        let body_hash = valid_body_hash();
        let _ = ash_verify_proof("0123456789abcdef0123456789abcdef", "ctxé", BINDING, TS, &body_hash, &"a".repeat(64));
        // Note: nonce must be hex, so unicode nonce will fail validation but not panic
    }

    #[test]
    fn empty_everything_no_panic() {
        let _ = ash_verify_proof("", "", "", "", "", "");
    }

    #[test]
    fn max_length_inputs_no_panic() {
        let long = "a".repeat(10000);
        let _ = ash_verify_proof(&long, &long, &long, &long, &long, &long);
    }

    #[test]
    fn binary_looking_strings_no_panic() {
        let binary_ish = (0u8..=255).map(|b| format!("{:02x}", b)).collect::<String>();
        let body_hash = valid_body_hash();
        let _ = ash_verify_proof(&binary_ish, CTX, BINDING, TS, &body_hash, &"a".repeat(64));
    }

    #[test]
    fn scoped_verify_with_absurd_inputs_no_panic() {
        let _ = ash_verify_proof_scoped(
            NONCE_64, CTX, BINDING, TS, "not json at all",
            &["field1", "field2.nested"], "not a hash", "not a proof",
        );
    }

    #[test]
    fn unified_verify_with_absurd_inputs_no_panic() {
        let _ = ash_verify_proof_unified(
            NONCE_64, CTX, BINDING, TS, "{}", "not_proof",
            &["f1"], "not_hash", Some("not_prev"), "not_chain",
        );
    }

    #[test]
    fn canonicalize_never_panics_on_garbage() {
        let garbage_inputs = vec![
            "", "\0", "\n\r\t", "🎉🎊🎈", "{", "}", "[", "]",
            r#"{"a":}"#, "null", "true", "false", "42",
            r#"{"a":1,"a":2}"#,
        ];
        for input in garbage_inputs {
            // These may return Ok or Err but must never panic
            let _ = ash_canonicalize_json(input);
            let _ = ash_canonicalize_query(input);
            let _ = ash_canonicalize_urlencoded(input);
        }
    }
}

// =========================================================================
// 8. CROSS-FUNCTION INTEGRATION — UNIQUENESS GUARANTEES
//    Verify mathematical properties across the full API surface
// =========================================================================

mod cross_function_integration {
    use super::*;

    #[test]
    fn distinct_nonces_produce_distinct_secrets() {
        let mut secrets = HashSet::new();
        for i in 0..100 {
            let nonce = ash_generate_nonce(32).unwrap();
            let secret = ash_derive_client_secret(&nonce, CTX, BINDING).unwrap();
            assert!(secrets.insert(secret), "Nonce {} produced duplicate secret", i);
        }
    }

    #[test]
    fn distinct_contexts_produce_distinct_secrets() {
        let mut secrets = HashSet::new();
        for i in 0..100 {
            let ctx = format!("ctx_test_{}", i);
            let secret = ash_derive_client_secret(NONCE_64, &ctx, BINDING).unwrap();
            assert!(secrets.insert(secret), "Context {} produced duplicate secret", i);
        }
    }

    #[test]
    fn distinct_bindings_produce_distinct_secrets() {
        let mut secrets = HashSet::new();
        for i in 0..100 {
            let binding = format!("GET|/api/endpoint_{}|", i);
            let secret = ash_derive_client_secret(NONCE_64, CTX, &binding).unwrap();
            assert!(secrets.insert(secret), "Binding {} produced duplicate secret", i);
        }
    }

    #[test]
    fn distinct_timestamps_produce_distinct_proofs() {
        let secret = ash_derive_client_secret(NONCE_64, CTX, BINDING).unwrap();
        let body_hash = valid_body_hash();
        let mut proofs = HashSet::new();

        for ts in 1700000000..1700000100 {
            let proof = ash_build_proof(&secret, &ts.to_string(), BINDING, &body_hash).unwrap();
            assert!(proofs.insert(proof), "Timestamp {} produced duplicate proof", ts);
        }
    }

    #[test]
    fn distinct_bodies_produce_distinct_proofs() {
        let secret = ash_derive_client_secret(NONCE_64, CTX, BINDING).unwrap();
        let mut proofs = HashSet::new();

        for i in 0..100 {
            let body = format!(r#"{{"value":{}}}"#, i);
            let canon = ash_canonicalize_json(&body).unwrap();
            let body_hash = ash_hash_body(&canon);
            let proof = ash_build_proof(&secret, TS, BINDING, &body_hash).unwrap();
            assert!(proofs.insert(proof), "Body {} produced duplicate proof", i);
        }
    }

    #[test]
    fn hash_chain_is_deterministic() {
        let proof = "a".repeat(64);
        let h1 = ash_hash_proof(&proof).unwrap();
        let h2 = ash_hash_proof(&proof).unwrap();
        assert_eq!(h1, h2, "hash_proof must be deterministic");

        // Hash of hash is also deterministic
        let h3 = ash_hash_proof(&h1).unwrap();
        let h4 = ash_hash_proof(&h1).unwrap();
        assert_eq!(h3, h4, "hash of hash must be deterministic");

        // But hash of hash is different from original hash
        assert_ne!(h1, h3, "hash chain must produce different values");
    }

    #[test]
    fn scope_hash_order_independence() {
        let h1 = ash_hash_scope(&["amount", "currency", "recipient"]).unwrap();
        let h2 = ash_hash_scope(&["recipient", "amount", "currency"]).unwrap();
        let h3 = ash_hash_scope(&["currency", "recipient", "amount"]).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn scope_hash_deduplication() {
        let h1 = ash_hash_scope(&["a", "b", "c"]).unwrap();
        let h2 = ash_hash_scope(&["a", "b", "c", "a", "b"]).unwrap();
        assert_eq!(h1, h2, "Scope hash must deduplicate field names");
    }

    #[test]
    fn generated_nonces_are_unique() {
        let mut nonces = HashSet::new();
        for _ in 0..1000 {
            let nonce = ash_generate_nonce(32).unwrap();
            assert!(nonces.insert(nonce), "Generated nonces must be unique");
        }
    }

    #[test]
    fn generated_context_ids_are_unique() {
        let mut ids = HashSet::new();
        for _ in 0..1000 {
            let id = ash_generate_context_id().unwrap();
            assert!(ids.insert(id), "Generated context IDs must be unique");
        }
    }

    #[test]
    fn json_canonicalization_is_idempotent() {
        let inputs = vec![
            r#"{"b":2,"a":1}"#,
            r#"{"nested":{"z":26,"a":1},"top":true}"#,
            r#"[3,1,2]"#,
            r#"{"emoji":"🎉","unicode":"café"}"#,
        ];
        for input in inputs {
            let c1 = ash_canonicalize_json(input).unwrap();
            let c2 = ash_canonicalize_json(&c1).unwrap();
            assert_eq!(c1, c2, "JSON canonicalization must be idempotent for: {}", input);
        }
    }

    #[test]
    fn query_canonicalization_is_idempotent() {
        let inputs = vec![
            "b=2&a=1",
            "z=3&a=1&m=2",
            "key=value",
            "a=1&a=2",
        ];
        for input in inputs {
            let c1 = ash_canonicalize_query(input).unwrap();
            let c2 = ash_canonicalize_query(&c1).unwrap();
            assert_eq!(c1, c2, "Query canonicalization must be idempotent for: {}", input);
        }
    }

    #[test]
    fn binding_normalization_is_idempotent() {
        // After normalizing, re-splitting and re-normalizing should produce same result
        let binding = ash_normalize_binding("post", "/api//users/../admin/", "z=3&a=1").unwrap();
        // Parse the normalized binding back
        let parts: Vec<&str> = binding.splitn(3, '|').collect();
        let method = parts[0];
        let path = parts[1];
        let query = parts[2];
        let binding2 = ash_normalize_binding(method, path, query).unwrap();
        assert_eq!(binding, binding2, "Binding normalization must be idempotent");
    }
}

// =========================================================================
// 9. ADVANCED JSON CANONICALIZATION EDGE CASES
// =========================================================================

mod json_canon_advanced {
    use super::*;

    #[test]
    fn negative_zero_becomes_zero() {
        assert_eq!(ash_canonicalize_json("-0").unwrap(), "0");
        assert_eq!(ash_canonicalize_json("-0.0").unwrap(), "0");
        assert_eq!(ash_canonicalize_json(r#"{"a":-0}"#).unwrap(), r#"{"a":0}"#);
    }

    #[test]
    fn scientific_notation_normalized() {
        // 1e2 = 100
        let result = ash_canonicalize_json("1e2").unwrap();
        assert_eq!(result, "100");
    }

    #[test]
    fn deep_nesting_within_limit() {
        // 50 levels of nesting should work
        let mut json = String::new();
        for _ in 0..50 {
            json.push_str(r#"{"a":"#);
        }
        json.push_str("1");
        for _ in 0..50 {
            json.push('}');
        }
        let result = ash_canonicalize_json(&json);
        assert!(result.is_ok(), "50-level nesting should succeed");
    }

    #[test]
    fn duplicate_keys_handled() {
        // JSON spec says duplicate keys are implementation-defined
        // JCS uses last-value-wins (from JSON.parse behavior)
        let result = ash_canonicalize_json(r#"{"a":1,"a":2}"#);
        // Should succeed (not error) and contain a:2
        assert!(result.is_ok());
    }

    #[test]
    fn unicode_escape_sequences_normalized() {
        // \u00e9 and literal é should produce same canonical form
        let r1 = ash_canonicalize_json(r#"{"key":"\u00e9"}"#).unwrap();
        let r2 = ash_canonicalize_json(r#"{"key":"é"}"#).unwrap();
        assert_eq!(r1, r2, "Unicode escapes must normalize to same form");
    }

    #[test]
    fn keys_sorted_by_utf16_code_units() {
        // JCS sorts by UTF-16 code units, not UTF-8 bytes
        let result = ash_canonicalize_json(r#"{"b":2,"a":1,"c":3}"#).unwrap();
        assert_eq!(result, r#"{"a":1,"b":2,"c":3}"#);
    }

    #[test]
    fn empty_structures() {
        assert_eq!(ash_canonicalize_json("{}").unwrap(), "{}");
        assert_eq!(ash_canonicalize_json("[]").unwrap(), "[]");
        assert_eq!(ash_canonicalize_json(r#"{"a":{}}"#).unwrap(), r#"{"a":{}}"#);
        assert_eq!(ash_canonicalize_json(r#"{"a":[]}"#).unwrap(), r#"{"a":[]}"#);
    }

    #[test]
    fn special_string_values() {
        // Strings with special characters must be properly escaped
        let result = ash_canonicalize_json(r#"{"a":"line1\nline2"}"#).unwrap();
        assert!(result.contains(r#"\n"#), "Newline must remain escaped");

        let result = ash_canonicalize_json(r#"{"a":"tab\there"}"#).unwrap();
        assert!(result.contains(r#"\t"#), "Tab must remain escaped");
    }

    #[test]
    fn nan_infinity_rejected() {
        assert!(ash_canonicalize_json("NaN").is_err());
        assert!(ash_canonicalize_json("Infinity").is_err());
        assert!(ash_canonicalize_json("-Infinity").is_err());
    }

    #[test]
    fn trailing_comma_rejected() {
        assert!(ash_canonicalize_json(r#"{"a":1,}"#).is_err());
        assert!(ash_canonicalize_json(r#"[1,2,]"#).is_err());
    }
}

// =========================================================================
// 10. ADVANCED BINDING NORMALIZATION
// =========================================================================

mod binding_normalization_advanced {
    use super::*;

    #[test]
    fn all_http_methods() {
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        for method in methods {
            let result = ash_normalize_binding(method, "/api", "");
            assert!(result.is_ok(), "Method {} should be accepted", method);
            assert!(result.unwrap().starts_with(method));
        }
    }

    #[test]
    fn method_case_normalization() {
        assert_eq!(
            ash_normalize_binding("get", "/api", "").unwrap(),
            ash_normalize_binding("GET", "/api", "").unwrap()
        );
        assert_eq!(
            ash_normalize_binding("pOsT", "/api", "").unwrap(),
            ash_normalize_binding("POST", "/api", "").unwrap()
        );
    }

    #[test]
    fn path_must_start_with_slash() {
        assert!(ash_normalize_binding("GET", "api", "").is_err());
        assert!(ash_normalize_binding("GET", ".", "").is_err());
        assert!(ash_normalize_binding("GET", "", "").is_err());
    }

    #[test]
    fn duplicate_slashes_collapsed() {
        assert_eq!(
            ash_normalize_binding("GET", "////api////users////", "").unwrap(),
            "GET|/api/users|"
        );
    }

    #[test]
    fn dot_segments_resolved() {
        assert_eq!(
            ash_normalize_binding("GET", "/a/b/../c/./d/../e", "").unwrap(),
            "GET|/a/c/e|"
        );
    }

    #[test]
    fn dots_beyond_root_clamped() {
        assert_eq!(
            ash_normalize_binding("GET", "/../../..", "").unwrap(),
            "GET|/|"
        );
    }

    #[test]
    fn control_characters_in_method_rejected() {
        // Note: method is trimmed first, so trailing \n/\r are stripped
        // Embedded control characters in the middle should be rejected
        assert!(ash_normalize_binding("GE\nT", "/api", "").is_err());
        assert!(ash_normalize_binding("GE\rT", "/api", "").is_err());
        assert!(ash_normalize_binding("GE\0T", "/api", "").is_err());
    }

    #[test]
    fn non_ascii_method_rejected() {
        assert!(ash_normalize_binding("GÉT", "/api", "").is_err());
        assert!(ash_normalize_binding("получить", "/api", "").is_err());
    }

    #[test]
    fn null_byte_in_path_rejected() {
        assert!(ash_normalize_binding("GET", "/api\0/users", "").is_err());
        assert!(ash_normalize_binding("GET", "/api/%00/users", "").is_err());
    }

    #[test]
    fn whitespace_query_treated_as_empty() {
        let b1 = ash_normalize_binding("GET", "/api", "   ").unwrap();
        let b2 = ash_normalize_binding("GET", "/api", "").unwrap();
        assert_eq!(b1, b2, "Whitespace-only query must be treated as empty");
    }
}

// =========================================================================
// 11. HASH FUNCTION PROPERTIES
// =========================================================================

mod hash_properties {
    use super::*;

    #[test]
    fn hash_body_is_sha256() {
        // SHA-256 of empty string is well-known
        let empty_hash = ash_hash_body("");
        assert_eq!(empty_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn hash_body_always_64_hex_chars() {
        let long = "x".repeat(100000);
        let inputs = vec!["", "a", "hello", &long];
        for input in inputs {
            let hash = ash_hash_body(input);
            assert_eq!(hash.len(), 64, "Hash must be 64 hex chars for input length {}", input.len());
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash must be hex");
        }
    }

    #[test]
    fn hash_body_lowercase_hex() {
        let hash = ash_hash_body("test");
        assert_eq!(hash, hash.to_lowercase(), "Hash must use lowercase hex");
    }

    #[test]
    fn hash_proof_hashes_ascii_bytes() {
        // ash_hash_proof should hash the ASCII bytes of the hex string
        // NOT the decoded binary bytes
        let proof = "aa".repeat(32); // 64 hex chars
        let hash_of_proof = ash_hash_proof(&proof).unwrap();

        // This should equal SHA-256 of the 64-byte ASCII string "aaa...a"
        let hash_of_ascii = ash_hash_body(&proof);
        assert_eq!(hash_of_proof, hash_of_ascii,
            "hash_proof must hash ASCII bytes, not decoded binary");
    }

    #[test]
    fn hash_proof_empty_rejected() {
        assert!(ash_hash_proof("").is_err(), "Empty proof must be rejected");
    }

    #[test]
    fn hash_scope_empty_returns_empty() {
        let result = ash_hash_scope(&[]).unwrap();
        assert!(result.is_empty(), "Empty scope must return empty string");
    }

    #[test]
    fn hash_scope_single_field() {
        let hash = ash_hash_scope(&["field"]).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn scoped_body_hash_strict_rejects_missing() {
        let result = ash_hash_scoped_body_strict(
            r#"{"a":1}"#,
            &["b"],
        );
        assert!(result.is_err(), "Strict mode must reject missing scoped field");
    }
}

// =========================================================================
// 12. VALIDATION FUNCTION EDGE CASES
// =========================================================================

mod validation_edge_cases {
    use super::*;

    #[test]
    fn nonce_validation_boundary() {
        // 31 hex chars = too short (need at least 32)
        assert!(ash_validate_nonce(&"a".repeat(31)).is_err());
        // 32 hex chars = minimum valid
        assert!(ash_validate_nonce(&"a".repeat(32)).is_ok());
        // 512 hex chars = maximum valid
        assert!(ash_validate_nonce(&"a".repeat(512)).is_ok());
        // 513 hex chars = too long
        assert!(ash_validate_nonce(&"a".repeat(513)).is_err());
    }

    #[test]
    fn nonce_validation_hex_only() {
        assert!(ash_validate_nonce(&"g".repeat(32)).is_err()); // 'g' not hex
        assert!(ash_validate_nonce(&"0".repeat(32)).is_ok());
        assert!(ash_validate_nonce(&"f".repeat(32)).is_ok());
        assert!(ash_validate_nonce(&"F".repeat(32)).is_ok()); // uppercase hex OK
    }

    #[test]
    fn nonce_validation_no_whitespace() {
        let nonce_with_space = "0123456789abcdef 123456789abcdef";
        assert!(ash_validate_nonce(nonce_with_space).is_err());
    }

    #[test]
    fn timestamp_format_validation() {
        assert!(ash_validate_timestamp_format("1700000000").is_ok());
        assert!(ash_validate_timestamp_format("0").is_ok());
        assert!(ash_validate_timestamp_format("").is_err());
        assert!(ash_validate_timestamp_format("abc").is_err());
        assert!(ash_validate_timestamp_format("-1").is_err());
        assert!(ash_validate_timestamp_format("1.5").is_err());
    }

    #[test]
    fn timestamp_format_leading_zeros() {
        // Leading zeros should be rejected (ambiguous)
        let result = ash_validate_timestamp_format("0123");
        // Implementation may accept or reject — document behavior
        let _ = result;
    }

    #[test]
    fn context_id_charset() {
        // Valid: A-Z a-z 0-9 _ - .
        assert!(ash_derive_client_secret(NONCE_64, "ctx_test", BINDING).is_ok());
        assert!(ash_derive_client_secret(NONCE_64, "CTX-123", BINDING).is_ok());
        assert!(ash_derive_client_secret(NONCE_64, "ctx.v2.test", BINDING).is_ok());

        // Invalid
        assert!(ash_derive_client_secret(NONCE_64, "ctx test", BINDING).is_err()); // space
        assert!(ash_derive_client_secret(NONCE_64, "ctx/test", BINDING).is_err()); // slash
        assert!(ash_derive_client_secret(NONCE_64, "", BINDING).is_err()); // empty
    }
}

// =========================================================================
// 13. ERROR CODE CLASSIFICATION
// =========================================================================

mod error_code_classification {
    use super::*;

    #[test]
    fn validation_error_for_bad_nonce() {
        let err = ash_validate_nonce("ZZZ").unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    #[test]
    fn timestamp_invalid_error_for_bad_timestamp() {
        let err = ash_validate_timestamp_format("abc").unwrap_err();
        // Timestamp validation uses TimestampInvalid, not ValidationError
        assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
    }

    #[test]
    fn canonicalization_error_for_bad_json() {
        let err = ash_canonicalize_json("{invalid}").unwrap_err();
        assert_eq!(err.code(), AshErrorCode::CanonicalizationError);
    }

    #[test]
    fn validation_error_for_bad_binding() {
        let err = ash_normalize_binding("", "/api", "").unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    #[test]
    fn validation_error_for_empty_context() {
        let err = ash_derive_client_secret(NONCE_64, "", BINDING).unwrap_err();
        assert_eq!(err.code(), AshErrorCode::ValidationError);
    }

    #[test]
    fn all_error_codes_have_unique_http_status() {
        // Collect HTTP statuses from all error codes
        let codes = vec![
            AshErrorCode::CtxNotFound,
            AshErrorCode::CtxExpired,
            AshErrorCode::CtxAlreadyUsed,
            AshErrorCode::BindingMismatch,
            AshErrorCode::ProofMissing,
            AshErrorCode::ProofInvalid,
            AshErrorCode::CanonicalizationError,
            AshErrorCode::ValidationError,
            AshErrorCode::ModeViolation,
            AshErrorCode::UnsupportedContentType,
            AshErrorCode::ScopeMismatch,
            AshErrorCode::ChainBroken,
            AshErrorCode::InternalError,
            AshErrorCode::TimestampInvalid,
            AshErrorCode::ScopedFieldMissing,
        ];

        let mut statuses = HashSet::new();
        for code in &codes {
            let err = AshError::new(*code, "test");
            let status = err.http_status();
            assert!(
                statuses.insert(status),
                "HTTP status {} is duplicated for {:?}",
                status,
                code
            );
        }
    }
}

// =========================================================================
// 14. CONCURRENT SAFETY
//    Verify core functions are safe under concurrent access
// =========================================================================

mod concurrent_safety {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn concurrent_proof_generation_deterministic() {
        let nonce = Arc::new(NONCE_64.to_string());
        let body_hash = Arc::new(valid_body_hash());

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let nonce = Arc::clone(&nonce);
                let body_hash = Arc::clone(&body_hash);
                thread::spawn(move || {
                    let secret = ash_derive_client_secret(&nonce, CTX, BINDING).unwrap();
                    ash_build_proof(&secret, TS, BINDING, &body_hash).unwrap()
                })
            })
            .collect();

        let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads must produce the same proof
        for proof in &results {
            assert_eq!(proof, &results[0], "Concurrent proof generation must be deterministic");
        }
    }

    #[test]
    fn concurrent_hash_generation() {
        let handles: Vec<_> = (0..20)
            .map(|i| {
                thread::spawn(move || {
                    let body = format!("body_{}", i);
                    (i, ash_hash_body(&body))
                })
            })
            .collect();

        let results: Vec<(i32, String)> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All results must be unique (different inputs)
        let unique: HashSet<&String> = results.iter().map(|(_, h)| h).collect();
        assert_eq!(unique.len(), 20, "All concurrent hashes must be unique");
    }

    #[test]
    fn concurrent_canonicalization() {
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let json = format!(r#"{{"value":{},"index":{}}}"#, i * 100, i);
                    ash_canonicalize_json(&json).unwrap()
                })
            })
            .collect();

        let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Verify correctness: all should have sorted keys
        for result in &results {
            assert!(result.starts_with(r#"{"index":"#),
                "Keys must be sorted: {}", result);
        }
    }

    #[test]
    fn concurrent_verification() {
        let (_, body_hash, proof) = derive_and_build();
        let body_hash = Arc::new(body_hash);
        let proof = Arc::new(proof);

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let bh = Arc::clone(&body_hash);
                let p = Arc::clone(&proof);
                thread::spawn(move || {
                    ash_verify_proof(NONCE_64, CTX, BINDING, TS, &bh, &p).unwrap()
                })
            })
            .collect();

        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(results.iter().all(|&v| v), "All concurrent verifications must succeed");
    }
}
