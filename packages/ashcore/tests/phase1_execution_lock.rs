//! Phase 1.5 — Execution Lock Tests
//!
//! These tests lock the behavior of Phase 1 primitives to prevent
//! regressions before building Phase 3 (high-level verify/build).
//!
//! Three categories:
//! 1. Header precedence is deterministic
//! 2. InternalReason mapping is stable
//! 3. Header extraction is insertion-order independent

use ashcore::headers::{ash_extract_headers, HeaderMapView};
use ashcore::{AshErrorCode, InternalReason, ash_validate_nonce, ash_validate_timestamp_format};

// ── Test HeaderMapView impl ──────────────────────────────────────────

struct TestHeaders(Vec<(String, String)>);

impl HeaderMapView for TestHeaders {
    fn get_all_ci(&self, name: &str) -> Vec<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.0
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

// =========================================================================
// 1. Header Precedence Tests (deterministic error ordering)
// =========================================================================

#[test]
fn precedence_missing_ts_before_invalid_nonce() {
    // Missing timestamp + bad nonce → timestamp error comes first
    let h = TestHeaders(vec![
        // no x-ash-ts
        ("x-ash-nonce".into(), "too_short".into()),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.reason(), InternalReason::HdrMissing);
    assert!(err.details().unwrap().get("header").unwrap().contains("ts"));
}

#[test]
fn precedence_missing_ts_before_missing_nonce() {
    // Missing both ts and nonce → ts error first (extraction order)
    let h = TestHeaders(vec![
        // no x-ash-ts
        // no x-ash-nonce
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.reason(), InternalReason::HdrMissing);
    assert!(err.details().unwrap().get("header").unwrap().contains("ts"));
}

#[test]
fn precedence_missing_nonce_before_missing_body_hash() {
    // Present ts, missing nonce + missing body-hash → nonce error first
    let h = TestHeaders(vec![
        ("x-ash-ts".into(), "1700000000".into()),
        // no x-ash-nonce
        // no x-ash-body-hash
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.reason(), InternalReason::HdrMissing);
    assert!(err.details().unwrap().get("header").unwrap().contains("nonce"));
}

#[test]
fn precedence_missing_body_hash_before_missing_proof() {
    // Present ts + nonce, missing body-hash + proof → body-hash first
    let h = TestHeaders(vec![
        ("x-ash-ts".into(), "1700000000".into()),
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        // no x-ash-body-hash
        // no x-ash-proof
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.reason(), InternalReason::HdrMissing);
    assert!(err.details().unwrap().get("header").unwrap().contains("body-hash"));
}

// =========================================================================
// 2. InternalReason Mapping Stability
// =========================================================================

#[test]
fn reason_hdr_missing_maps_to_validation_485() {
    let h = TestHeaders(vec![
        // no x-ash-ts
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.http_status(), 485);
    assert_eq!(err.reason(), InternalReason::HdrMissing);
}

#[test]
fn reason_hdr_multi_maps_to_validation_485() {
    let h = TestHeaders(vec![
        ("x-ash-ts".into(), "1700000000".into()),
        ("x-ash-ts".into(), "1700000001".into()), // duplicate
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.http_status(), 485);
    assert_eq!(err.reason(), InternalReason::HdrMultiValue);
}

#[test]
fn reason_hdr_invalid_chars_maps_to_validation_485() {
    let h = TestHeaders(vec![
        ("x-ash-ts".into(), "1700\n000000".into()), // control char
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);
    let err = ash_extract_headers(&h).unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.http_status(), 485);
    assert_eq!(err.reason(), InternalReason::HdrInvalidChars);
}

#[test]
fn reason_nonce_too_short_maps_to_validation_485() {
    let err = ash_validate_nonce("abcdef").unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.http_status(), 485);
    assert_eq!(err.reason(), InternalReason::NonceTooShort);
}

#[test]
fn reason_nonce_too_long_maps_to_validation_485() {
    let err = ash_validate_nonce(&"a".repeat(513)).unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.http_status(), 485);
    assert_eq!(err.reason(), InternalReason::NonceTooLong);
}

#[test]
fn reason_nonce_invalid_chars_maps_to_validation_485() {
    let err = ash_validate_nonce(&format!("{}XY", "a".repeat(30))).unwrap_err();
    assert_eq!(err.code(), AshErrorCode::ValidationError);
    assert_eq!(err.http_status(), 485);
    assert_eq!(err.reason(), InternalReason::NonceInvalidChars);
}

#[test]
fn reason_ts_parse_maps_to_timestamp_482() {
    let err = ash_validate_timestamp_format("not_a_number").unwrap_err();
    assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
    assert_eq!(err.http_status(), 482);
}

#[test]
fn reason_ts_leading_zeros_maps_to_timestamp_482() {
    let err = ash_validate_timestamp_format("0123456789").unwrap_err();
    assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
    assert_eq!(err.http_status(), 482);
}

#[test]
fn reason_ts_empty_maps_to_timestamp_482() {
    let err = ash_validate_timestamp_format("").unwrap_err();
    assert_eq!(err.code(), AshErrorCode::TimestampInvalid);
    assert_eq!(err.http_status(), 482);
}

// =========================================================================
// 3. Insertion Order Independence
// =========================================================================

#[test]
fn headers_order_does_not_matter() {
    // Normal order
    let h1 = TestHeaders(vec![
        ("x-ash-ts".into(), "1700000000".into()),
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-proof".into(), "b".repeat(64)),
    ]);

    // Reversed order
    let h2 = TestHeaders(vec![
        ("x-ash-proof".into(), "b".repeat(64)),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ash-ts".into(), "1700000000".into()),
    ]);

    // Scrambled order
    let h3 = TestHeaders(vec![
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-ts".into(), "1700000000".into()),
        ("x-ash-proof".into(), "b".repeat(64)),
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
    ]);

    let b1 = ash_extract_headers(&h1).unwrap();
    let b2 = ash_extract_headers(&h2).unwrap();
    let b3 = ash_extract_headers(&h3).unwrap();

    assert_eq!(b1.ts, b2.ts);
    assert_eq!(b2.ts, b3.ts);
    assert_eq!(b1.nonce, b2.nonce);
    assert_eq!(b2.nonce, b3.nonce);
    assert_eq!(b1.body_hash, b2.body_hash);
    assert_eq!(b2.body_hash, b3.body_hash);
    assert_eq!(b1.proof, b2.proof);
    assert_eq!(b2.proof, b3.proof);
}

#[test]
fn headers_mixed_case_all_orders() {
    // Different casing + scrambled order should produce same bundle
    let h1 = TestHeaders(vec![
        ("X-ASH-TS".into(), "1700000000".into()),
        ("X-Ash-Nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ASH-BODY-HASH".into(), "a".repeat(64)),
        ("x-ash-PROOF".into(), "b".repeat(64)),
    ]);

    let h2 = TestHeaders(vec![
        ("x-ash-proof".into(), "b".repeat(64)),
        ("x-ash-body-hash".into(), "a".repeat(64)),
        ("x-ash-nonce".into(), "0123456789abcdef0123456789abcdef".into()),
        ("x-ash-ts".into(), "1700000000".into()),
    ]);

    let b1 = ash_extract_headers(&h1).unwrap();
    let b2 = ash_extract_headers(&h2).unwrap();
    assert_eq!(b1.ts, b2.ts);
    assert_eq!(b1.nonce, b2.nonce);
}

// =========================================================================
// 4. Nonce validation consistency with ash_derive_client_secret
// =========================================================================

#[test]
fn nonce_validator_matches_derive_behavior() {
    // Valid nonce should work in both paths
    let nonce = "0123456789abcdef0123456789abcdef";
    assert!(ash_validate_nonce(nonce).is_ok());
    assert!(ashcore::ash_derive_client_secret(nonce, "ctx_test", "POST|/api|").is_ok());
}

#[test]
fn nonce_validator_rejects_same_as_derive() {
    // Invalid nonce should fail in both paths
    let short_nonce = "abcdef";
    assert!(ash_validate_nonce(short_nonce).is_err());
    assert!(ashcore::ash_derive_client_secret(short_nonce, "ctx_test", "POST|/api|").is_err());

    let bad_chars = "0123456789abcdef0123456789abcdXY";
    assert!(ash_validate_nonce(bad_chars).is_err());
    assert!(ashcore::ash_derive_client_secret(bad_chars, "ctx_test", "POST|/api|").is_err());
}
