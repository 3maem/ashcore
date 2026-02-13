//! Phase 3 — Build↔Verify Round-trip Integration Tests
//!
//! These tests prove that `build_request_proof()` and `verify_incoming_request()`
//! are perfectly symmetric: what one builds, the other accepts.
//!
//! This is the core contract: SDKs that use `build_request_proof` on the client
//! will always pass `verify_incoming_request` on the server, given correct inputs.

use ashcore::build::{build_request_proof, BuildRequestInput};
use ashcore::headers::HeaderMapView;
use ashcore::verify::{verify_incoming_request, VerifyRequestInput};

struct TestHeaders(Vec<(String, String)>);

impl HeaderMapView for TestHeaders {
    fn get_all_ci(&self, name: &str) -> Vec<&str> {
        let n = name.to_ascii_lowercase();
        self.0
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == n)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

// =========================================================================
// 1. Basic round-trip (no scope, no chain)
// =========================================================================

#[test]
fn roundtrip_basic_post() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let context_id = "ctx_roundtrip_basic";
    let body = r#"{"amount":100,"recipient":"alice"}"#;
    let ts = now_ts();

    let built = build_request_proof(&BuildRequestInput {
        method: "POST",
        path: "/api/transfer",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "POST",
        path: "/api/transfer",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(result.ok, "Basic round-trip failed: {:?}", result.error);
}

#[test]
fn roundtrip_get_with_query() {
    let nonce = "abcdef0123456789abcdef0123456789";
    let context_id = "ctx_roundtrip_query";
    let body = "";
    let ts = now_ts();

    let built = build_request_proof(&BuildRequestInput {
        method: "GET",
        path: "/api/search",
        raw_query: "z=3&a=1&b=2",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    // Server uses the same raw query — binding normalization handles sorting
    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "GET",
        path: "/api/search",
        raw_query: "z=3&a=1&b=2",
        canonical_body: body,
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(result.ok, "Query round-trip failed: {:?}", result.error);
}

// =========================================================================
// 2. Method/path normalization symmetry
// =========================================================================

#[test]
fn roundtrip_method_case_normalization() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let context_id = "ctx_method_case";
    let body = "{}";
    let ts = now_ts();

    // Client uses lowercase method
    let built = build_request_proof(&BuildRequestInput {
        method: "post",
        path: "/api/data",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    // Server uses uppercase method — both should normalize to POST
    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "POST",
        path: "/api/data",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(result.ok, "Method case round-trip failed: {:?}", result.error);
}

#[test]
fn roundtrip_path_normalization() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let context_id = "ctx_path_norm";
    let body = "{}";
    let ts = now_ts();

    // Client sends path with trailing slash and duplicate slashes
    let built = build_request_proof(&BuildRequestInput {
        method: "GET",
        path: "/api//users/",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    // Server uses the same unnormalized path — both normalize identically
    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "GET",
        path: "/api//users/",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(result.ok, "Path normalization round-trip failed: {:?}", result.error);
}

// =========================================================================
// 3. Tamper detection (build valid, then tamper before verify)
// =========================================================================

#[test]
fn roundtrip_tampered_body_rejected() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let context_id = "ctx_tamper_body";
    let body = r#"{"amount":100}"#;
    let ts = now_ts();

    let built = build_request_proof(&BuildRequestInput {
        method: "POST",
        path: "/api/transfer",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    // Tamper: change body
    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "POST",
        path: "/api/transfer",
        raw_query: "",
        canonical_body: r#"{"amount":999}"#, // tampered
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(!result.ok, "Tampered body should be rejected");
}

#[test]
fn roundtrip_tampered_proof_rejected() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let context_id = "ctx_tamper_proof";
    let body = r#"{"amount":100}"#;
    let ts = now_ts();

    let built = build_request_proof(&BuildRequestInput {
        method: "POST",
        path: "/api/transfer",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), "f".repeat(64)), // tampered proof
    ]);

    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "POST",
        path: "/api/transfer",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(!result.ok, "Tampered proof should be rejected");
}

#[test]
fn roundtrip_wrong_context_rejected() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let body = r#"{"data":"test"}"#;
    let ts = now_ts();

    let built = build_request_proof(&BuildRequestInput {
        method: "POST",
        path: "/api/test",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id: "ctx_original",
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    // Server uses different context_id
    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "POST",
        path: "/api/test",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id: "ctx_different", // wrong context
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(!result.ok, "Wrong context should be rejected");
}

// =========================================================================
// 4. Empty body round-trip
// =========================================================================

#[test]
fn roundtrip_empty_body() {
    let nonce = "0123456789abcdef0123456789abcdef";
    let context_id = "ctx_empty_body";
    let body = "";
    let ts = now_ts();

    let built = build_request_proof(&BuildRequestInput {
        method: "DELETE",
        path: "/api/resource/123",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        timestamp: &ts,
        scope: None,
        previous_proof: None,
    })
    .unwrap();

    let headers = TestHeaders(vec![
        ("x-ash-ts".into(), built.timestamp.clone()),
        ("x-ash-body-hash".into(), built.body_hash.clone()),
        ("x-ash-proof".into(), built.proof.clone()),
    ]);

    let result = verify_incoming_request(&VerifyRequestInput {
        headers: &headers,
        method: "DELETE",
        path: "/api/resource/123",
        raw_query: "",
        canonical_body: body,
        nonce,
        context_id,
        max_age_seconds: 300,
        clock_skew_seconds: 60,
    });

    assert!(result.ok, "Empty body round-trip failed: {:?}", result.error);
}
