//! Testkit — Conformance adapter runner.
//!
//! Provides a reusable framework for running conformance vectors against
//! any SDK implementation. New SDKs implement the `AshAdapter` trait
//! and get full conformance testing for free.
//!
//! ## Usage
//!
//! 1. Implement `AshAdapter` for your SDK
//! 2. Call `load_vectors()` to parse vectors.json
//! 3. Call `run_vectors()` to execute all vectors
//! 4. Inspect the `TestReport` for pass/fail + diffs
//!
//! ## Example
//!
//! ```rust,ignore
//! use ashcore::testkit::{load_vectors, run_vectors, AshAdapter, AdapterResult};
//!
//! struct MyAdapter;
//! impl AshAdapter for MyAdapter {
//!     fn canonicalize_json(&self, input: &str) -> AdapterResult {
//!         match my_sdk::canonicalize(input) {
//!             Ok(s) => AdapterResult::ok(s),
//!             Err(e) => AdapterResult::error(e.code, e.status),
//!         }
//!     }
//!     // ... implement other methods
//! }
//!
//! let vectors = load_vectors(include_bytes!("../../tests/conformance/vectors.json")).unwrap();
//! let report = run_vectors(&vectors, &MyAdapter);
//! assert!(report.all_passed(), "Failures: {:?}", report.failures());
//! ```

use serde::Deserialize;
use std::collections::BTreeMap;

// ── Vector Types ─────────────────────────────────────────────────────

/// Top-level vectors file.
#[derive(Debug, Deserialize)]
pub struct VectorFile {
    /// Schema version
    pub schema_version: u32,
    /// ASH version these vectors are locked to
    pub ash_version: String,
    /// All vector categories
    #[serde(default)]
    pub categories: BTreeMap<String, Vec<Vector>>,
    /// Flat list (alternative format)
    #[serde(default)]
    pub vectors: Vec<Vector>,
}

/// A single conformance vector.
#[derive(Debug, Clone, Deserialize)]
pub struct Vector {
    /// Unique vector ID (e.g., "json_001")
    pub id: String,
    /// Category (e.g., "json_canonicalization")
    #[serde(default)]
    pub category: String,
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    /// Input data (varies by category)
    #[serde(default)]
    pub input: serde_json::Value,
    /// Expected output (varies by category)
    #[serde(default)]
    pub expected: serde_json::Value,
}

// ── Adapter Interface ────────────────────────────────────────────────

/// Result from an adapter operation.
#[derive(Debug, Clone)]
pub struct AdapterResult {
    /// Successful output (canonical string, hash, proof, etc.)
    pub output: Option<String>,
    /// Whether the operation succeeded
    pub ok: bool,
    /// Error code if failed (e.g., "ASH_VALIDATION_ERROR")
    pub error_code: Option<String>,
    /// HTTP status if failed
    pub error_status: Option<u16>,
}

impl AdapterResult {
    /// Successful result with output string.
    pub fn ok(output: impl Into<String>) -> Self {
        Self {
            output: Some(output.into()),
            ok: true,
            error_code: None,
            error_status: None,
        }
    }

    /// Successful result with boolean (for timing-safe comparison).
    pub fn ok_bool(val: bool) -> Self {
        Self {
            output: Some(val.to_string()),
            ok: true,
            error_code: None,
            error_status: None,
        }
    }

    /// Error result.
    pub fn error(code: impl Into<String>, status: u16) -> Self {
        Self {
            output: None,
            ok: false,
            error_code: Some(code.into()),
            error_status: Some(status),
        }
    }

    /// Skipped (adapter doesn't support this operation).
    pub fn skip() -> Self {
        Self {
            output: None,
            ok: true,
            error_code: None,
            error_status: None,
        }
    }
}

/// Trait that SDK implementations must implement for conformance testing.
///
/// Each method corresponds to a vector category. Return `AdapterResult::skip()`
/// for categories your SDK doesn't implement yet.
pub trait AshAdapter {
    /// JSON canonicalization: input JSON text → canonical JSON text
    fn canonicalize_json(&self, input: &str) -> AdapterResult { let _ = input; AdapterResult::skip() }
    /// Query canonicalization: raw query → canonical query
    fn canonicalize_query(&self, input: &str) -> AdapterResult { let _ = input; AdapterResult::skip() }
    /// URL-encoded canonicalization: raw → canonical
    fn canonicalize_urlencoded(&self, input: &str) -> AdapterResult { let _ = input; AdapterResult::skip() }
    /// Binding normalization: (method, path, query) → binding string
    fn normalize_binding(&self, method: &str, path: &str, query: &str) -> AdapterResult { let _ = (method, path, query); AdapterResult::skip() }
    /// Body hashing: canonical body → hex hash
    fn hash_body(&self, body: &str) -> AdapterResult { let _ = body; AdapterResult::skip() }
    /// Client secret derivation: (nonce, context_id, binding) → hex secret
    fn derive_client_secret(&self, nonce: &str, context_id: &str, binding: &str) -> AdapterResult { let _ = (nonce, context_id, binding); AdapterResult::skip() }
    /// Proof generation: full inputs → hex proof
    fn build_proof(&self, secret: &str, ts: &str, binding: &str, body_hash: &str) -> AdapterResult { let _ = (secret, ts, binding, body_hash); AdapterResult::skip() }
    /// Timing-safe comparison: (a, b) → bool
    fn timing_safe_equal(&self, a: &str, b: &str) -> AdapterResult { let _ = (a, b); AdapterResult::skip() }
    /// Timestamp validation: ts → ok or error
    fn validate_timestamp(&self, ts: &str) -> AdapterResult { let _ = ts; AdapterResult::skip() }
    /// Error behavior: trigger → error code + status
    fn trigger_error(&self, input: &serde_json::Value) -> AdapterResult { let _ = input; AdapterResult::skip() }
    /// Scoped field extraction: (payload, fields, mode) → extracted/hash
    fn extract_scoped_fields(&self, payload: &str, fields: &[String], strict: bool) -> AdapterResult { let _ = (payload, fields, strict); AdapterResult::skip() }
    /// Unified proof: full inputs → proof + scope_hash + chain_hash
    fn build_unified_proof(&self, input: &serde_json::Value) -> AdapterResult { let _ = input; AdapterResult::skip() }
}

// ── Loading ──────────────────────────────────────────────────────────

/// Load vectors from raw JSON bytes (e.g., `include_bytes!`).
///
/// Accepts the standard vectors.json format.
pub fn load_vectors(data: &[u8]) -> Result<Vec<Vector>, String> {
    let file: serde_json::Value =
        serde_json::from_slice(data).map_err(|e| format!("Failed to parse vectors JSON: {}", e))?;

    let mut all_vectors = Vec::new();

    // Extract vectors from categorized format
    if let Some(obj) = file.as_object() {
        for (key, val) in obj {
            // Skip metadata fields
            if matches!(
                key.as_str(),
                "schema_version"
                    | "ash_version"
                    | "generated_from"
                    | "generated_at"
                    | "generator_version"
                    | "platform"
            ) {
                continue;
            }

            // Each category is an array of vectors
            if let Some(arr) = val.as_array() {
                for item in arr {
                    // BUG-FIX: Report malformed vectors instead of silently dropping them.
                    // Previously, deserialization failures were swallowed, causing the
                    // conformance suite to silently shrink without warning.
                    match serde_json::from_value::<Vector>(item.clone()) {
                        Ok(mut vec) => {
                            if vec.category.is_empty() {
                                vec.category = key.clone();
                            }
                            all_vectors.push(vec);
                        }
                        Err(e) => {
                            return Err(format!(
                                "Failed to parse vector in category '{}': {}",
                                key, e
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(all_vectors)
}

/// Load vectors from a file path.
pub fn load_vectors_from_file(path: &str) -> Result<Vec<Vector>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    load_vectors(&data)
}

// ── Running ──────────────────────────────────────────────────────────

/// Result of running a single vector.
#[derive(Debug, Clone)]
pub struct VectorResult {
    /// Vector ID
    pub id: String,
    /// Category
    pub category: String,
    /// Whether the vector passed
    pub passed: bool,
    /// Whether the vector was skipped
    pub skipped: bool,
    /// Expected output
    pub expected: String,
    /// Actual output
    pub actual: String,
    /// Diff message if failed
    pub diff: Option<String>,
}

/// Report from running all vectors.
#[derive(Debug)]
pub struct TestReport {
    /// Results for each vector
    pub results: Vec<VectorResult>,
    /// Total vectors processed
    pub total: usize,
    /// Vectors that passed
    pub passed: usize,
    /// Vectors that failed
    pub failed: usize,
    /// Vectors that were skipped
    pub skipped: usize,
}

impl TestReport {
    /// Whether all non-skipped vectors passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Get only the failed vectors.
    pub fn failures(&self) -> Vec<&VectorResult> {
        self.results.iter().filter(|r| !r.passed && !r.skipped).collect()
    }

    /// Get a summary string.
    pub fn summary(&self) -> String {
        format!(
            "{}/{} passed, {} failed, {} skipped",
            self.passed, self.total, self.failed, self.skipped
        )
    }
}

/// Run all vectors against an adapter.
///
/// Dispatches each vector to the appropriate adapter method based on category,
/// compares outputs, and collects results into a `TestReport`.
pub fn run_vectors(vectors: &[Vector], adapter: &dyn AshAdapter) -> TestReport {
    let mut results = Vec::with_capacity(vectors.len());
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for vec in vectors {
        let result = run_single_vector(vec, adapter);
        if result.skipped {
            skipped += 1;
        } else if result.passed {
            passed += 1;
        } else {
            failed += 1;
        }
        results.push(result);
    }

    TestReport {
        total: vectors.len(),
        passed,
        failed,
        skipped,
        results,
    }
}

fn run_single_vector(vec: &Vector, adapter: &dyn AshAdapter) -> VectorResult {
    let category = vec.category.as_str();

    let (adapter_result, expected_str) = match category {
        "json_canonicalization" => {
            let input = vec.input.get("input_json_text")
                .or_else(|| vec.input.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let expected = vec.expected.get("canonical_json")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.canonicalize_json(input), expected.to_string())
        }
        "query_canonicalization" => {
            let input = vec.input.get("raw_query")
                .or_else(|| vec.input.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let expected = vec.expected.get("canonical_query")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.canonicalize_query(input), expected.to_string())
        }
        "urlencoded_canonicalization" => {
            let input = vec.input.get("input")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let expected = vec.expected.get("canonical")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.canonicalize_urlencoded(input), expected.to_string())
        }
        "binding_normalization" => {
            let method = vec.input.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let path = vec.input.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let query = vec.input.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let expected = vec.expected.get("binding")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.normalize_binding(method, path, query), expected.to_string())
        }
        "body_hashing" => {
            let input = vec.input.get("body")
                .or_else(|| vec.input.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let expected = vec.expected.get("hash")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.hash_body(input), expected.to_string())
        }
        "client_secret_derivation" => {
            let nonce = vec.input.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
            let ctx = vec.input.get("context_id").and_then(|v| v.as_str()).unwrap_or("");
            let binding = vec.input.get("binding").and_then(|v| v.as_str()).unwrap_or("");
            let expected = vec.expected.get("client_secret")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.derive_client_secret(nonce, ctx, binding), expected.to_string())
        }
        "proof_generation" => {
            let secret = vec.input.get("client_secret").and_then(|v| v.as_str()).unwrap_or("");
            let ts = vec.input.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let binding = vec.input.get("binding").and_then(|v| v.as_str()).unwrap_or("");
            let body_hash = vec.input.get("body_hash").and_then(|v| v.as_str()).unwrap_or("");
            let expected = vec.expected.get("proof")
                .or_else(|| vec.expected.as_str().map(|_| &vec.expected))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (adapter.build_proof(secret, ts, binding, body_hash), expected.to_string())
        }
        "timing_safe_comparison" => {
            let a = vec.input.get("a").and_then(|v| v.as_str()).unwrap_or("");
            let b = vec.input.get("b").and_then(|v| v.as_str()).unwrap_or("");
            let expected = vec.expected.get("equal")
                .and_then(|v| v.as_bool())
                .map(|b| b.to_string())
                .unwrap_or_default();
            (adapter.timing_safe_equal(a, b), expected)
        }
        "error_behavior" => {
            let expected_code = vec.expected.get("error_code")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let expected_status: u16 = vec.expected.get("http_status")
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0);
            let result = adapter.trigger_error(&vec.input);
            // BUG-FIX: Compute skip first so passed is always false when skipped.
            let is_skip = result.output.is_none() && result.ok && result.error_code.is_none();
            let expected_str = format!("{}:{}", expected_code, expected_status);
            let actual_str = if result.ok {
                "ok".to_string()
            } else {
                format!("{}:{}", result.error_code.as_deref().unwrap_or(""), result.error_status.unwrap_or(0))
            };
            return VectorResult {
                id: vec.id.clone(),
                category: vec.category.clone(),
                passed: !is_skip && !result.ok
                    && result.error_code.as_deref() == Some(expected_code)
                    && result.error_status == Some(expected_status),
                skipped: is_skip,
                expected: expected_str,
                actual: actual_str,
                diff: None,
            };
        }
        "timestamp_validation" => {
            let ts = vec.input.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let should_pass = vec.expected.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
            let result = adapter.validate_timestamp(ts);
            // BUG-FIX: Compute skip first so passed is always false when skipped.
            let is_skip = result.output.is_none() && result.ok && result.error_code.is_none();
            let actual_ok = result.ok;
            return VectorResult {
                id: vec.id.clone(),
                category: vec.category.clone(),
                passed: !is_skip && actual_ok == should_pass,
                skipped: is_skip,
                expected: format!("valid={}", should_pass),
                actual: format!("valid={}", actual_ok),
                diff: if !is_skip && actual_ok != should_pass {
                    Some(format!("Expected valid={}, got valid={}", should_pass, actual_ok))
                } else {
                    None
                },
            };
        }
        "scoped_field_extraction" => {
            let payload = vec.input.get("payload")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            let fields: Vec<String> = vec.input.get("fields")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let strict = vec.input.get("strict")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let expected_code = vec.expected.get("error_code")
                .and_then(|v| v.as_str());
            let expected_status: Option<u16> = vec.expected.get("http_status")
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok());

            let result = adapter.extract_scoped_fields(payload, &fields, strict);

            if expected_code.is_some() || expected_status.is_some() {
                // Error expected
                let is_skip = result.output.is_none() && result.ok && result.error_code.is_none();
                let expected_str = format!("{}:{}", expected_code.unwrap_or(""), expected_status.unwrap_or(0));
                let actual_str = if result.ok {
                    "ok".to_string()
                } else {
                    format!("{}:{}", result.error_code.as_deref().unwrap_or(""), result.error_status.unwrap_or(0))
                };
                return VectorResult {
                    id: vec.id.clone(),
                    category: vec.category.clone(),
                    passed: !is_skip && !result.ok
                        && result.error_code.as_deref() == expected_code
                        && result.error_status == expected_status,
                    skipped: is_skip,
                    expected: expected_str,
                    actual: actual_str,
                    diff: None,
                };
            }

            let expected = vec.expected.get("extracted")
                .or_else(|| vec.expected.get("hash"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (result, expected.to_string())
        }
        "unified_proof" => {
            let result = adapter.build_unified_proof(&vec.input);

            let expected_code = vec.expected.get("error_code")
                .and_then(|v| v.as_str());
            let expected_status: Option<u16> = vec.expected.get("http_status")
                .and_then(|v| v.as_u64())
                .and_then(|v| u16::try_from(v).ok());

            if expected_code.is_some() || expected_status.is_some() {
                let is_skip = result.output.is_none() && result.ok && result.error_code.is_none();
                let expected_str = format!("{}:{}", expected_code.unwrap_or(""), expected_status.unwrap_or(0));
                let actual_str = if result.ok {
                    "ok".to_string()
                } else {
                    format!("{}:{}", result.error_code.as_deref().unwrap_or(""), result.error_status.unwrap_or(0))
                };
                return VectorResult {
                    id: vec.id.clone(),
                    category: vec.category.clone(),
                    passed: !is_skip && !result.ok
                        && result.error_code.as_deref() == expected_code
                        && result.error_status == expected_status,
                    skipped: is_skip,
                    expected: expected_str,
                    actual: actual_str,
                    diff: None,
                };
            }

            let expected = vec.expected.get("proof")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (result, expected.to_string())
        }
        _ => {
            return VectorResult {
                id: vec.id.clone(),
                category: vec.category.clone(),
                passed: false,
                skipped: true,
                expected: String::new(),
                actual: String::new(),
                diff: Some(format!("Unknown category: {}", category)),
            };
        }
    };

    // Standard comparison for most categories
    if adapter_result.output.is_none() && adapter_result.ok && adapter_result.error_code.is_none() {
        return VectorResult {
            id: vec.id.clone(),
            category: vec.category.clone(),
            passed: false,
            skipped: true,
            expected: expected_str,
            actual: String::new(),
            diff: None,
        };
    }

    let actual = adapter_result.output.unwrap_or_default();
    let pass = actual == expected_str;

    VectorResult {
        id: vec.id.clone(),
        category: vec.category.clone(),
        passed: pass,
        skipped: false,
        expected: expected_str.clone(),
        actual: actual.clone(),
        diff: if pass {
            None
        } else {
            Some(format!("expected: {}\n  actual: {}", expected_str, actual))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AdapterResult construction ────────────────────────────────────

    #[test]
    fn test_adapter_result_ok() {
        let r = AdapterResult::ok("hello");
        assert!(r.ok);
        assert_eq!(r.output, Some("hello".to_string()));
        assert!(r.error_code.is_none());
    }

    #[test]
    fn test_adapter_result_error() {
        let r = AdapterResult::error("ASH_VALIDATION_ERROR", 485);
        assert!(!r.ok);
        assert!(r.output.is_none());
        assert_eq!(r.error_code, Some("ASH_VALIDATION_ERROR".to_string()));
        assert_eq!(r.error_status, Some(485));
    }

    #[test]
    fn test_adapter_result_skip() {
        let r = AdapterResult::skip();
        assert!(r.ok);
        assert!(r.output.is_none());
    }

    #[test]
    fn test_adapter_result_ok_bool() {
        let r = AdapterResult::ok_bool(true);
        assert_eq!(r.output, Some("true".to_string()));
    }

    // ── TestReport ────────────────────────────────────────────────────

    #[test]
    fn test_report_all_passed() {
        let report = TestReport {
            results: vec![],
            total: 5,
            passed: 5,
            failed: 0,
            skipped: 0,
        };
        assert!(report.all_passed());
        assert_eq!(report.summary(), "5/5 passed, 0 failed, 0 skipped");
    }

    #[test]
    fn test_report_with_failures() {
        let report = TestReport {
            results: vec![VectorResult {
                id: "test_001".to_string(),
                category: "json".to_string(),
                passed: false,
                skipped: false,
                expected: "a".to_string(),
                actual: "b".to_string(),
                diff: Some("expected: a\n  actual: b".to_string()),
            }],
            total: 1,
            passed: 0,
            failed: 1,
            skipped: 0,
        };
        assert!(!report.all_passed());
        assert_eq!(report.failures().len(), 1);
    }

    // ── Default adapter returns skips ─────────────────────────────────

    struct EmptyAdapter;
    impl AshAdapter for EmptyAdapter {}

    #[test]
    fn test_empty_adapter_skips_all() {
        let vec = Vector {
            id: "test".to_string(),
            category: "json_canonicalization".to_string(),
            description: "test".to_string(),
            input: serde_json::json!({"input_json_text": "{}"}),
            expected: serde_json::json!({"canonical_json": "{}"}),
        };
        let report = run_vectors(&[vec], &EmptyAdapter);
        assert_eq!(report.skipped, 1);
    }

    // ── Rust core adapter (proves testkit works) ──────────────────────

    struct RustCoreAdapter;
    impl AshAdapter for RustCoreAdapter {
        fn canonicalize_json(&self, input: &str) -> AdapterResult {
            match crate::ash_canonicalize_json(input) {
                Ok(s) => AdapterResult::ok(s),
                Err(e) => AdapterResult::error(e.code().as_str(), e.http_status()),
            }
        }
        fn canonicalize_query(&self, input: &str) -> AdapterResult {
            match crate::ash_canonicalize_query(input) {
                Ok(s) => AdapterResult::ok(s),
                Err(e) => AdapterResult::error(e.code().as_str(), e.http_status()),
            }
        }
        fn hash_body(&self, body: &str) -> AdapterResult {
            AdapterResult::ok(crate::ash_hash_body(body))
        }
        fn derive_client_secret(&self, nonce: &str, ctx: &str, binding: &str) -> AdapterResult {
            match crate::ash_derive_client_secret(nonce, ctx, binding) {
                Ok(s) => AdapterResult::ok(s),
                Err(e) => AdapterResult::error(e.code().as_str(), e.http_status()),
            }
        }
        fn build_proof(&self, secret: &str, ts: &str, binding: &str, body_hash: &str) -> AdapterResult {
            match crate::ash_build_proof(secret, ts, binding, body_hash) {
                Ok(s) => AdapterResult::ok(s),
                Err(e) => AdapterResult::error(e.code().as_str(), e.http_status()),
            }
        }
        fn timing_safe_equal(&self, a: &str, b: &str) -> AdapterResult {
            AdapterResult::ok_bool(crate::ash_timing_safe_equal(a.as_bytes(), b.as_bytes()))
        }
        fn normalize_binding(&self, method: &str, path: &str, query: &str) -> AdapterResult {
            match crate::ash_normalize_binding(method, path, query) {
                Ok(s) => AdapterResult::ok(s),
                Err(e) => AdapterResult::error(e.code().as_str(), e.http_status()),
            }
        }
    }

    #[test]
    fn test_rust_core_adapter_json() {
        let vec = Vector {
            id: "json_inline".to_string(),
            category: "json_canonicalization".to_string(),
            description: "sort keys".to_string(),
            input: serde_json::json!({"input_json_text": r#"{"z":1,"a":2}"#}),
            expected: serde_json::json!({"canonical_json": r#"{"a":2,"z":1}"#}),
        };
        let report = run_vectors(&[vec], &RustCoreAdapter);
        assert!(report.all_passed(), "Failures: {:?}", report.failures());
    }

    #[test]
    fn test_rust_core_adapter_body_hash() {
        let hash = crate::ash_hash_body("test");
        let vec = Vector {
            id: "hash_inline".to_string(),
            category: "body_hashing".to_string(),
            description: "hash test".to_string(),
            input: serde_json::json!({"body": "test"}),
            expected: serde_json::json!({"hash": hash}),
        };
        let report = run_vectors(&[vec], &RustCoreAdapter);
        assert!(report.all_passed());
    }

    #[test]
    fn test_rust_core_adapter_timing_safe() {
        let vectors = vec![
            Vector {
                id: "ts_eq".to_string(),
                category: "timing_safe_comparison".to_string(),
                description: "equal".to_string(),
                input: serde_json::json!({"a": "hello", "b": "hello"}),
                expected: serde_json::json!({"equal": true}),
            },
            Vector {
                id: "ts_neq".to_string(),
                category: "timing_safe_comparison".to_string(),
                description: "not equal".to_string(),
                input: serde_json::json!({"a": "hello", "b": "world"}),
                expected: serde_json::json!({"equal": false}),
            },
        ];
        let report = run_vectors(&vectors, &RustCoreAdapter);
        assert!(report.all_passed());
        assert_eq!(report.passed, 2);
    }
}
