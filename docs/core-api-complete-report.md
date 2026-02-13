# ASH Core API — Complete Implementation Report

**Version:** 1.0.0
**Date:** 2026-02-08
**Conformance:** 134/134 vectors, 6 SDKs, byte-identical
**Total Tests:** 1,253 pass (ashcore), 0 failures

---

## Executive Summary

All 10 Core API additions from the vNext specification are now implemented
in the Rust core. The implementation adds no new behavioral logic — every
function orchestrates existing, conformance-tested primitives. The 134-vector
conformance suite passes unchanged across both Rust core and WASM.

---

## Implementation Status: 10/10 Complete

| # | Feature | Status | Module | Tests |
|---|---------|--------|--------|-------|
| 1 | Canonical Query | **Done** | `canonicalize.rs` + `enriched.rs` | 6 |
| 2 | Headers Extractor | **Done** | `headers.rs` | 11 |
| 3 | Binding Normalizer | **Done** | `binding.rs` + `enriched.rs` | 21 + 5 |
| 4 | Timestamp Validator | **Done** | `proof.rs` (public) | 3 |
| 5 | Nonce Validator | **Done** | `validate.rs` | 10 |
| 6 | Body Hash Helper | **Done** | `proof.rs` + `enriched.rs` | 3 |
| 7 | High-level Builder | **Done** | `build.rs` | 12 + 8 roundtrip |
| 8 | High-level Verifier | **Done** | `verify.rs` | 9 + 17 lock |
| 9 | Structured Errors | **Done** | `errors.rs` | 7 retryable + 14 existing |
| 10 | Testkit | **Done** | `testkit.rs` | 10 |

---

## Detailed Implementation

### 1. Canonical Query

**Base:** `ash_canonicalize_query(raw_query) -> Result<String, AshError>`
**Enriched:** `ash_canonicalize_query_enriched(raw_query) -> Result<CanonicalQueryResult, AshError>`

```rust
pub struct CanonicalQueryResult {
    pub canonical: String,                  // sorted, normalized query
    pub pairs_count: usize,                 // number of key=value pairs
    pub had_fragment: bool,                 // whether # was stripped
    pub had_leading_question_mark: bool,    // whether ? was stripped
    pub unique_keys: usize,                 // distinct key count
}
```

**Location:** `src/canonicalize.rs` (base), `src/enriched.rs` (enriched)

### 2. Canonical Headers Extractor

**API:** `ash_extract_headers(headers: &impl HeaderMapView) -> Result<HeaderBundle, AshError>`

```rust
pub struct HeaderBundle {
    pub ts: String,
    pub nonce: String,
    pub body_hash: String,
    pub proof: String,
    pub context_id: Option<String>,
}
```

**Rules:**
- Case-insensitive header lookup
- Single-value enforcement
- Whitespace trimming
- Control character rejection
- Deterministic extraction order (ts → nonce → body_hash → proof)

**Location:** `src/headers.rs`

### 3. Binding Normalizer

#### Route Binding (METHOD|PATH|QUERY)
**API:** `ash_normalize_binding(method, path, query) -> Result<String, AshError>`
**Enriched:** `ash_normalize_binding_enriched(method, path, query) -> Result<NormalizedBinding, AshError>`
**Parser:** `ash_parse_binding(binding) -> Result<NormalizedBinding, AshError>`

```rust
pub struct NormalizedBinding {
    pub binding: String,           // full METHOD|PATH|QUERY
    pub method: String,            // uppercased
    pub path: String,              // decoded, dot-resolved, re-encoded
    pub canonical_query: String,   // sorted, normalized
    pub had_query: bool,
}
```

#### Generic Binding (ip/device/session/user/tenant/custom)
**API:** `ash_normalize_binding_value(binding_type, value) -> Result<NormalizedBindingValue, AshError>`

```rust
pub enum BindingType { Route, Ip, Device, Session, User, Tenant, Custom }

pub struct NormalizedBindingValue {
    pub value: String,              // trimmed, validated
    pub binding_type: BindingType,
    pub original_length: usize,
    pub was_trimmed: bool,
}
```

**Universal rules:** trim, reject control chars/newlines/NULL, max 8192 bytes
**Type-specific:** IP = ASCII-only no spaces; User = NFC normalization; Route = redirects to `ash_normalize_binding()`

**Location:** `src/binding.rs` (generic), `src/lib.rs` (route), `src/enriched.rs` (structured)

### 4. Timestamp Validator

**API:** `ash_validate_timestamp(timestamp, max_age_seconds, clock_skew_seconds) -> Result<(), AshError>`
**Format-only:** `ash_validate_timestamp_format(timestamp) -> Result<u64, AshError>`

**Rules:** digits only, no leading zeros, valid u64, below MAX_TIMESTAMP (year 3000), freshness check against system clock.

**Location:** `src/proof.rs` (both functions now public)

### 5. Nonce Validator

**API:** `ash_validate_nonce(nonce) -> Result<(), AshError>`

**Rules:** min 32 hex chars, max 512 chars, ASCII hex charset only.
**Integration:** `ash_derive_client_secret` calls this internally — single validation path.

**Location:** `src/validate.rs`

### 6. Body Hash Helper

**Base:** `ash_hash_body(canonical_body) -> String`
**Enriched:** `ash_hash_body_enriched(canonical_body) -> BodyHashResult`

```rust
pub struct BodyHashResult {
    pub hash: String,       // SHA-256 hex (64 chars)
    pub input_bytes: usize, // size of input
    pub is_empty: bool,
}
```

**Location:** `src/proof.rs` (base), `src/enriched.rs` (enriched)

### 7. High-level Builder (Client-side)

**API:** `build_request_proof(input) -> Result<BuildRequestResult, AshError>`

```rust
pub struct BuildRequestInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub raw_query: &'a str,
    pub canonical_body: &'a str,
    pub nonce: &'a str,
    pub context_id: &'a str,
    pub timestamp: &'a str,
    pub scope: Option<&'a [&'a str]>,
    pub previous_proof: Option<&'a str>,
}

pub struct BuildRequestResult {
    pub proof: String,          // 64-char hex
    pub body_hash: String,      // 64-char hex
    pub binding: String,        // METHOD|PATH|QUERY
    pub timestamp: String,      // echoed
    pub nonce: String,          // echoed
    pub scope_hash: String,     // empty if no scope
    pub chain_hash: String,     // empty if no chain
    pub meta: Option<BuildMeta>,
}
```

**Execution Order (locked):**
1. Validate nonce format
2. Validate timestamp format
3. Normalize binding
4. Hash canonical body
5. Derive client secret
6. Build proof (basic / scoped / unified)
7. Return result

**Location:** `src/build.rs`

### 8. High-level Verifier (Server-side)

**API:** `verify_incoming_request(input) -> VerifyResult`

```rust
pub struct VerifyRequestInput<'a, H: HeaderMapView> {
    pub headers: &'a H,
    pub method: &'a str,
    pub path: &'a str,
    pub raw_query: &'a str,
    pub canonical_body: &'a str,
    pub nonce: &'a str,
    pub context_id: &'a str,
    pub max_age_seconds: u64,
    pub clock_skew_seconds: u64,
}

pub struct VerifyResult {
    pub ok: bool,
    pub error: Option<AshError>,
    pub meta: Option<VerifyMeta>,
}
```

**Execution Order (locked):**
1. Extract headers (ts, body-hash, proof)
2. Validate timestamp format
3. Validate timestamp freshness
4. Validate nonce format
5. Normalize binding
6. Hash canonical body
7. Compare body hashes (timing-safe)
8. Verify proof
9. Return ok

**Location:** `src/verify.rs`

### 9. Structured Errors + Error Registry

**Error Shape:**
```rust
pub struct AshError {
    code: AshErrorCode,                              // wire-level (conformance-locked)
    message: String,                                  // human-readable
    reason: InternalReason,                           // diagnostic (not on wire)
    details: Option<BTreeMap<&'static str, String>>,  // diagnostic metadata
}
```

**Accessors:** `code()`, `http_status()`, `message()`, `reason()`, `details()`, `retryable()`

**Error Registry (15 codes, all with unique HTTP status):**

| Code | HTTP | Retryable | Description |
|------|------|-----------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | No | Context not found |
| `ASH_CTX_EXPIRED` | 451 | No | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | No | Replay detected |
| `ASH_PROOF_INVALID` | 460 | No | Wrong proof |
| `ASH_BINDING_MISMATCH` | 461 | No | Wrong endpoint |
| `ASH_SCOPE_MISMATCH` | 473 | No | Scope hash mismatch |
| `ASH_CHAIN_BROKEN` | 474 | No | Chain broken |
| `ASH_SCOPED_FIELD_MISSING` | 475 | No | Required field missing |
| `ASH_TIMESTAMP_INVALID` | 482 | **Yes** | Clock skew / format |
| `ASH_PROOF_MISSING` | 483 | No | Missing header |
| `ASH_CANONICALIZATION_ERROR` | 484 | No | Malformed payload |
| `ASH_VALIDATION_ERROR` | 485 | No | Input validation |
| `ASH_MODE_VIOLATION` | 486 | No | Mode mismatch |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | No | Wrong content type |
| `ASH_INTERNAL_ERROR` | 500 | **Yes** | Transient server issue |

**Internal Reasons (11 variants):**
`HdrMissing`, `HdrMultiValue`, `HdrInvalidChars`, `TsParse`, `TsSkew`, `TsLeadingZeros`, `TsOverflow`, `NonceTooShort`, `NonceTooLong`, `NonceInvalidChars`, `General`

**Key Design:** `InternalReason` is never exposed on wire (JSON, WASM, SDK surface). `AshErrorCode` is the API. `InternalReason` is implementation detail.

**Location:** `src/errors.rs`

### 10. Testkit

**API:**
```rust
// Load vectors
pub fn load_vectors(data: &[u8]) -> Result<Vec<Vector>, String>
pub fn load_vectors_from_file(path: &str) -> Result<Vec<Vector>, String>

// Run vectors against any implementation
pub fn run_vectors(vectors: &[Vector], adapter: &dyn AshAdapter) -> TestReport

// Report
pub struct TestReport {
    pub fn all_passed(&self) -> bool
    pub fn failures(&self) -> Vec<&VectorResult>
    pub fn summary(&self) -> String
}
```

**Adapter Trait (12 methods, all with default skip):**
```rust
pub trait AshAdapter {
    fn canonicalize_json(&self, input: &str) -> AdapterResult;
    fn canonicalize_query(&self, input: &str) -> AdapterResult;
    fn canonicalize_urlencoded(&self, input: &str) -> AdapterResult;
    fn normalize_binding(&self, method: &str, path: &str, query: &str) -> AdapterResult;
    fn hash_body(&self, body: &str) -> AdapterResult;
    fn derive_client_secret(&self, nonce: &str, ctx: &str, binding: &str) -> AdapterResult;
    fn build_proof(&self, secret: &str, ts: &str, binding: &str, body_hash: &str) -> AdapterResult;
    fn timing_safe_equal(&self, a: &str, b: &str) -> AdapterResult;
    fn validate_timestamp(&self, ts: &str) -> AdapterResult;
    fn trigger_error(&self, input: &serde_json::Value) -> AdapterResult;
    fn extract_scoped_fields(&self, payload: &str, fields: &[String], strict: bool) -> AdapterResult;
    fn build_unified_proof(&self, input: &serde_json::Value) -> AdapterResult;
}
```

**Adding a new SDK:**
1. Implement `AshAdapter` with your SDK's functions
2. `let vectors = load_vectors(include_bytes!("vectors.json"))?;`
3. `let report = run_vectors(&vectors, &MyAdapter);`
4. `assert!(report.all_passed());`

**Location:** `src/testkit.rs`

---

## Files Created/Modified

| File | Action | Phase |
|------|--------|-------|
| `src/errors.rs` | **Modified** — `InternalReason`, `retryable()`, `details` | 1, 2 |
| `src/headers.rs` | **Created** — `HeaderMapView`, `ash_extract_headers` | 1 |
| `src/validate.rs` | **Created** — `ash_validate_nonce` | 1 |
| `src/proof.rs` | **Modified** — nonce delegation, timestamp_format public | 1 |
| `src/verify.rs` | **Created** — `verify_incoming_request` | 3-A |
| `src/build.rs` | **Created** — `build_request_proof` | 3-B |
| `src/enriched.rs` | **Created** — enriched query, body hash, binding | 2 |
| `src/binding.rs` | **Created** — generic binding normalizer | 2 |
| `src/testkit.rs` | **Created** — `load_vectors`, `run_vectors`, `AshAdapter` | 2 |
| `src/lib.rs` | **Modified** — module declarations, exports | All |
| `tests/phase1_execution_lock.rs` | **Created** — 17 precedence/stability tests | 1.5 |
| `tests/phase3_build_verify_roundtrip.rs` | **Created** — 8 E2E roundtrip tests | 3 |

---

## Test Summary

| Category | Count |
|----------|-------|
| Lib unit tests | 282 |
| Execution lock tests | 17 |
| Build↔Verify roundtrip | 8 |
| Conformance (Rust core) | 134/134 |
| Conformance (WASM) | 134/134 |
| Integration/other tests | ~800+ |
| **Total ashcore** | **1,253** |

---

## Conformance Impact

**None.** All 134 vectors pass unchanged in both Rust core and WASM.
No wire-level behavior was changed. All new APIs orchestrate existing primitives.

---

## Architecture After All Phases

```
SDK / Middleware
 └── call core high-level API
         ├── build_request_proof()        [client-side]
         ├── verify_incoming_request()    [server-side]
         │    ├── ash_extract_headers()   [Phase 1]
         │    ├── ash_validate_timestamp  [Phase 1]
         │    ├── ash_validate_nonce()    [Phase 1]
         │    ├── ash_normalize_binding() [existing]
         │    ├── ash_hash_body()         [existing]
         │    ├── ash_derive_client_secret [existing]
         │    └── ash_build_proof()       [existing]
         ├── ash_normalize_binding_value() [generic bindings]
         ├── AshError { code, http_status, message, reason, details, retryable }
         └── Testkit: load_vectors → run_vectors(adapter) → report
```

SDKs are now thin wrappers. No parsing, no mapping, no sequencing logic.
