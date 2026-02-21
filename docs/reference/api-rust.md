# ASH Rust SDK — API Reference

**Crate:** `ashcore`
**Version:** v1.0.0-beta

> **⚠️ Beta Notice:** This is v1.0.0-beta. Feature-complete but may undergo internal refinements. Not recommended for production-critical environments yet.

## Installation

```bash
cargo add ashcore
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
ashcore = "1.0.0"
```

---

## Constants

```rust
pub const ASH_SDK_VERSION: &str = "1.0.0";
pub const DEFAULT_MAX_TIMESTAMP_AGE_SECONDS: u64 = 300;
pub const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;
```

---

## Core Proof Functions

| Function | Description |
|----------|-------------|
| `ash_derive_client_secret(nonce, ctx_id, binding)` | Derive HMAC key from nonce |
| `ash_build_proof(secret, timestamp, binding, body_hash)` | Build HMAC-SHA256 proof |
| `ash_verify_proof(nonce, ctx_id, binding, timestamp, body_hash, proof)` | Verify proof |
| `ash_verify_proof_with_freshness(...)` | Verify proof + timestamp freshness |

---

## Scoped Proof Functions

| Function | Description |
|----------|-------------|
| `ash_build_proof_scoped(...)` | Build proof protecting specific fields |
| `ash_verify_proof_scoped(...)` | Verify scoped proof |
| `ash_extract_scoped_fields(payload, scope)` | Extract fields (lenient) |
| `ash_extract_scoped_fields_strict(payload, scope, strict)` | Extract fields with strict mode flag |
| `ash_hash_scoped_body(payload, scope)` | Hash only scoped fields |
| `ash_hash_scoped_body_strict(payload, scope)` | Hash scoped fields (strict) |

---

## Unified Proof Functions

| Function | Description |
|----------|-------------|
| `ash_build_proof_unified(...)` | Build proof with scoping + chaining |
| `ash_verify_proof_unified(...)` | Verify unified proof |
| `ash_hash_proof(proof)` | Compute chain hash (SHA-256 of proof hex) |

---

## Canonicalization Functions

| Function | Description |
|----------|-------------|
| `ash_canonicalize_json(input)` | Canonicalize JSON string (RFC 8785) |
| `ash_canonicalize_json_value(value)` | Canonicalize `serde_json::Value` |
| `ash_canonicalize_query(query)` | Canonicalize URL query string |
| `ash_canonicalize_urlencoded(input)` | Canonicalize form data |
| `ash_normalize_binding(method, path, query)` | Normalize endpoint binding |

---

## Hash Functions

| Function | Description |
|----------|-------------|
| `ash_hash_body(body)` | SHA-256 hash of body (lowercase hex) |
| `ash_hash_body_checked(body)` | Hash with size limit check |
| `ash_hash_proof(proof)` | SHA-256 of proof for chaining |
| `ash_hash_scope(scope)` | SHA-256 of scope fields |

---

## Utility Functions

| Function | Description |
|----------|-------------|
| `ash_generate_nonce(bytes)` | Generate cryptographic nonce (CSPRNG) |
| `ash_generate_context_id()` | Generate unique context ID (128-bit) |
| `ash_generate_context_id_256()` | Generate context ID (256-bit) |
| `ash_timing_safe_equal(a, b)` | Constant-time comparison |
| `ash_timing_safe_compare(a, b)` | Constant-time string comparison (convenience wrapper) |
| `ash_validate_nonce(nonce)` | Validate nonce format |

---

## Header Extraction

```rust
use ashcore::{ash_extract_headers, HeaderMapView, HeaderBundle};
```

Header constants:

| Constant | Value |
|----------|-------|
| `HDR_TIMESTAMP` | `x-ash-ts` |
| `HDR_NONCE` | `x-ash-nonce` |
| `HDR_BODY_HASH` | `x-ash-body-hash` |
| `HDR_PROOF` | `x-ash-proof` |
| `HDR_CONTEXT_ID` | `x-ash-context-id` |

---

## Build / Verify Orchestrators

```rust
use ashcore::{build_request_proof, BuildRequestInput, BuildRequestResult};
use ashcore::{verify_incoming_request, VerifyRequestInput, VerifyResult};
```

| Function | Description |
|----------|-------------|
| `build_request_proof(input)` | Full build pipeline |
| `verify_incoming_request(input)` | Basic proof verification |
| `verify_incoming_request_scoped(input)` | Scoped proof verification |
| `verify_incoming_request_unified(input)` | Unified proof verification |

---

## Types

```rust
pub enum AshMode {
    Minimal,   // Basic integrity checking
    Balanced,  // Recommended for most applications
    Strict,    // Maximum security with nonce requirement
}
```

---

## Quick Start

### JSON Canonicalization

```rust
use ashcore::ash_canonicalize_json;

let canonical = ash_canonicalize_json(r#"{"z": 1, "a": 2}"#).unwrap();
assert_eq!(canonical, r#"{"a":2,"z":1}"#);
```

### Proof Generation

```rust
use ashcore::{
    ash_derive_client_secret, ash_build_proof, ash_hash_body,
    ash_generate_nonce, ash_generate_context_id,
};

let nonce = ash_generate_nonce(32).unwrap();
let context_id = ash_generate_context_id().unwrap();
let binding = "POST|/api/transfer|";

let client_secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
let body_hash = ash_hash_body(r#"{"amount":100}"#);
let timestamp = "1706400000";
let proof = ash_build_proof(&client_secret, timestamp, binding, &body_hash).unwrap();
```

### Proof Verification

```rust
use ashcore::ash_verify_proof;

let is_valid = ash_verify_proof(
    &nonce,
    &context_id,
    binding,
    timestamp,
    &body_hash,
    &client_proof,
).unwrap();
```

---

## Error Handling

Fallible functions return `Result<T, AshError>`. Hash functions (`ash_hash_body`, `ash_hash_scope`) return `String` directly. Comparison functions (`ash_timing_safe_equal`, `ash_timing_safe_compare`) return `bool`. See [Error Codes Reference](error-codes.md).

---

## Cryptographic Details

| Component | Algorithm |
|-----------|-----------|
| Proof Generation | HMAC-SHA256 |
| Body Hashing | SHA-256 |
| Nonce Generation | CSPRNG (`getrandom`) |
| Comparison | Constant-time (`subtle` crate) |
| Key Derivation | HMAC-based |

---

## Input Validation Rules

| Parameter | Rule |
|-----------|------|
| `nonce` | 32-512 hex characters |
| `context_id` | 1-256 chars, `[A-Za-z0-9_\-.]` only |
| `binding` | Max 8,192 bytes |
| `timestamp` | Digits only, no leading zeros |
| `body_hash` | Exactly 64 hex chars (SHA-256) |

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
