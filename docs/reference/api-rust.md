# ASH Rust SDK API Reference

**Version:** 1.0.0
**Package:** `ashcore`

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

### Version Constants

```rust
const ASH_SDK_VERSION: &str = "1.0.0";
const ASH_VERSION_PREFIX: &str = "ASHv2.1";
const DEFAULT_MAX_TIMESTAMP_AGE_SECONDS: u64 = 300;
const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 30;
```

### Security Modes

```rust
pub enum AshMode {
    Minimal,   // Basic integrity checking
    Balanced,  // Recommended for most applications
    Strict,    // Maximum security with nonce requirement
}
```

### Error Codes

```rust
pub enum AshErrorCode {
    CtxNotFound,           // HTTP 450
    CtxExpired,            // HTTP 451
    CtxAlreadyUsed,        // HTTP 452
    ProofInvalid,          // HTTP 460
    BindingMismatch,       // HTTP 461
    ScopeMismatch,         // HTTP 473
    ChainBroken,           // HTTP 474
    TimestampInvalid,      // HTTP 482
    ProofMissing,          // HTTP 483
    CanonicalizationError, // HTTP 484
    ValidationError,       // HTTP 485
    ModeViolation,         // HTTP 486
    UnsupportedContentType,// HTTP 415
    InternalError,         // HTTP 500
}
```

---

## Core Proof Functions

| Function | Description |
|----------|-------------|
| `ash_derive_client_secret(nonce, ctx_id, binding)` | Derive HMAC key from nonce |
| `ash_build_proof(secret, timestamp, binding, body_hash)` | Build HMAC-SHA256 proof |
| `ash_verify_proof(nonce, ctx_id, binding, timestamp, body_hash, proof)` | Verify proof |

---

## Scoped Proof Functions

| Function | Description |
|----------|-------------|
| `ash_build_proof_scoped(...)` | Build proof protecting specific fields |
| `ash_verify_proof_scoped(...)` | Verify scoped proof |
| `ash_extract_scoped_fields(payload, scope)` | Extract fields for scoping |
| `ash_hash_scoped_body(payload, scope)` | Hash only scoped fields |

---

## Unified Proof Functions

| Function | Description |
|----------|-------------|
| `ash_build_proof_unified(...)` | Build proof with scoping + chaining |
| `ash_verify_proof_unified(...)` | Verify unified proof |
| `ash_hash_proof(proof)` | Compute chain hash |

---

## Canonicalization Functions

| Function | Description |
|----------|-------------|
| `ash_canonicalize_json(input)` | Canonicalize JSON (RFC 8785) |
| `ash_canonicalize_query(query)` | Canonicalize URL query string |
| `ash_canonicalize_urlencoded(input)` | Canonicalize form data |
| `ash_normalize_binding(method, path, query)` | Normalize endpoint binding |

---

## Utility Functions

| Function | Description |
|----------|-------------|
| `ash_generate_nonce(bytes)` | Generate cryptographic nonce |
| `ash_generate_context_id()` | Generate unique context ID |
| `ash_hash_body(body)` | SHA-256 hash of body |
| `ash_timing_safe_equal(a, b)` | Constant-time comparison |

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
    ash_generate_nonce, ash_generate_context_id, ash_canonicalize_json,
};

// Server generates nonce and context
let nonce = ash_generate_nonce(32).unwrap();
let context_id = ash_generate_context_id().unwrap();
let binding = "POST|/api/transfer|";

// Client canonicalizes payload
let payload = r#"{"amount":100}"#;
let canonical = ash_canonicalize_json(payload).unwrap();

// Client derives secret and builds proof
let client_secret = ash_derive_client_secret(&nonce, &context_id, binding).unwrap();
let body_hash = ash_hash_body(&canonical);
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

## Cryptographic Details

| Component | Algorithm |
|-----------|-----------|
| Proof Generation | HMAC-SHA256 |
| Body Hashing | SHA-256 |
| Nonce Generation | CSPRNG (`getrandom`) |
| Comparison | Constant-time (`subtle` crate) |
| Key Derivation | HMAC-based |

---

## Input Validation

| Parameter | Rule |
|-----------|------|
| `nonce` | Minimum 32 hex characters |
| `nonce` | Maximum 128 characters |
| `nonce` | Hexadecimal only |
| `context_id` | Cannot be empty |
| `context_id` | Maximum 256 characters |
| `context_id` | Alphanumeric + `_` `-` `.` |
| `binding` | Maximum 8192 bytes |

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
