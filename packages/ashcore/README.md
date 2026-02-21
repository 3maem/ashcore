# ashcore

[![Crates.io](https://img.shields.io/crates/v/ashcore.svg)](https://crates.io/crates/ashcore)
[![Documentation](https://docs.rs/ashcore/badge.svg)](https://docs.rs/ashcore)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](../../LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0--beta-blue)](../../CHANGELOG.md)

> **⚠️ Beta Notice:** This is v1.0.0-beta. Feature-complete but may undergo internal refinements. Not recommended for production-critical environments yet.

**Developed by 3maem | عمائم**

Core Rust implementation of ASH (Application Security Hash) for request integrity verification and anti-replay protection.

## Overview

ASH provides the foundational cryptographic primitives and canonicalization functions for request integrity verification. It ensures byte-identical output across all platforms through deterministic processing.

## Features

- **RFC 8785 Compliant**: JSON Canonicalization Scheme (JCS) for deterministic serialization
- **Cryptographic Proofs**: HMAC-SHA256 based proof generation and verification
- **Timing Attack Resistance**: Constant-time comparison for all security-sensitive operations
- **Anti-Replay Protection**: Single-use context enforcement with TTL
- **Field Scoping**: Protect specific fields while allowing others to change
- **Request Chaining**: Link sequential requests cryptographically
- **Zero Dependencies (Runtime)**: Pure Rust with no C dependencies

## Installation

```bash
cargo add ashcore
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
ashcore = "1.0.0"
```

## Examples

For usage examples, see the [`examples/`](../../examples/) directory and the [API Documentation](https://docs.rs/ashcore).

## API Reference

### Core Proof Functions

| Function | Description |
|----------|-------------|
| `ash_derive_client_secret(nonce, ctx_id, binding)` | Derive HMAC key from nonce |
| `ash_build_proof(secret, timestamp, binding, body_hash)` | Build HMAC-SHA256 proof |
| `ash_verify_proof(nonce, ctx_id, binding, timestamp, body_hash, proof)` | Verify proof |

### High-Level API (v1.0.0)

| Function | Description |
|----------|-------------|
| `build_request_proof(input)` | Client-side: build proof in one call |
| `verify_incoming_request(input)` | Server-side: verify request in one call |

### Scoped Proof Functions

| Function | Description |
|----------|-------------|
| `ash_build_proof_scoped(...)` | Build proof protecting specific fields |
| `ash_verify_proof_scoped(...)` | Verify scoped proof |
| `ash_extract_scoped_fields(payload, scope)` | Extract fields for scoping |
| `ash_hash_scoped_body(payload, scope)` | Hash only scoped fields |

### Unified Proof Functions (Scoping + Chaining)

| Function | Description |
|----------|-------------|
| `ash_build_proof_unified(...)` | Build proof with scoping + chaining |
| `ash_verify_proof_unified(...)` | Verify unified proof |
| `ash_hash_proof(proof)` | Compute chain hash |

### Canonicalization Functions

| Function | Description |
|----------|-------------|
| `ash_canonicalize_json(input)` | Canonicalize JSON (RFC 8785) |
| `ash_canonicalize_query(query)` | Canonicalize URL query string |
| `ash_canonicalize_urlencoded(input)` | Canonicalize form data |
| `ash_normalize_binding(method, path, query)` | Normalize endpoint binding |

### Enriched API (v1.0.0)

| Function | Description |
|----------|-------------|
| `ash_canonicalize_query_enriched(query)` | Canonical query with metadata |
| `ash_hash_body_enriched(body)` | Body hash with metadata |
| `ash_normalize_binding_enriched(method, path, query)` | Binding with parsed components |

### Utility Functions

| Function | Description |
|----------|-------------|
| `ash_generate_nonce(bytes)` | Generate cryptographic nonce |
| `ash_generate_context_id()` | Generate unique context ID |
| `ash_hash_body(body)` | SHA-256 hash of body |
| `ash_hash_scope(scope)` | Hash scope field list |
| `ash_timing_safe_equal(a, b)` | Constant-time comparison |
| `ash_validate_timestamp(ts, now, max_age, skew)` | Validate timestamp |
| `ash_validate_nonce(nonce)` | Validate nonce format |
| `ash_normalize_binding_value(type, value)` | Generic binding normalizer |

### Testkit (v1.0.0)

| Function | Description |
|----------|-------------|
| `load_vectors(data)` | Load conformance vectors |
| `run_vectors(vectors, adapter)` | Run vectors against any adapter |
| `AshAdapter` trait | 12-method trait for SDK testing |

### Types

| Type | Description |
|------|-------------|
| `AshMode` | Security mode: `Minimal`, `Balanced`, `Strict` |
| `AshError` | Error type with code, message, reason, retryable |
| `AshErrorCode` | Error codes (e.g., `CtxNotFound`, `ProofInvalid`) |
| `UnifiedProofResult` | Result from unified proof functions |
| `BindingType` | Binding types: Route, Ip, Device, Session, User, Tenant, Custom |

### Error Codes

| Code | HTTP | Retryable | Description |
|------|------|-----------|-------------|
| `CtxNotFound` | 450 | No | Context not found |
| `CtxExpired` | 451 | No | Context expired |
| `CtxAlreadyUsed` | 452 | No | Replay detected |
| `ProofInvalid` | 460 | No | Proof verification failed |
| `BindingMismatch` | 461 | No | Endpoint binding mismatch |
| `ScopeMismatch` | 473 | No | Scope hash mismatch |
| `ChainBroken` | 474 | No | Chain broken |
| `ScopedFieldMissing` | 475 | No | Required scoped field missing |
| `TimestampInvalid` | 482 | Yes | Clock skew / format |
| `ProofMissing` | 483 | No | Missing header |
| `CanonicalizationError` | 484 | No | Malformed payload |
| `ValidationError` | 485 | No | Input validation |
| `ModeViolation` | 486 | No | Mode mismatch |
| `UnsupportedContentType` | 415 | No | Wrong content type |
| `InternalError` | 500 | Yes | Transient server issue |

## Cryptographic Details

| Component | Algorithm |
|-----------|-----------|
| Proof Generation | HMAC-SHA256 |
| Body Hashing | SHA-256 |
| Nonce Generation | CSPRNG (`getrandom`) |
| Comparison | Constant-time (`subtle` crate) |
| Key Derivation | HMAC-based |

## Thread Safety

All functions are thread-safe and can be called concurrently.

## Security Notes

ASH verifies **what** is being submitted, not **who** is submitting it.
It should be used alongside authentication systems (JWT, OAuth, etc.).

## Documentation

- **[SPECIFICATION.md](SPECIFICATION.md)** - Complete protocol specification for SDK implementers
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and migration guides
- **[API Documentation](https://docs.rs/ashcore)** - Full Rust API docs

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.

## Links

- [Website](https://www.ashcore.ai)
- [Main Repository](https://github.com/3maem/ashcore)
- [API Documentation](https://docs.rs/ashcore)
- [Protocol Specification](SPECIFICATION.md)
- [Security Policy](../../SECURITY.md)

© 3maem | عمائم
