# Core API Phase 3 — High-Level Build & Verify

## Summary

Phase 3 introduces two orchestration functions that replace per-middleware
reimplementations of the ASH pipeline. No new logic — only assembly of
existing Core primitives in fixed execution order.

## Phase 3-A: `verify_incoming_request`

Server-side request verification. Middlewares become thin wrappers.

### Input: `VerifyRequestInput<H: HeaderMapView>`

| Field | Type | Description |
|-------|------|-------------|
| `headers` | `&H` | HTTP headers (HeaderMapView) |
| `method` | `&str` | HTTP method |
| `path` | `&str` | URL path |
| `raw_query` | `&str` | Raw query string |
| `canonical_body` | `&str` | Canonicalized body |
| `nonce` | `&str` | Server nonce (from store) |
| `context_id` | `&str` | Context ID (from store) |
| `max_age_seconds` | `u64` | Max timestamp age |
| `clock_skew_seconds` | `u64` | Clock skew tolerance |

### Output: `VerifyResult`

| Field | Type | Description |
|-------|------|-------------|
| `ok` | `bool` | Whether verification passed |
| `error` | `Option<AshError>` | Error if failed |
| `meta` | `Option<VerifyMeta>` | Debug metadata (debug builds only) |

### Execution Order (Locked)

1. Extract headers (ts, body-hash, proof)
2. Validate timestamp format
3. Validate timestamp freshness
4. Validate nonce format
5. Normalize binding
6. Hash canonical body
7. Compare body hashes (timing-safe)
8. Verify proof (re-derive + compare)
9. Return ok

First error wins. No error accumulation.

## Phase 3-B: `build_request_proof`

Client-side proof building. SDKs become thin wrappers.

### Input: `BuildRequestInput`

| Field | Type | Description |
|-------|------|-------------|
| `method` | `&str` | HTTP method |
| `path` | `&str` | URL path |
| `raw_query` | `&str` | Raw query string |
| `canonical_body` | `&str` | Canonicalized body |
| `nonce` | `&str` | Server nonce |
| `context_id` | `&str` | Context ID |
| `timestamp` | `&str` | Unix timestamp |
| `scope` | `Option<&[&str]>` | Scope fields (optional) |
| `previous_proof` | `Option<&str>` | Chain previous proof (optional) |

### Output: `BuildRequestResult`

| Field | Type | Description |
|-------|------|-------------|
| `proof` | `String` | 64-char hex proof |
| `body_hash` | `String` | 64-char hex body hash |
| `binding` | `String` | Normalized binding |
| `timestamp` | `String` | Echoed timestamp |
| `nonce` | `String` | Echoed nonce |
| `scope_hash` | `String` | Scope hash (empty if no scope) |
| `chain_hash` | `String` | Chain hash (empty if no chain) |
| `meta` | `Option<BuildMeta>` | Debug metadata |

### Execution Order (Locked)

1. Validate nonce format
2. Validate timestamp format
3. Normalize binding
4. Hash canonical body
5. Derive client secret
6. Build proof (basic / scoped / unified)
7. Return result

### Proof Modes

- **Basic**: No scope, no chain → standard `ash_build_proof`
- **Scoped**: `scope` provided → `ash_build_proof_scoped` (returns scope_hash)
- **Chained**: `previous_proof` provided → `ash_build_proof_unified` (returns chain_hash)
- **Unified**: Both scope and chain → `ash_build_proof_unified`

## Build↔Verify Contract

What `build_request_proof` produces, `verify_incoming_request` accepts.
This is proven by 8 integration tests in `phase3_build_verify_roundtrip.rs`.

## Conformance Impact

**None.** All 134 vectors pass unchanged.

## Files Changed

| File | Change |
|------|--------|
| `src/verify.rs` | **New** — Phase 3-A |
| `src/build.rs` | **New** — Phase 3-B |
| `src/lib.rs` | Module declarations and exports |
| `tests/phase3_build_verify_roundtrip.rs` | **New** — integration tests |
