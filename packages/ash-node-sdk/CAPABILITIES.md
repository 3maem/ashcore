# ASH Node SDK v1.0.0 — Capabilities

## Core Capability

Cryptographically bind an API request's identity, endpoint, timestamp, and payload into an unforgeable proof.

## What It Provides

### 1. Request Integrity
Prove the payload wasn't tampered with.
- Full-body hashing (SHA-256) ensures any modification is detected
- JSON canonicalization (RFC 8785) makes hash deterministic regardless of key order or formatting

### 2. Endpoint Binding
Proof is locked to a specific API route.
- `POST /api/transfer` proof cannot be reused on `POST /api/admin`
- Method + path + query are all part of the cryptographic binding

### 3. Replay Prevention
Timestamp is baked into the proof.
- Same request at a different time produces a different proof
- Freshness validation rejects old proofs (configurable window)

### 4. Client Authentication
Only someone with the nonce can produce a valid proof.
- Server issues nonce → client derives secret → client builds proof → server verifies
- No shared secret transmitted over the wire

### 5. Scoped Proofs
Protect specific fields, not just the whole body.
- Prove that `amount` and `recipient` are untampered, even if other fields change
- Useful for partial updates where only certain fields matter

### 6. Request Chaining
Prove sequence integrity.
- Each proof references the previous one via chain hash
- Detects skipped, reordered, or injected requests in a sequence

## What It Prevents

| Attack | How ASH Stops It |
|--------|-----------------|
| Payload tampering | Body hash changes → proof invalid |
| Replay attacks | Timestamp in proof → old proofs rejected |
| Endpoint hijacking | Binding in proof → wrong route rejected |
| Method swapping (GET→POST) | Method in binding → mismatch detected |
| Parameter injection | Full-body hash catches any added/removed fields |
| Proof forgery | HMAC-SHA256 → can't forge without the nonce |
| Cross-context reuse | Context ID in secret derivation → different contexts = different secrets |
| Chain manipulation | Chain hash → skipped/reordered requests detected |
| Timing attacks | Constant-time comparison on all proof verification |
| DoS via large payloads | Size limits on JSON (10MB), nesting (64), query params (1024) |
| Injection attacks | Input validation on nonce, context ID, binding, timestamps |

## What It Does NOT Do (Phase 2)

- No automatic middleware integration (you call functions manually)
- No nonce lifecycle management (issue, store, expire, revoke)
- No HTTP header extraction (you parse headers yourself)
- No rate limiting or IP binding enforcement

Phase 1 gives you the cryptographic engine. You wire it into your server yourself. Phase 2 adds plug-and-play integration.
