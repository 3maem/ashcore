# ASH Error Code Reference

**Version:** v1.0.0-beta

Every ASH error code maps to a **unique** HTTP status code for unambiguous identification.

---

## Error Code Format

All error codes:
- Use the `ASH_` prefix
- Use `SCREAMING_SNAKE_CASE` format
- Are returned as strings in API responses

---

## Error Categories

| Category | HTTP Range | Purpose |
|----------|------------|---------|
| Context errors | 450-459 | Context lifecycle issues |
| Proof errors | 460-469 | Cryptographic verification failures |
| Verification errors | 473-479 | Scope/chain/field verification issues |
| Format errors | 480-486 | Malformed requests, validation, canonicalization |

---

## Context Errors (450-459)

### ASH_CTX_NOT_FOUND — HTTP 450

The provided `contextId` does not exist or is unknown to the server.

**Causes:** Invalid contextId, context already consumed, context store cleared.

**Action:** Request a new context.

---

### ASH_CTX_EXPIRED — HTTP 451

The context exists but has exceeded its TTL.

**Causes:** Request sent after expiration, clock drift, network delay.

**Action:** Request a new context with appropriate TTL.

---

### ASH_CTX_ALREADY_USED — HTTP 452

The context has already been consumed (single-use enforcement).

**Causes:** Replay attack, duplicate submission, network retry without new context.

**Action:** Request a new context for each request.

---

## Proof Errors (460-461)

### ASH_PROOF_INVALID — HTTP 460

The proof does not match the expected value.

**Causes:** Payload modified after signing, canonicalization mismatch, wrong secret, timestamp mismatch.

**Action:** Verify proof generation matches server expectations.

---

### ASH_BINDING_MISMATCH — HTTP 461

The request does not match the binding associated with the context.

**Causes:** Wrong endpoint, method mismatch, query string mismatch.

**Action:** Ensure context binding matches request endpoint.

---

## Verification Errors (473-475)

### ASH_SCOPE_MISMATCH — HTTP 473

The scope hash does not match the expected scoped fields.

**Causes:** Scoped fields modified, incorrect scope specification, hash calculation error.

**Action:** Verify scoped fields match server policy.

---

### ASH_CHAIN_BROKEN — HTTP 474

Request chain verification failed.

**Causes:** Previous proof missing or invalid, chain hash mismatch, out-of-order request.

**Action:** Ensure correct previous proof is provided.

---

### ASH_SCOPED_FIELD_MISSING — HTTP 475

A required scoped field is missing from the payload (strict mode).

**Causes:** Missing field in payload, field name typo, scope policy updated.

**Action:** Ensure all scoped fields are present in the request payload.

---

## Format Errors (482-486)

### ASH_TIMESTAMP_INVALID — HTTP 482

Timestamp validation failed.

**Causes:** Outside allowed drift window, invalid format, clock drift.

**Action:** Synchronize clocks, use valid Unix timestamp (seconds).

---

### ASH_PROOF_MISSING — HTTP 483

The request did not include a required header.

**Causes:** Missing `x-ash-proof` or other required header, middleware misconfiguration.

**Action:** Include all 5 required headers in request.

---

### ASH_CANONICALIZATION_ERROR — HTTP 484

The payload could not be canonicalized.

**Causes:** Invalid JSON, unsupported structure, encoding issues.

**Action:** Verify payload is valid and use SDK canonicalization functions.

---

### ASH_VALIDATION_ERROR — HTTP 485

Input validation failure.

**Causes:** Empty or missing parameter, format failure, parameter exceeds max length.

**Action:** Check all required parameters are present and correctly formatted.

---

### ASH_MODE_VIOLATION — HTTP 486

The request violates security mode constraints.

**Causes:** Strict mode requires nonce but none provided, mode mismatch.

**Action:** Use correct security mode settings.

---

## Standard HTTP Errors

### ASH_UNSUPPORTED_CONTENT_TYPE — HTTP 415

Content type not supported.

**Causes:** Missing Content-Type, unsupported media type.

**Action:** Use `application/json` or `application/x-www-form-urlencoded`.

---

### ASH_INTERNAL_ERROR — HTTP 500

Internal server error during ASH processing.

**Causes:** RNG failure, system time unavailable.

**Action:** Retry; if persistent, contact server administrator.

---

## Summary Table

| Error Code | HTTP | Category |
|------------|------|----------|
| `ASH_CTX_NOT_FOUND` | 450 | Context |
| `ASH_CTX_EXPIRED` | 451 | Context |
| `ASH_CTX_ALREADY_USED` | 452 | Context |
| `ASH_PROOF_INVALID` | 460 | Proof |
| `ASH_BINDING_MISMATCH` | 461 | Proof |
| `ASH_SCOPE_MISMATCH` | 473 | Verification |
| `ASH_CHAIN_BROKEN` | 474 | Verification |
| `ASH_SCOPED_FIELD_MISSING` | 475 | Verification |
| `ASH_TIMESTAMP_INVALID` | 482 | Format |
| `ASH_PROOF_MISSING` | 483 | Format |
| `ASH_CANONICALIZATION_ERROR` | 484 | Format |
| `ASH_VALIDATION_ERROR` | 485 | Format |
| `ASH_MODE_VIOLATION` | 486 | Format |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Standard |
| `ASH_INTERNAL_ERROR` | 500 | Standard |

---

## Implementation

**Rust:**
```rust
pub enum AshErrorCode {
    CtxNotFound,           // 450
    CtxExpired,            // 451
    CtxAlreadyUsed,        // 452
    ProofInvalid,          // 460
    BindingMismatch,       // 461
    ScopeMismatch,         // 473
    ChainBroken,           // 474
    ScopedFieldMissing,    // 475
    TimestampInvalid,      // 482
    ProofMissing,          // 483
    CanonicalizationError, // 484
    ValidationError,       // 485
    ModeViolation,         // 486
    UnsupportedContentType,// 415
    InternalError,         // 500
}
```

**TypeScript:**
```typescript
export enum AshErrorCode {
    CTX_NOT_FOUND = 'ASH_CTX_NOT_FOUND',           // 450
    CTX_EXPIRED = 'ASH_CTX_EXPIRED',               // 451
    CTX_ALREADY_USED = 'ASH_CTX_ALREADY_USED',     // 452
    PROOF_INVALID = 'ASH_PROOF_INVALID',            // 460
    BINDING_MISMATCH = 'ASH_BINDING_MISMATCH',      // 461
    SCOPE_MISMATCH = 'ASH_SCOPE_MISMATCH',          // 473
    CHAIN_BROKEN = 'ASH_CHAIN_BROKEN',              // 474
    SCOPED_FIELD_MISSING = 'ASH_SCOPED_FIELD_MISSING', // 475
    TIMESTAMP_INVALID = 'ASH_TIMESTAMP_INVALID',    // 482
    PROOF_MISSING = 'ASH_PROOF_MISSING',            // 483
    CANONICALIZATION_ERROR = 'ASH_CANONICALIZATION_ERROR', // 484
    VALIDATION_ERROR = 'ASH_VALIDATION_ERROR',      // 485
    MODE_VIOLATION = 'ASH_MODE_VIOLATION',           // 486
    UNSUPPORTED_CONTENT_TYPE = 'ASH_UNSUPPORTED_CONTENT_TYPE', // 415
    INTERNAL_ERROR = 'ASH_INTERNAL_ERROR',           // 500
}
```

---

## Security Notes

- **Server-side logging**: Log detailed error info (contextId, binding, timestamps)
- **Client-facing responses**: Return only error code and generic message
- **Never expose**: Nonces, secrets, or cryptographic details in error responses
- **Timing**: Error responses should be returned in constant time

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
