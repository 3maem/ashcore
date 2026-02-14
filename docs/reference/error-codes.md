# ASH Error Code Specification

**Version:** 1.0.0
**Date:** 2026-02-07

This document defines the standard error codes used across all ASH SDK implementations to ensure interoperability and consistent error handling.

---

## Overview

All ASH SDKs MUST implement the error codes defined in this specification. Error codes are used to communicate specific failure conditions during request verification.

Every ASH error code maps to a **unique** HTTP status code for unambiguous identification — no shared codes. Each error is identifiable by HTTP status alone.

## Error Code Format

All error codes MUST:
- Use the `ASH_` prefix
- Use `SCREAMING_SNAKE_CASE` format
- Be returned as strings in API responses

Example: `ASH_CONTEXT_EXPIRED`

---

## Standard Error Codes

## Error Categories

ASH error codes are organized into categories with dedicated HTTP status code ranges:

| Category | HTTP Range | Purpose |
|----------|------------|---------|
| Context errors | 450-459 | Context lifecycle issues |
| Seal/Proof errors | 460-469 | Cryptographic verification failures |
| Binding errors | 461 | Endpoint binding mismatch |
| Verification errors | 473-479 | Scope/chain/field verification issues |
| Format/Protocol errors | 480-486 | Malformed requests, validation, canonicalization |

---

## Context Errors (450-459)

### ASH_CTX_NOT_FOUND

**HTTP Status:** 450

The provided `contextId` does not exist or is unknown to the server.

**Possible Causes:**
- Invalid or malformed contextId
- Context already consumed (single-use)
- Context store reset or cleared
- Typo in contextId

**Client Action:** Request a new context

---

### ASH_CTX_EXPIRED

**HTTP Status:** 451

The context exists but has exceeded its TTL (time-to-live).

**Possible Causes:**
- Request sent after context expiration
- Client/server clock drift beyond tolerance
- Network latency caused delay

**Client Action:** Request a new context with appropriate TTL

---

### ASH_CTX_ALREADY_USED

**HTTP Status:** 452

The context or proof has already been successfully consumed.

**Possible Causes:**
- Replay attack attempt
- Duplicate request submission (e.g., double-click)
- Network retry without obtaining new context

**Client Action:** Request a new context for each request

---

## Seal/Proof Errors (460-469)

### ASH_PROOF_INVALID

**HTTP Status:** 460

The provided proof does not match the expected value.

**Possible Causes:**
- Payload modified after proof generation
- Canonicalization mismatch between client and server
- Incorrect mode or binding used
- Wrong client secret
- Timestamp mismatch

**Client Action:** Verify proof generation matches server expectations

---

## Binding Errors (461)

### ASH_BINDING_MISMATCH

**HTTP Status:** 461

The request does not match the binding associated with the context.

**Possible Causes:**
- Request sent to different endpoint than context was issued for
- HTTP method mismatch (e.g., POST vs PUT)
- Query string mismatch
- Context reused for another operation

**Client Action:** Ensure context binding matches request endpoint

### ASH_SCOPE_MISMATCH

**HTTP Status:** 473

The scope hash does not match the expected scoped fields (v2.2+).

**Possible Causes:**
- Scoped fields modified
- Incorrect scope specification
- Scope hash calculation error

**Client Action:** Verify scoped fields match server policy

---

### ASH_CHAIN_BROKEN

**HTTP Status:** 474

The request chain verification failed (v2.3+).

**Possible Causes:**
- Previous proof missing or invalid
- Chain hash mismatch
- Out-of-order request in chain

**Client Action:** Ensure correct previous proof is provided

---

### ASH_SCOPED_FIELD_MISSING

**HTTP Status:** 475

A required scoped field is missing from the payload (v2.2+, strict mode).

**Possible Causes:**
- Payload is missing a field required by the scope policy
- Field name typo in payload or scope definition
- Scope policy updated but client not aware

**Client Action:** Ensure all scoped fields are present in the request payload

---

## Format/Protocol Errors (480-486)

### ASH_TIMESTAMP_INVALID

**HTTP Status:** 482

The timestamp validation failed.

**Possible Causes:**
- Timestamp outside allowed drift window
- Invalid timestamp format
- Client/server clock drift

**Client Action:** Ensure timestamps are synchronized

---

### ASH_PROOF_MISSING

**HTTP Status:** 483

The request did not include a required proof value.

**Possible Causes:**
- Missing `X-ASH-Proof` header
- Client integration error
- Middleware misconfiguration

**Client Action:** Include proof in request headers

---

## Format/Protocol Errors (484-486)

### ASH_CANONICALIZATION_ERROR

**HTTP Status:** 484

The payload could not be canonicalized deterministically.

**Possible Causes:**
- Invalid JSON syntax
- Unsupported payload structure
- Non-deterministic serialization
- Character encoding issues

**Client Action:** Verify payload is valid and use SDK canonicalization functions

---

### ASH_VALIDATION_ERROR

**HTTP Status:** 485

Input validation failure. A required input parameter is missing, empty, or malformed.

**Possible Causes:**
- Empty or missing required parameter (nonce, context_id, binding, etc.)
- Parameter format validation failure
- Parameter exceeds maximum length

**Client Action:** Check all required parameters are present and correctly formatted

---

### ASH_MODE_VIOLATION

**HTTP Status:** 486

The request violates the security mode constraints.

**Possible Causes:**
- Strict mode requires nonce but none provided
- Mode mismatch between client and server
- Invalid mode value

**Client Action:** Use correct security mode settings

---

### ASH_UNSUPPORTED_CONTENT_TYPE

**HTTP Status:** 415 Unsupported Media Type

The request content type is not supported for ASH verification.

**Possible Causes:**
- Content-Type header missing or invalid
- Unsupported media type (not JSON or form-urlencoded)

**Client Action:** Use supported content type (application/json or application/x-www-form-urlencoded)

---

### ASH_INTERNAL_ERROR

**HTTP Status:** 500

An internal server error occurred during ASH processing.

**Possible Causes:**
- Random number generation (RNG) failure
- System time unavailable
- Unexpected internal state

**Client Action:** Retry the request; if persistent, contact server administrator

---

## HTTP Status Code Summary

Every ASH error code maps to a **unique** HTTP status code for unambiguous identification:

| Error Code | HTTP Status | Category |
|------------|-------------|----------|
| `ASH_CTX_NOT_FOUND` | 450 | Context |
| `ASH_CTX_EXPIRED` | 451 | Context |
| `ASH_CTX_ALREADY_USED` | 452 | Context |
| `ASH_PROOF_INVALID` | 460 | Seal |
| `ASH_BINDING_MISMATCH` | 461 | Binding |
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

## Language-Specific Implementation Guidelines

### Error Code Constants

Each SDK MUST define constants/enums for all error codes:

**Rust:**
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
    ScopedFieldMissing,    // HTTP 475
    CanonicalizationError, // HTTP 484
    ValidationError,       // HTTP 485
    ModeViolation,         // HTTP 486
    UnsupportedContentType,// HTTP 415
    InternalError,         // HTTP 500
}
```

**TypeScript/JavaScript:**
```typescript
type AshErrorCode =
  | 'ASH_CTX_NOT_FOUND'           // HTTP 450
  | 'ASH_CTX_EXPIRED'             // HTTP 451
  | 'ASH_CTX_ALREADY_USED'        // HTTP 452
  | 'ASH_PROOF_INVALID'           // HTTP 460
  | 'ASH_BINDING_MISMATCH'        // HTTP 461
  | 'ASH_SCOPE_MISMATCH'          // HTTP 473
  | 'ASH_CHAIN_BROKEN'            // HTTP 474
  | 'ASH_TIMESTAMP_INVALID'       // HTTP 482
  | 'ASH_PROOF_MISSING'           // HTTP 483
  | 'ASH_SCOPED_FIELD_MISSING'   // HTTP 475
  | 'ASH_CANONICALIZATION_ERROR'  // HTTP 484
  | 'ASH_VALIDATION_ERROR'        // HTTP 485
  | 'ASH_MODE_VIOLATION'          // HTTP 486
  | 'ASH_UNSUPPORTED_CONTENT_TYPE'// HTTP 415
  | 'ASH_INTERNAL_ERROR';         // HTTP 500
```

---

## Error Response Format

SDKs SHOULD return errors in this JSON format:

```json
{
  "error": {
    "code": "ASH_CTX_EXPIRED",
    "message": "Context has expired",
    "details": {
      "contextId": "ash_abc123",
      "expiredAt": "2026-01-28T12:00:00Z"
    }
  }
}
```

**Fields:**
- `code` (required): One of the standard error codes
- `message` (required): Human-readable error description
- `details` (optional): Additional context-specific information

---

## Security Considerations

### Error Message Disclosure

- **Server-side logging**: Log detailed error information including contextId, binding, timestamps
- **Client-facing responses**: Return only the error code and generic message
- **Never expose**: Internal state, nonces, or cryptographic details in error responses

### Timing Attack Prevention

Error responses SHOULD be returned in constant time to prevent timing-based information disclosure about:
- Whether a contextId exists
- How close a proof was to being valid
- The stage at which verification failed

---

## Migration Notes

### From Legacy Error Codes

If your SDK uses different error codes, map them to the standard codes:

| Legacy (Node.js) | Standard |
|------------------|----------|
| `MISSING_CONTEXT_ID` | `ASH_CTX_NOT_FOUND` |
| `CONTEXT_USED` | `ASH_CTX_ALREADY_USED` |
| `INVALID_CONTEXT` | `ASH_CTX_NOT_FOUND` |
| `PROOF_MISMATCH` | `ASH_PROOF_INVALID` |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-07 | Unique HTTP status codes for all errors; initial stable release |

---

**Document maintained by:** 3maem Co. | شركة عمائم
