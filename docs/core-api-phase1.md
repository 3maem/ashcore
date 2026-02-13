# Core API Phase 1 — Foundation Layer

## Summary

Phase 1 introduces internal diagnostic granularity and centralized header extraction
without changing any wire-level behavior or conformance outputs.

## Error Reconciliation Table

One registry, two layers: wire codes are conformance-locked, internal reasons are diagnostic-only.

| InternalReason | WireCode (AshErrorCode) | http_status | When |
|----------------|-------------------------|-------------|------|
| `HdrMissing` | `ASH_VALIDATION_ERROR` | 485 | Required ASH header not found |
| `HdrMultiValue` | `ASH_VALIDATION_ERROR` | 485 | Header has multiple values |
| `HdrInvalidChars` | `ASH_VALIDATION_ERROR` | 485 | Header contains control chars / newlines |
| `TsParse` | `ASH_TIMESTAMP_INVALID` | 482 | Timestamp not a valid integer |
| `TsSkew` | `ASH_TIMESTAMP_INVALID` | 482 | Timestamp outside allowed clock skew |
| `TsLeadingZeros` | `ASH_TIMESTAMP_INVALID` | 482 | Timestamp has leading zeros |
| `TsOverflow` | `ASH_TIMESTAMP_INVALID` | 482 | Timestamp exceeds MAX_TIMESTAMP |
| `NonceTooShort` | `ASH_VALIDATION_ERROR` | 485 | Nonce < 32 hex chars |
| `NonceTooLong` | `ASH_VALIDATION_ERROR` | 485 | Nonce > 512 chars |
| `NonceInvalidChars` | `ASH_VALIDATION_ERROR` | 485 | Nonce contains non-hex chars |
| `General` | (varies) | (varies) | Existing error paths (backward compat) |

## New Public APIs

### `ash_extract_headers(h: &impl HeaderMapView) -> Result<HeaderBundle, AshError>`

Extracts and validates all required ASH headers from any framework's header map.

**Required headers:** `x-ash-ts`, `x-ash-nonce`, `x-ash-body-hash`, `x-ash-proof`

**Optional headers:** `x-ash-context-id`

**Rules:**
- Case-insensitive lookup
- Single-value enforcement (multi-value → error)
- Whitespace trimming
- Control character / newline rejection

### `ash_validate_nonce(nonce: &str) -> Result<(), AshError>`

Standalone nonce format validator. Extracted from `ash_derive_client_secret` — identical rules.

**Rules:**
- Minimum 32 hex characters (SEC-014)
- Maximum 512 characters (SEC-NONCE-001)
- ASCII hexadecimal charset only (BUG-004)

### `ash_validate_timestamp_format(timestamp: &str) -> Result<u64, AshError>`

Now public. Validates timestamp string format without freshness check.

**Rules:**
- ASCII digits only
- No leading zeros (except "0")
- Valid u64
- Below MAX_TIMESTAMP (year 3000)

### `InternalReason` enum

Diagnostic-only classification. Not exposed on wire. Available via `AshError::reason()`.

### `AshError::with_reason()` constructor

Creates errors with specific `InternalReason` for diagnostic precision.

### `AshError::with_detail()` builder

Adds key-value diagnostic details. Must not contain secrets.

## Conformance Impact

**None.** All 134 vectors pass unchanged. Wire codes, HTTP statuses, and messages are identical.

## Files Changed

| File | Change |
|------|--------|
| `src/errors.rs` | Added `InternalReason`, extended `AshError` with `reason`/`details` |
| `src/headers.rs` | **New** — `HeaderMapView`, `HeaderBundle`, `ash_extract_headers()` |
| `src/validate.rs` | **New** — `ash_validate_nonce()` |
| `src/proof.rs` | `ash_derive_client_secret` calls `ash_validate_nonce()`, `ash_validate_timestamp_format` now public |
| `src/lib.rs` | New module declarations and exports |
