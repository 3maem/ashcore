# ASH SDK Implementation Reference v2.3.4

This document provides the authoritative reference for implementing ASH SDKs across all languages. All SDKs (Node.js, Python, Go, PHP, WASM) and middlewares MUST implement these specifications to ensure cross-SDK interoperability.

**Reference Implementation**: Rust `ashcore` (packages/ashcore)

---

## Table of Contents

1. [Constants](#1-constants)
2. [Input Validation](#2-input-validation)
3. [Core Functions](#3-core-functions)
4. [Canonicalization](#4-canonicalization)
5. [Scope Handling](#5-scope-handling)
6. [Timestamp Validation](#6-timestamp-validation)
7. [Constant-Time Comparison](#7-constant-time-comparison)
8. [Error Codes](#8-error-codes)
9. [Security Checklist](#9-security-checklist)

---

## 1. Constants

All SDKs MUST define these constants with the EXACT values specified:

### 1.1 Security Limits

```
MIN_NONCE_BYTES           = 16        // Minimum bytes for nonce generation
MIN_NONCE_HEX_CHARS       = 32        // Minimum hex chars in derive_client_secret
MAX_NONCE_LENGTH          = 512       // SEC-NONCE-001: Maximum nonce length
MAX_CONTEXT_ID_LENGTH     = 256       // SEC-CTX-001: Maximum context_id length
MAX_BINDING_LENGTH        = 8192      // SEC-AUDIT-004: Maximum binding length (8KB)
MAX_SCOPE_FIELD_NAME_LENGTH = 64      // SEC-SCOPE-001: Maximum individual field name
MAX_TOTAL_SCOPE_LENGTH    = 4096      // SEC-SCOPE-001: Maximum total scope string
MAX_SCOPE_FIELDS          = 100       // BUG-018: Maximum number of scope fields
MAX_ARRAY_INDEX           = 10000     // SEC-011: Maximum array index in scope paths
MAX_TOTAL_ARRAY_ALLOCATION = 10000    // BUG-036: Maximum total array elements
MAX_SCOPE_PATH_DEPTH      = 32        // SEC-019: Maximum dot-separated path depth
MAX_RECURSION_DEPTH       = 64        // VULN-001: Maximum JSON nesting depth
MAX_PAYLOAD_SIZE          = 10485760  // VULN-002: Maximum payload size (10MB)
MAX_TIMESTAMP             = 32503680000  // SEC-018: Maximum timestamp (year 3000)
SHA256_HEX_LENGTH         = 64        // Expected length of SHA-256 hex output
```

### 1.2 Protocol Constants

```
ASH_SDK_VERSION           = "2.3.4"
ASH_VERSION_PREFIX        = "ASHv2.1"
SCOPE_FIELD_DELIMITER     = '\x1F'    // Unit separator (U+001F) - CRITICAL for cross-SDK
```

### 1.3 Timing-Safe Comparison Constants

```
CHUNK_SIZE                = 256       // Bytes per comparison chunk
FIXED_ITERATIONS          = 8         // BUG-030/BUG-037: Always 8 iterations
FIXED_WORK_SIZE           = 2048      // Total bytes compared (256 * 8)
```

---

## 2. Input Validation

### 2.1 Nonce Validation (`derive_client_secret`)

```
MUST validate:
1. Length >= MIN_NONCE_HEX_CHARS (32)
   Error: "Nonce must be at least 32 hex characters (16 bytes) for adequate entropy"

2. Length <= MAX_NONCE_LENGTH (512)
   Error: "Nonce exceeds maximum length of 512 characters"

3. All characters are hexadecimal (0-9, a-f, A-F)
   Error: "Nonce must contain only hexadecimal characters (0-9, a-f, A-F)"
```

### 2.2 Context ID Validation (`derive_client_secret`)

```
MUST validate:
1. Not empty
   Error: "context_id cannot be empty"

2. Length <= MAX_CONTEXT_ID_LENGTH (256)
   Error: "context_id exceeds maximum length of 256 characters"

3. Only ASCII alphanumeric + underscore + hyphen + dot
   Regex: ^[A-Za-z0-9_.-]+$
   Error: "context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot"

4. Does not contain '|' (redundant after #3, but explicit check recommended)
   Error: "context_id must not contain '|' character (delimiter collision risk)"
```

### 2.3 Binding Validation

```
MUST validate:
1. Not empty (in build_proof, build_proof_scoped, build_proof_unified)
   Error: "binding cannot be empty"

2. Length <= MAX_BINDING_LENGTH (8192)
   Error: "binding exceeds maximum length of 8192 bytes"
```

### 2.4 Body Hash Validation (`build_proof`)

```
MUST validate:
1. Length == SHA256_HEX_LENGTH (64)
   Error: "body_hash must be 64 hex characters (SHA-256), got {length}"

2. All characters are hexadecimal
   Error: "body_hash must contain only hexadecimal characters (0-9, a-f, A-F)"
```

### 2.5 Timestamp Validation

```
MUST validate:
1. Not empty
   Error: "Timestamp cannot be empty"

2. All characters are digits (0-9)
   Error: "Timestamp must contain only digits (0-9)"

3. No leading zeros (except "0" itself)
   Error: "Timestamp must not have leading zeros"

4. Parses as unsigned 64-bit integer
   Error: "Timestamp must be a valid integer"

5. Value <= MAX_TIMESTAMP (32503680000)
   Error: "Timestamp exceeds maximum allowed value"
```

### 2.6 Scope Field Validation

```
MUST validate:
1. Field name not empty
   Error: "Scope field names cannot be empty"

2. Field name length <= MAX_SCOPE_FIELD_NAME_LENGTH (64)
   Error: "Scope field name exceeds maximum length of 64 characters"

3. Field name does not contain SCOPE_FIELD_DELIMITER (\x1F)
   Error: "Scope field contains reserved delimiter character (U+001F)"

4. Total scope length <= MAX_TOTAL_SCOPE_LENGTH (4096)
   Error: "Total scope length exceeds maximum of 4096 bytes"

5. Scope array length <= MAX_SCOPE_FIELDS (100)
   Error: "Scope exceeds maximum of 100 fields"
```

---

## 3. Core Functions

### 3.1 `generate_nonce(bytes)`

```
Input:  bytes (integer) - Number of random bytes to generate
Output: String (hex-encoded)
Errors: If bytes < MIN_NONCE_BYTES (16)

Algorithm:
1. Validate bytes >= 16
2. Generate `bytes` cryptographically secure random bytes
3. Return hex-encoded string (lowercase)
```

### 3.2 `generate_context_id()`

```
Output: String - Format "ash_{random_hex}"

Algorithm:
1. Generate 16 random bytes (128 bits)
2. Return "ash_" + hex_encode(bytes)
```

### 3.3 `derive_client_secret(nonce, context_id, binding)`

```
Input:  nonce (string), context_id (string), binding (string)
Output: String (64 hex chars)
Errors: See validation rules in Section 2

Algorithm:
1. Validate nonce (length, hex chars)
2. Validate context_id (length, charset, no delimiter)
3. Validate binding (length)
4. message = context_id + "|" + binding
5. Return hex_encode(HMAC-SHA256(key=nonce_bytes, message=message_bytes))

Note: nonce is used as raw string bytes for HMAC key, NOT decoded from hex
```

### 3.4 `build_proof(client_secret, timestamp, binding, body_hash)`

```
Input:  client_secret, timestamp, binding, body_hash (all strings)
Output: String (64 hex chars - HMAC-SHA256 output)
Errors: See validation rules

Algorithm:
1. Validate client_secret not empty
2. Validate timestamp not empty
3. Validate binding (not empty, length)
4. Validate body_hash (64 hex chars)
5. message = timestamp + "|" + binding + "|" + body_hash
6. Return hex_encode(HMAC-SHA256(key=client_secret_bytes, message=message_bytes))
```

### 3.5 `verify_proof(nonce, context_id, binding, timestamp, body_hash, client_proof)`

```
Input:  All strings
Output: Boolean (true if valid)
Errors: Validation errors

Algorithm:
1. Validate timestamp format (validate_timestamp_format)
2. client_secret = derive_client_secret(nonce, context_id, binding)
3. expected_proof = build_proof(client_secret, timestamp, binding, body_hash)
4. Return timing_safe_equal(expected_proof, client_proof)
```

### 3.6 `hash_body(canonical_body)`

```
Input:  canonical_body (string)
Output: String (64 hex chars - SHA-256)

Algorithm:
1. Return hex_encode(SHA-256(canonical_body_bytes))
```

---

## 4. Canonicalization

### 4.1 JSON Canonicalization (RFC 8785)

```
Rules:
1. Parse JSON
2. Validate size <= MAX_PAYLOAD_SIZE (10MB)
3. Validate depth <= MAX_RECURSION_DEPTH (64)
4. Recursively canonicalize:
   - Objects: Sort keys lexicographically (byte order), canonicalize values
   - Arrays: Preserve order, canonicalize elements
   - Strings: Apply Unicode NFC normalization
   - Numbers:
     - Reject NaN and Infinity
     - Convert -0 to 0
     - Convert whole floats to integers (5.0 -> 5) within safe range (±2^53-1)
   - Booleans: Preserve
   - Null: Preserve
5. Serialize to minified JSON (no whitespace)
```

### 4.2 Query String Canonicalization

```
Rules (10 MUST rules):
1. Remove leading '?' if present
2. Strip fragment (#) and everything after
3. Split on '&' to get key=value pairs
4. Handle keys without '=' (treat value as empty string)
5. Percent-decode keys and values (+ is literal plus, NOT space)
6. Apply Unicode NFC normalization to keys and values
7. Sort pairs by key (byte order)
8. Sort by value for duplicate keys (byte order)
9. Re-encode with uppercase percent encoding (%XX)
10. Join with '&' separator
```

### 4.3 Binding Normalization

```
Format: METHOD|PATH|QUERY

Algorithm:
1. Normalize method to uppercase
2. Normalize path:
   - Percent-decode
   - Collapse multiple slashes (//)
   - Resolve . and .. segments
   - Remove trailing slash (except root /)
   - Re-encode with uppercase percent encoding
3. Canonicalize query string (if present)
4. Return METHOD + "|" + PATH + "|" + CANONICAL_QUERY
```

---

## 5. Scope Handling

### 5.1 Scope Normalization (CRITICAL for cross-SDK)

```
Algorithm:
1. Sort scope array lexicographically (byte order)
2. Remove duplicates
3. Return normalized array

Example:
  Input:  ["z", "a", "b", "a"]
  Output: ["a", "b", "z"]
```

### 5.2 Scope Hash (`hash_scope`)

```
Input:  scope (array of strings)
Output: String (64 hex chars) or empty string if scope is empty

Algorithm:
1. If scope is empty, return ""
2. Validate each field (see Section 2.6)
3. Normalize scope (sort, dedup)
4. Join with SCOPE_FIELD_DELIMITER (\x1F)
5. Return hash_body(joined_string)

CRITICAL: Use \x1F (unit separator), NOT comma!
```

### 5.3 Scoped Field Extraction

```
Input:  payload (JSON Value), scope (array of strings)
Output: JSON Value with only scoped fields

Path Syntax:
- "field"           -> top-level field
- "parent.child"    -> nested field
- "items[0]"        -> array element
- "items[0].id"     -> nested field in array element
- "matrix[0][1]"    -> multi-dimensional array

Algorithm:
1. Validate total allocation <= MAX_TOTAL_ARRAY_ALLOCATION
2. For each scope path:
   a. Split on '.' (max MAX_SCOPE_PATH_DEPTH levels)
   b. Parse array indices (max MAX_ARRAY_INDEX per index)
   c. Extract value from payload
   d. Set value in result, preserving array structure
3. Return result object
```

### 5.4 Build Proof Scoped

```
Message format: timestamp|binding|body_hash|scope_hash

Algorithm:
1. Validate inputs (client_secret, timestamp, binding not empty)
2. Parse payload (empty string -> {})
3. Extract scoped fields
4. Canonicalize scoped payload
5. body_hash = hash_body(canonical_scoped)
6. scope_hash = hash_scope(scope)
7. message = timestamp + "|" + binding + "|" + body_hash + "|" + scope_hash
8. proof = HMAC-SHA256(client_secret, message)
9. Return (proof, scope_hash)
```

### 5.5 Build Proof Unified

```
Message format: timestamp|binding|body_hash|scope_hash|chain_hash

Algorithm:
1. Validate inputs
2. Parse payload (empty string -> {})
3. Extract scoped fields (empty scope = full payload)
4. Canonicalize scoped payload
5. body_hash = hash_body(canonical_scoped)
6. scope_hash = hash_scope(scope)  // empty string if no scope
7. chain_hash = previous_proof ? hash_body(previous_proof) : ""
8. message = timestamp + "|" + binding + "|" + body_hash + "|" + scope_hash + "|" + chain_hash
9. proof = HMAC-SHA256(client_secret, message)
10. Return {proof, scope_hash, chain_hash}
```

### 5.6 Verify Proof Unified - SEC-013 Consistency Validation

```
MUST validate:
1. If scope is empty AND scope_hash is NOT empty:
   Error: ScopeMismatch "scope_hash must be empty when scope is empty"

2. If previous_proof is absent/empty AND chain_hash is NOT empty:
   Error: ChainBroken "chain_hash must be empty when previous_proof is absent"
```

---

## 6. Timestamp Validation

### 6.1 Format Validation (`validate_timestamp_format`)

```
Input:  timestamp (string)
Output: Parsed integer value
Errors: TimestampInvalid

Checks:
1. Not empty
2. Only digits (0-9)
3. No leading zeros (except "0")
4. Parses as u64/long
5. Value <= MAX_TIMESTAMP
```

### 6.2 Freshness Validation (`validate_timestamp`)

```
Input:  timestamp, max_age_seconds, clock_skew_seconds
Output: void (success) or error
Errors: TimestampInvalid

Algorithm:
1. Validate format (validate_timestamp_format)
2. Get current time (now)
3. If ts > now + clock_skew_seconds:
   Error: "Timestamp is in the future"
4. If now > ts AND (now - ts) > max_age_seconds:
   Error: "Timestamp has expired"

Boundary conditions:
- Timestamp exactly max_age_seconds old: VALID (inclusive)
- Timestamp exactly clock_skew_seconds in future: VALID (inclusive)
```

---

## 7. Constant-Time Comparison

### 7.1 Implementation Requirements

```
MUST:
1. Use constant-time length comparison
2. Always perform FIXED_ITERATIONS (8) iterations
3. Process CHUNK_SIZE (256) bytes per iteration
4. Use constant-time conditional selection (not branching)
5. Compare full 2048 bytes regardless of input length

Algorithm:
1. lengths_equal = constant_time_compare(len_a, len_b)
2. result = true
3. For i in 0..FIXED_ITERATIONS:
   a. Create padded_a[256] and padded_b[256] (zero-filled)
   b. Copy available data into padded arrays
   c. chunk_cmp = constant_time_compare(padded_a, padded_b)
   d. in_range = (i * CHUNK_SIZE) < min(len_a, len_b, 2048)
   e. result = conditional_select(result, result & chunk_cmp, in_range)
4. Return lengths_equal AND result

Note: Inputs > 2048 bytes only compare first 2048 bytes (documented limitation)
```

---

## 8. Error Codes

### 8.1 Error Code Enumeration

```
Code                      HTTP Status   Description
─────────────────────────────────────────────────────────────────
ASH_CTX_NOT_FOUND         450          Context not found in store
ASH_CTX_EXPIRED           451          Context has expired
ASH_CTX_ALREADY_USED      452          Context already consumed (replay)
ASH_PROOF_INVALID         460          Proof verification failed
ASH_BINDING_MISMATCH      461          Endpoint doesn't match context
ASH_SCOPE_MISMATCH        473          Scope hash mismatch (v2.2+)
ASH_CHAIN_BROKEN          474          Chain verification failed (v2.3+)
ASH_TIMESTAMP_INVALID     482          Timestamp validation failed
ASH_PROOF_MISSING         483          Required proof not provided
ASH_CANONICALIZATION_ERROR 484         Payload cannot be canonicalized
ASH_MODE_VIOLATION        486          Mode requirements not met
ASH_UNSUPPORTED_CONTENT_TYPE 415       Content type not supported
ASH_VALIDATION_ERROR      485          Input validation failed
ASH_INTERNAL_ERROR        500          Internal error (RNG failure, etc.)
```

### 8.2 Error Message Guidelines

```
1. Never include user input in error messages (SEC-AUDIT-003)
2. Use generic messages that don't leak information
3. Include error code for programmatic handling
4. Map to appropriate HTTP status codes
```

---

## 9. Security Checklist

### 9.1 Input Validation Checklist

```
[ ] Nonce minimum length (32 hex chars)
[ ] Nonce maximum length (512 chars)
[ ] Nonce hex-only validation
[ ] Context ID maximum length (256 chars)
[ ] Context ID charset validation (alphanumeric + _-.)
[ ] Context ID no pipe character
[ ] Binding maximum length (8KB)
[ ] Binding not empty (in proof functions)
[ ] Body hash length (64 hex chars)
[ ] Body hash hex-only validation
[ ] Timestamp format validation
[ ] Timestamp leading zero rejection
[ ] Timestamp maximum value
[ ] Scope field name length (64 chars)
[ ] Scope total length (4096 bytes)
[ ] Scope field count (100 max)
[ ] Scope delimiter validation (\x1F not in field names)
[ ] Array index limit (10000)
[ ] Total array allocation limit (10000)
[ ] Scope path depth limit (32)
[ ] JSON nesting depth limit (64)
[ ] Payload size limit (10MB)
```

### 9.2 Cryptographic Checklist

```
[ ] HMAC-SHA256 for all proof generation
[ ] SHA-256 for all hashing (body, scope, chain)
[ ] Constant-time comparison for all proof verification
[ ] Minimum 128-bit entropy for nonces
[ ] No timing leaks in validation
```

### 9.3 Cross-SDK Compatibility Checklist

```
[ ] Scope delimiter is \x1F (NOT comma)
[ ] Scope normalization (sort + dedup)
[ ] JSON canonicalization uses RFC 8785
[ ] Query string canonicalization (sort key, then value)
[ ] Empty payload treated as {}
[ ] SEC-013 consistency validation
[ ] Timestamp boundary conditions match
```

---

## Appendix A: Test Vectors

### A.1 Scope Hash Test

```
Input scope:  ["z", "a", "b"]
Normalized:   ["a", "b", "z"]
Joined:       "a\x1Fb\x1Fz"
Expected hash: SHA256("a\x1Fb\x1Fz") = <compute>
```

### A.2 Derive Client Secret Test

```
nonce:      "0123456789abcdef0123456789abcdef"
context_id: "ctx_abc123"
binding:    "POST|/api/test|"
message:    "ctx_abc123|POST|/api/test|"
Expected:   HMAC-SHA256(nonce_bytes, message_bytes)
```

### A.3 Build Proof Test

```
client_secret: "abc123..."
timestamp:     "1704067200"
binding:       "POST|/api/test|"
body_hash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
message:       "1704067200|POST|/api/test|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
Expected:      HMAC-SHA256(client_secret_bytes, message_bytes)
```

---

## Appendix B: Migration Notes

### B.1 From Pre-2.3.4 SDKs

1. **Add new constants**: MAX_NONCE_LENGTH, MAX_CONTEXT_ID_LENGTH, MAX_SCOPE_FIELD_NAME_LENGTH, MAX_TOTAL_SCOPE_LENGTH

2. **Add context_id charset validation**: Only allow `A-Za-z0-9_.-`

3. **Add nonce max length validation**: Reject > 512 chars

4. **Add scope field validation**: Individual (64) and total (4096) length limits

5. **Use saturating arithmetic**: Prevent integer overflow in allocation calculations

6. **Verify SEC-013**: Both scoped and unified verify functions must validate consistency

---

## Document History

| Version | Date       | Changes |
|---------|------------|---------|
| 2.3.4   | 2026-01-31 | Added security guardrails (SEC-CTX-001, SEC-NONCE-001, SEC-SCOPE-001), BUG-050 fix |
| 2.3.4   | 2026-01-29 | Initial comprehensive reference |

---

*This document is the authoritative reference for ASH SDK implementation. All SDKs MUST conform to these specifications.*
