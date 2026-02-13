# ASH Protocol Specification v2.3.5

**Anti-tamper Security Hash (ASH)** - Request Integrity & Replay Protection Protocol

This document serves as the authoritative reference for implementing ASH SDKs and middleware in any programming language.

---

## Table of Contents

1. [Overview](#overview)
2. [Protocol Flow](#protocol-flow)
3. [Data Formats](#data-formats)
4. [Algorithms](#algorithms)
5. [Canonicalization](#canonicalization)
6. [Proof Generation](#proof-generation)
7. [Proof Verification](#proof-verification)
8. [Scoped Proofs](#scoped-proofs)
9. [Request Chaining](#request-chaining)
10. [Timestamp Validation](#timestamp-validation)
11. [Error Codes](#error-codes)
12. [HTTP Headers](#http-headers)
13. [Test Vectors](#test-vectors)
14. [Security Requirements](#security-requirements)

---

## Overview

### What ASH Does

ASH provides cryptographic proof that:
- The **payload** has not been modified in transit
- The request targets the **correct endpoint** (method + path + query)
- The request is **not a replay** of a previous request
- Optionally, only **specific fields** are protected (scoping)

### What ASH Does NOT Do

- **Authentication**: ASH verifies WHAT is sent, not WHO sends it
- **Encryption**: Payloads are signed, not encrypted
- **Transport security**: Use HTTPS alongside ASH

### Version History

| Version | Features |
|---------|----------|
| v2.1 | HMAC-SHA256 proofs, client secret derivation |
| v2.2 | Field-level scoping |
| v2.3 | Request chaining |
| v2.3.2 | Binding normalization (METHOD|PATH|QUERY format) |
| v2.3.4 | Bug fixes (BUG-020 through BUG-045), path normalization, input validation |
| v2.3.5 | Body hash normalization mandate, input validation improvements |

---

## Protocol Flow

```
┌────────┐                                    ┌────────┐
│ Server │                                    │ Client │
└───┬────┘                                    └───┬────┘
    │                                             │
    │  1. Generate nonce + context_id             │
    │────────────────────────────────────────────>│
    │     { nonce: "abc123...", context_id: "ctx_xyz" }
    │                                             │
    │                                             │  2. Derive client_secret
    │                                             │     client_secret = HMAC(nonce, context_id|binding)
    │                                             │
    │                                             │  3. Canonicalize payload
    │                                             │     canonical = canonicalize(payload)
    │                                             │
    │                                             │  4. Hash body
    │                                             │     body_hash = SHA256(canonical)
    │                                             │
    │                                             │  5. Build proof
    │                                             │     proof = HMAC(client_secret, timestamp|binding|body_hash)
    │                                             │
    │  6. Send request with proof                 │
    │<────────────────────────────────────────────│
    │     Headers: X-ASH-Proof, X-ASH-Timestamp   │
    │     Body: payload                           │
    │                                             │
    │  7. Verify proof                            │
    │     - Re-derive client_secret               │
    │     - Re-hash body                          │
    │     - Compare proofs (constant-time)        │
    │                                             │
    │  8. Mark context as consumed                │
    │                                             │
```

---

## Data Formats

### Nonce

- **Format**: Lowercase hexadecimal string
- **Minimum length**: 32 characters (128 bits of entropy)
- **Recommended length**: 64 characters (256 bits)
- **Generation**: Cryptographically secure random bytes, hex-encoded

```
Example: "0123456789abcdef0123456789abcdef"
```

### Context ID

- **Format**: String with "ash_" prefix followed by hex nonce
- **Must NOT be empty**: BUG-041 requires non-empty context_id
- **Must NOT contain**: Pipe character `|`
- **Generation**: `"ash_" + hex(random_bytes(16))`

```
Example: "ash_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
```

### Binding

- **Format**: `METHOD|PATH|CANONICAL_QUERY`
- **Separator**: Pipe character `|`
- **Method**: Uppercase HTTP method (ASCII only - BUG-042)
- **Path**: URL path starting with `/`, normalized:
  - Duplicate slashes collapsed (`//` → `/`)
  - Trailing slashes removed (except root `/`)
  - `.` segments removed (BUG-035)
  - `..` segments resolved by removing preceding segment (BUG-035)
  - Cannot traverse above root (`/../api` → `/api`)
- **Query**: Canonicalized query string (may be empty, whitespace trimmed - BUG-043)

```
Examples:
  "POST|/api/transfer|"
  "GET|/api/users|page=1&sort=name"
  "PUT|/api/users/123|"

Path normalization examples:
  "/api/./users"        → "/api/users"
  "/api/users/../admin" → "/api/admin"
  "/api//users///"      → "/api/users"
```

### Timestamp

- **Format**: Unix timestamp as decimal string (seconds since epoch)
- **Maximum value**: 32503680000 (year 3000)
- **Validation**: Must be numeric, no leading zeros (except "0")

```
Example: "1704067200"
```

### Proof

- **Format**: Hex-encoded string (lowercase)
- **Length**: 64 characters (256 bits = 64 hex chars for SHA-256)
- **Alphabet**: `0-9a-f`

```
Example: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

### Body Hash

- **Format**: Hexadecimal string (case-insensitive)
- **Length**: Exactly 64 characters (SHA-256 = 256 bits = 64 hex chars) - BUG-040
- **Validation**: Must contain only characters 0-9, a-f, A-F - BUG-040
- **Normalization**: Implementations MUST normalize body_hash to lowercase before including it in the HMAC message.

```
Example: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

---

## Algorithms

### Client Secret Derivation

```
FUNCTION derive_client_secret(nonce, context_id, binding):
    INPUT:
        nonce: string (32+ hex chars)
        context_id: string (must not be empty, must not contain '|')
        binding: string (METHOD|PATH|QUERY format)

    VALIDATE:
        nonce.length >= 32
        nonce matches /^[0-9a-f]+$/i
        context_id is not empty (BUG-041)
        context_id does not contain '|'

    NORMALIZE:
        nonce = lowercase(nonce)
        // Before use, the nonce MUST be normalized to lowercase: `nonce = lowercase(nonce)`

    COMPUTE:
        key = utf8_bytes(nonce)
        // The nonce hex string is used directly as UTF-8 bytes for the HMAC key, not hex-decoded to binary.
        message = context_id + "|" + binding
        hmac = HMAC-SHA256(key, message)

    RETURN:
        hex_encode(hmac)  // lowercase, 64 chars
```

### Proof Generation

```
FUNCTION build_proof(client_secret, timestamp, binding, body_hash):
    INPUT:
        client_secret: string (64 hex chars from derive_client_secret)
        timestamp: string (Unix timestamp)
        binding: string (METHOD|PATH|QUERY format)
        body_hash: string (64 hex chars from hash_body)

    VALIDATE:
        All inputs are non-empty
        timestamp is valid numeric string

    NORMALIZE:
        body_hash = lowercase(body_hash)

    COMPUTE:
        key = utf8_bytes(client_secret)
        // The client secret hex string is used directly as UTF-8 bytes for the HMAC key.
        message = timestamp + "|" + binding + "|" + body_hash
        hmac = HMAC-SHA256(key, message)

    RETURN:
        hex_encode(hmac)  // Proof output is hex-encoded (64 lowercase hex characters for SHA-256).
```

### Body Hashing

```
FUNCTION hash_body(canonical_payload):
    INPUT:
        canonical_payload: string (canonicalized JSON or form data)

    COMPUTE:
        hash = SHA-256(utf8_encode(canonical_payload))

    RETURN:
        hex_encode(hash)  // lowercase, 64 chars
```

### Proof Verification

```
FUNCTION verify_proof(nonce, context_id, binding, timestamp, body_hash, client_proof):
    INPUT:
        nonce: string
        context_id: string
        binding: string
        timestamp: string
        body_hash: string
        client_proof: string

    COMPUTE:
        client_secret = derive_client_secret(nonce, context_id, binding)
        expected_proof = build_proof(client_secret, timestamp, binding, body_hash)

    COMPARE:
        result = constant_time_equal(expected_proof, client_proof)

    RETURN:
        result  // boolean
```

---

## Canonicalization

### JSON Canonicalization (RFC 8785)

JSON must be transformed to a deterministic byte sequence.

**Rules (all MUST be implemented):**

| Rule | Description | Example |
|------|-------------|---------|
| 1 | Sort object keys lexicographically (byte order) | `{"z":1,"a":2}` → `{"a":2,"z":1}` |
| 2 | No whitespace between elements | `{ "a" : 1 }` → `{"a":1}` |
| 3 | Preserve array order | `[3,1,2]` → `[3,1,2]` |
| 4 | Apply Unicode NFC normalization to strings | Combining chars normalized |
| 5 | Convert `-0` to `0` | `{"a":-0}` → `{"a":0}` |
| 6 | Convert whole floats to integers | `{"a":5.0}` → `{"a":5}` |
| 7 | Reject `NaN` and `Infinity` | Error on invalid values |
| 8 | Escape control characters in strings | `\u0000` - `\u001F` |

**Pseudocode:**

```
FUNCTION canonicalize_json(input):
    value = parse_json(input)
    RETURN canonicalize_value(value, depth=0)

FUNCTION canonicalize_value(value, depth):
    IF depth > 64:
        ERROR "Maximum nesting depth exceeded"

    SWITCH typeof(value):
        CASE null:
            RETURN "null"

        CASE boolean:
            RETURN value ? "true" : "false"

        CASE number:
            IF is_nan(value) OR is_infinite(value):
                ERROR "NaN/Infinity not supported"
            IF value == -0:
                value = 0
            IF is_whole_number(value) AND abs(value) <= 9007199254740991:
                RETURN format_integer(value)
            RETURN format_number(value)

        CASE string:
            RETURN quote(nfc_normalize(escape_string(value)))

        CASE array:
            parts = []
            FOR each element IN value:
                parts.append(canonicalize_value(element, depth + 1))
            RETURN "[" + join(parts, ",") + "]"

        CASE object:
            keys = sort_by_bytes(object_keys(value))
            parts = []
            FOR each key IN keys:
                canonical_key = quote(nfc_normalize(escape_string(key)))
                canonical_value = canonicalize_value(value[key], depth + 1)
                parts.append(canonical_key + ":" + canonical_value)
            RETURN "{" + join(parts, ",") + "}"
```

### Query String Canonicalization

**Rules (all MUST be implemented):**

| Rule | Description | Example |
|------|-------------|---------|
| 1 | Strip leading `?` if present | `?a=1` → `a=1` |
| 2 | Strip fragment `#` and everything after | `a=1#section` → `a=1` |
| 3 | Split on `&` to get pairs | `a=1&b=2` → `[("a","1"), ("b","2")]` |
| 4 | Handle keys without values as empty string | `flag&a=1` → `[("flag",""), ("a","1")]` |
| 5 | Percent-decode keys and values | `a%20b=1` → `("a b", "1")` |
| 6 | `+` is literal plus, NOT space | `a+b=1` → `("a+b", "1")` |
| 7 | Apply Unicode NFC normalization | Combining chars normalized |
| 8 | Sort by key (byte order) | `z=1&a=2` → `a=2&z=1` |
| 9 | For duplicate keys, sort by value | `a=2&a=1` → `a=1&a=2` |
| 10 | Re-encode with uppercase hex | `%2f` → `%2F` |

**Pseudocode:**

```
FUNCTION canonicalize_query(input):
    // Rule 1: Strip leading ?
    query = strip_prefix(input, "?")

    // Rule 2: Strip fragment
    query = split(query, "#")[0]

    IF query is empty:
        RETURN ""

    pairs = []

    // Rule 3: Split on &
    FOR each part IN split(query, "&"):
        IF part is empty:
            CONTINUE

        // Rule 4: Handle keys without =
        IF "=" IN part:
            pos = index_of(part, "=")
            key = part[0:pos]
            value = part[pos+1:]
        ELSE:
            key = part
            value = ""

        // Rule 5 & 6: Percent-decode (+ is literal)
        key = percent_decode(key)  // + stays as +
        value = percent_decode(value)

        // Rule 7: NFC normalize
        key = nfc_normalize(key)
        value = nfc_normalize(value)

        pairs.append((key, value))

    // Rule 8 & 9: Sort by key, then value (byte order)
    pairs = sort(pairs, by: (a, b) =>
        compare_bytes(a.key, b.key) OR compare_bytes(a.value, b.value)
    )

    // Rule 10: Re-encode with uppercase hex
    result = []
    FOR each (key, value) IN pairs:
        encoded_key = percent_encode_uppercase(key)
        encoded_value = percent_encode_uppercase(value)
        result.append(encoded_key + "=" + encoded_value)

    RETURN join(result, "&")
```

### Binding Normalization

**Rules:**

| Rule | Description | Example |
|------|-------------|---------|
| 1 | Uppercase method | `post` → `POST` |
| 2 | Path must start with `/` | `api/users` → ERROR |
| 3 | Collapse duplicate slashes | `/api//users` → `/api/users` |
| 4 | Remove trailing slash (except root) | `/api/users/` → `/api/users` |
| 5 | Percent-decode then re-encode path | `/%2F/` → `/` |
| 6 | Canonicalize query string | `z=1&a=2` → `a=2&z=1` |
| 7 | Reject `?` in path (use `ash_normalize_binding_from_url`) | `/api?x` → ERROR |

**Pseudocode:**

```
FUNCTION normalize_binding(method, path, query):
    // Rule 1
    method = uppercase(trim(method))
    IF method is empty:
        ERROR "Method cannot be empty"

    // Rule 2
    path = trim(path)
    IF NOT starts_with(path, "/"):
        ERROR "Path must start with /"

    // Rule 5: Decode path
    decoded_path = percent_decode(path)

    // Rule 7: Check for ? after decoding
    IF "?" IN decoded_path:
        ERROR "Path must not contain '?'"

    // Rule 3: Collapse duplicate slashes
    normalized_path = ""
    prev_slash = false
    FOR each char IN decoded_path:
        IF char == '/':
            IF NOT prev_slash:
                normalized_path += char
            prev_slash = true
        ELSE:
            normalized_path += char
            prev_slash = false

    // Rule 4: Remove trailing slash (except root)
    IF length(normalized_path) > 1 AND ends_with(normalized_path, "/"):
        normalized_path = normalized_path[0:-1]

    // Rule 5: Re-encode path
    encoded_path = percent_encode_path(normalized_path)

    // Rule 6: Canonicalize query
    canonical_query = canonicalize_query(query)

    RETURN method + "|" + encoded_path + "|" + canonical_query
```

---

## Proof Generation

### Basic Proof

```
FUNCTION build_proof(client_secret, timestamp, binding, body_hash):
    // Validate inputs (SEC-012)
    IF any input is empty:
        ERROR "All inputs must be non-empty"

    // Validate timestamp format (BUG-007, BUG-012)
    IF NOT is_valid_timestamp(timestamp):
        ERROR "Invalid timestamp format"

    // Normalize body_hash to lowercase
    body_hash = lowercase(body_hash)

    // Build HMAC message
    message = timestamp + "|" + binding + "|" + body_hash

    // Compute HMAC-SHA256
    key = utf8_bytes(client_secret)
    // The client secret hex string is used directly as UTF-8 bytes for the HMAC key.
    hmac = HMAC_SHA256(key, utf8_encode(message))

    // Encode as hex
    RETURN hex_encode(hmac)  // Proof output is hex-encoded (64 lowercase hex characters for SHA-256).
```

### Scoped Proof

Scoped proofs protect only specific fields, allowing other fields to change.

```
FUNCTION build_proof_scoped(client_secret, timestamp, binding, payload, scope):
    // Extract scoped fields from payload
    scoped_payload = extract_scoped_fields(payload, scope)

    // Canonicalize and hash
    canonical = canonicalize_json(scoped_payload)
    body_hash = hash_body(canonical)

    // Compute scope hash (BUG-023: auto-sort scope)
    scope_hash = hash_scope(scope)

    // Build message with scope hash
    message = timestamp + "|" + binding + "|" + body_hash + "|" + scope_hash

    key = utf8_bytes(client_secret)
    // The client secret hex string is used directly as UTF-8 bytes for the HMAC key.
    hmac = HMAC_SHA256(key, utf8_encode(message))

    RETURN {
        proof: hex_encode(hmac),
        scope_hash: scope_hash
    }
```

### Scope Hash Computation

```
FUNCTION hash_scope(scope):
    IF scope is empty:
        RETURN ""

    // BUG-023: Auto-sort and deduplicate
    normalized = sort(unique(scope))

    // BUG-028: Validate no field contains delimiter
    FOR each field IN normalized:
        IF field contains '\x1F':
            ERROR "Field name contains reserved delimiter"

    // BUG-002: Join with unit separator to prevent collision
    joined = join(normalized, '\x1F')

    RETURN hash_body(joined)
```

### Field Extraction

```
FUNCTION extract_scoped_fields(payload, scope):
    result = {}

    FOR each path IN scope:
        value = get_nested_value(payload, path)
        IF value is not null:
            set_nested_value(result, path, value)

    RETURN result

FUNCTION get_nested_value(obj, path):
    // Parse path: "user.addresses[0].city"
    parts = split_path(path)
    current = obj

    FOR each part IN parts:
        IF part is array_index:
            IF current is not array OR index >= length(current):
                RETURN null
            current = current[index]
        ELSE:
            IF current is not object OR part not in current:
                RETURN null
            current = current[part]

    RETURN clone(current)
```

---

## Proof Verification

### Basic Verification

```
FUNCTION verify_proof(nonce, context_id, binding, timestamp, body_hash, client_proof):
    // Validate timestamp format (BUG-007)
    IF NOT is_valid_timestamp(timestamp):
        ERROR "Invalid timestamp format"

    // Re-derive client secret
    client_secret = derive_client_secret(nonce, context_id, binding)

    // Re-build expected proof
    expected_proof = build_proof(client_secret, timestamp, binding, body_hash)

    // Constant-time comparison (SEC-008)
    RETURN constant_time_equal(expected_proof, client_proof)
```

### Scoped Verification

```
FUNCTION verify_proof_scoped(nonce, context_id, binding, timestamp,
                              body_hash, scope_hash, scope, client_proof):
    // Validate timestamp
    IF NOT is_valid_timestamp(timestamp):
        ERROR "Invalid timestamp format"

    // Verify scope hash matches
    expected_scope_hash = hash_scope(scope)
    IF NOT constant_time_equal(expected_scope_hash, scope_hash):
        RETURN false

    // Re-derive and verify
    client_secret = derive_client_secret(nonce, context_id, binding)
    message = timestamp + "|" + binding + "|" + body_hash + "|" + scope_hash

    key = utf8_bytes(client_secret)
    // The client secret hex string is used directly as UTF-8 bytes for the HMAC key.
    expected_hmac = HMAC_SHA256(key, utf8_encode(message))
    expected_proof = hex_encode(expected_hmac)

    RETURN constant_time_equal(expected_proof, client_proof)
```

---

## Request Chaining

Request chaining links sequential requests cryptographically, ensuring they execute in order.

### Chain Hash Computation

```
FUNCTION hash_proof(proof):
    // BUG-029: Reject empty proof
    IF proof is empty:
        ERROR "Proof cannot be empty for chain hashing"

    hash = SHA256(utf8_encode(proof))
    RETURN hex_encode(hash)  // lowercase, 64 chars
```

### Unified Proof (Scoping + Chaining)

```
FUNCTION build_proof_unified(nonce, context_id, binding, timestamp,
                              payload, scope, previous_proof):
    // Derive client secret
    client_secret = derive_client_secret(nonce, context_id, binding)

    // Extract and hash scoped body
    IF scope is not empty:
        scoped_payload = extract_scoped_fields(payload, scope)
        canonical = canonicalize_json(scoped_payload)
    ELSE:
        canonical = canonicalize_json(payload)
    body_hash = hash_body(canonical)

    // Compute scope hash
    scope_hash = hash_scope(scope)

    // Compute chain hash
    IF previous_proof is not empty:
        chain_hash = hash_proof(previous_proof)
    ELSE:
        chain_hash = ""

    // Build message: timestamp|binding|body_hash|scope_hash|chain_hash
    message = timestamp + "|" + binding + "|" + body_hash
    IF scope_hash is not empty:
        message += "|" + scope_hash
    IF chain_hash is not empty:
        message += "|" + chain_hash

    key = utf8_bytes(client_secret)
    // The client secret hex string is used directly as UTF-8 bytes for the HMAC key.
    hmac = HMAC_SHA256(key, utf8_encode(message))

    RETURN {
        proof: hex_encode(hmac),
        scope_hash: scope_hash,
        chain_hash: chain_hash
    }
```

---

## Timestamp Validation

### Format Validation

```
FUNCTION is_valid_timestamp(timestamp):
    // Must be non-empty
    IF timestamp is empty:
        RETURN false

    // Must be numeric
    IF NOT matches(timestamp, /^[0-9]+$/):
        RETURN false

    // No leading zeros (except "0" itself)
    IF length(timestamp) > 1 AND starts_with(timestamp, "0"):
        RETURN false

    // Must not exceed maximum (year 3000)
    IF parse_int(timestamp) > 32503680000:
        RETURN false

    RETURN true
```

### Age Validation

```
CONST DEFAULT_MAX_AGE_SECONDS = 300        // 5 minutes
CONST DEFAULT_CLOCK_SKEW_SECONDS = 30      // 30 seconds

FUNCTION validate_timestamp(timestamp, current_time, max_age, clock_skew):
    ts = parse_int(timestamp)
    now = current_time

    // Check for future timestamp (with clock skew allowance)
    IF ts > now + clock_skew:
        ERROR "Timestamp is in the future"

    // Check for expired timestamp
    IF now > ts AND (now - ts) > max_age:
        ERROR "Timestamp has expired"

    RETURN true
```

---

## Error Codes

All SDKs MUST use these standardized error codes with the `ASH_` prefix:

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context ID not found in store |
| `ASH_CTX_EXPIRED` | 451 | Context has expired (TTL exceeded) |
| `ASH_CTX_ALREADY_USED` | 452 | Context was already consumed (replay attempt) |
| `ASH_PROOF_INVALID` | 460 | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Request endpoint doesn't match context binding |
| `ASH_SCOPE_MISMATCH` | 473 | Scope hash does not match expected scope |
| `ASH_CHAIN_BROKEN` | 474 | Chain hash does not match previous proof |
| `ASH_SCOPED_FIELD_MISSING` | 475 | Required scoped field missing from payload |
| `ASH_TIMESTAMP_INVALID` | 482 | Invalid timestamp format or value (too old, future, malformed) |
| `ASH_PROOF_MISSING` | 483 | Required X-ASH-Proof header not provided |
| `ASH_CANONICALIZATION_ERROR` | 484 | Payload cannot be canonicalized |
| `ASH_VALIDATION_ERROR` | 485 | General input validation failure |
| `ASH_MODE_VIOLATION` | 486 | Security mode requirements not met |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Content type not supported |
| `ASH_INTERNAL_ERROR` | 500 | Internal server error |

---

## HTTP Headers

### Request Headers (Client → Server)

| Header | Required | Description |
|--------|----------|-------------|
| `X-ASH-Proof` | Yes | The computed proof (hex-encoded) |
| `X-ASH-Timestamp` | Yes | Unix timestamp used in proof |
| `X-ASH-Context-ID` | Yes | Context ID from server |
| `X-ASH-Scope-Hash` | If scoped | Hash of scope fields |
| `X-ASH-Chain-Hash` | If chained | Hash of previous proof |

### Response Headers (Server → Client on context creation)

| Header | Required | Description |
|--------|----------|-------------|
| `X-ASH-Nonce` | Yes | Server-generated nonce |
| `X-ASH-Context-ID` | Yes | Context ID for this request |
| `X-ASH-Binding` | Recommended | Expected binding for verification |

---

## Test Vectors

### Nonce Generation

```
Input bytes (hex): 0123456789abcdef0123456789abcdef
Expected nonce: "0123456789abcdef0123456789abcdef"
```

### Client Secret Derivation

```
Input:
  nonce: "0123456789abcdef0123456789abcdef"
  context_id: "ctx_test123"
  binding: "POST|/api/transfer|"

Expected:
  client_secret: (64 hex chars, HMAC-SHA256 output)
```

### JSON Canonicalization

```
Input: {"z":1,"a":{"c":3,"b":2}}
Expected: {"a":{"b":2,"c":3},"z":1}

Input: {"a":5.0}
Expected: {"a":5}

Input: {"a":-0.0}
Expected: {"a":0}

Input: {"b":true,"a":false}
Expected: {"a":false,"b":true}
```

### Query Canonicalization

```
Input: "z=3&a=1&b=2"
Expected: "a=1&b=2&z=3"

Input: "a=2&a=1"
Expected: "a=1&a=2"

Input: "a=hello+world"
Expected: "a=hello%2Bworld"

Input: "a=1#fragment"
Expected: "a=1"
```

### Binding Normalization

```
Input: method="post", path="/api//users/", query=""
Expected: "POST|/api/users|"

Input: method="GET", path="/api/users", query="z=3&a=1"
Expected: "GET|/api/users|a=1&z=3"

Input: method="GET", path="/api/%2F%2F/users", query=""
Expected: "GET|/api/users|"
```

### Body Hash

```
Input: ""
Expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

Input: "{}"
Expected: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

Input: {"a":1}
Expected: (SHA-256 of '{"a":1}')
```

### Constant-Time Comparison

```
Input: a="abc", b="abc"
Expected: true

Input: a="abc", b="abd"
Expected: false

Input: a="abc", b="abcd"
Expected: false

CRITICAL: All comparisons must take the same time regardless of where differences occur.
```

---

## Security Requirements

### MUST Implement

| ID | Requirement |
|----|-------------|
| SEC-001 | Limit regex complexity to prevent ReDoS |
| SEC-002 | Return Result/Error on RNG failure, don't panic |
| SEC-003 | Handle mutex/lock poisoning gracefully |
| SEC-008 | Use constant-time comparison for all secrets |
| SEC-011 | Limit array indices to prevent memory exhaustion |
| SEC-012 | Validate all inputs are non-empty |
| SEC-014 | Require minimum 32 hex chars for nonce |
| SEC-015 | Reject context_id containing `\|` delimiter |
| SEC-018 | Reject unreasonably large timestamps |
| SEC-019 | Limit scope path depth to prevent stack overflow |
| BUG-035 | Normalize `.` and `..` path segments |
| BUG-036 | Limit total array allocation across scope fields |
| BUG-037 | Compare at least 2048 bytes in constant-time |
| BUG-038 | Reject timestamps with leading zeros |
| BUG-039 | Reject empty scope field names |
| BUG-040 | Validate body_hash is 64 hex characters |
| BUG-041 | Reject empty context_id |
| BUG-042 | Reject non-ASCII method names |
| BUG-043 | Trim whitespace from query strings |
| BUG-045 | Use overflow-safe arithmetic in timestamp checks |

### MUST NOT

- Store nonces or client secrets in logs
- Use non-constant-time string comparison for proofs
- Allow nonces shorter than 32 hex characters
- Reuse context IDs across requests
- Accept timestamps more than 5 minutes old (default)
- Accept timestamps with leading zeros (except "0")
- Accept empty context_id values
- Accept non-ASCII HTTP method names
- Accept body hashes that aren't valid SHA-256 hex

### Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Max nesting depth | 64 | Prevent stack overflow |
| Max payload size | 10 MB | Prevent memory exhaustion |
| Max array index | 10000 | Prevent sparse array DoS |
| Max total array allocation | 10000 | Prevent memory exhaustion (BUG-036) |
| Max scope depth | 32 | Prevent deep recursion |
| Max scope fields | 100 | Prevent processing DoS |
| Max pattern length | 512 | Prevent regex DoS |
| Max wildcards | 8 | Prevent backtracking DoS |
| Max timestamp | 32503680000 | Prevent integer overflow |
| Min comparison bytes | 2048 | Ensure full proof comparison (BUG-037) |

---

## Implementation Checklist

Use this checklist when implementing a new SDK:

### Core Functions

- [ ] `generate_nonce(bytes)` - Cryptographic random hex string
- [ ] `generate_context_id()` - "ash_" + random hex
- [ ] `derive_client_secret(nonce, context_id, binding)` - HMAC-SHA256
- [ ] `hash_body(canonical_payload)` - SHA-256 hex
- [ ] `build_proof(client_secret, timestamp, binding, body_hash)` - HMAC-SHA256 hex-encoded
- [ ] `verify_proof(...)` - Constant-time comparison

### Canonicalization

- [ ] `canonicalize_json(input)` - RFC 8785 compliant
- [ ] `canonicalize_query(input)` - Query string normalization
- [ ] `normalize_binding(method, path, query)` - Binding format

### Scoping (Optional)

- [ ] `extract_scoped_fields(payload, scope)` - Field extraction
- [ ] `hash_scope(scope)` - Scope hash with delimiter
- [ ] `build_proof_scoped(...)` - Scoped proof generation
- [ ] `verify_proof_scoped(...)` - Scoped verification

### Chaining (Optional)

- [ ] `hash_proof(proof)` - Chain hash computation
- [ ] `build_proof_unified(...)` - Full unified proof
- [ ] `verify_proof_unified(...)` - Unified verification

### Security

- [ ] Constant-time comparison function
- [ ] Input validation (non-empty, format)
- [ ] Timestamp validation
- [ ] Depth/size limits
- [ ] Error codes matching specification

---

## Changelog

### v2.3.5 (Current)

- Added body hash normalization mandate (implementations MUST lowercase body_hash before HMAC)
- Input validation improvements (MAX_NONCE_LENGTH updated, HTTP status code corrections)

### v2.3.4

- BUG-020: Fixed escape sequence handling in scope patterns
- BUG-021: Added depth tracking for nested scope paths
- BUG-022: Fixed multi-dimensional array handling
- BUG-023: Auto-sort scope fields for deterministic ordering
- BUG-024: Fixed empty payload handling
- BUG-025: Fixed path percent-encoding normalization
- BUG-026: Fixed timing-safe comparison padding
- BUG-027: Fixed encoded query delimiter bypass
- BUG-028: Added scope field delimiter validation
- BUG-029: Reject empty proof in chain hashing
- BUG-030: Fixed timing leak in comparison iteration count
- BUG-034: Documented BTreeMap ordering in register_many
- Removed deprecated v1 functions
- Renamed v21 functions to remove version suffix

---

## License

ASH Protocol Specification is released under the Apache License 2.0.

## Contact

For questions about this specification, please open an issue on the GitHub repository.
