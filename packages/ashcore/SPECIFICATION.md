# ASH Specification v1.0.0-beta

**Application Security Hash (ASH)** — Request Integrity & Replay Protection Library

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
15. [Limits](#limits)

---

## Overview

### What ASH Does

ASH provides cryptographic proof that:
- The **payload** has not been modified in transit
- The request targets the **correct endpoint** (method + path + query)
- The request is **not a replay** of a previous request
- Optionally, only **specific fields** are protected (scoping)
- Optionally, sequential requests are **cryptographically chained**

### What ASH Does NOT Do

- **Authentication**: ASH verifies WHAT is sent, not WHO sends it
- **Encryption**: Payloads are signed, not encrypted
- **Transport security**: Use HTTPS alongside ASH

### Protocol Version

| Constant | Value |
|----------|-------|
| SDK Version | `1.0.0-beta` |

---

## Protocol Flow

```
Client                                          Server
  |                                               |
  |  1. Request context                           |
  |---------------------------------------------->|
  |                                               |  Generate nonce + context_id
  |  2. Return { nonce, context_id, binding }     |
  |<----------------------------------------------|
  |                                               |
  |  3. Derive client_secret                      |
  |     HMAC-SHA256(nonce, context_id|binding)     |
  |                                               |
  |  4. Canonicalize payload                      |
  |     canonical = canonicalize(payload)          |
  |                                               |
  |  5. Hash body                                 |
  |     body_hash = SHA-256(canonical)             |
  |                                               |
  |  6. Build proof                               |
  |     HMAC-SHA256(client_secret,                 |
  |       timestamp|binding|body_hash)             |
  |                                               |
  |  7. Send request with ASH headers             |
  |---------------------------------------------->|
  |     x-ash-proof, x-ash-ts, x-ash-context-id   |
  |                                               |
  |                                               |  8. Re-derive client_secret
  |                                               |  9. Re-hash body
  |                                               |  10. Compare proofs (constant-time)
  |                                               |  11. Mark context as consumed
  |                                               |
  |  12. Response                                 |
  |<----------------------------------------------|
```

---

## Data Formats

### Nonce

- **Format**: Lowercase hexadecimal string
- **Minimum length**: 32 characters (128 bits of entropy)
- **Maximum length**: 512 characters
- **Generation**: Cryptographically secure random bytes, hex-encoded
- **Normalization**: MUST be lowercased before use as HMAC key

```
Example: "0123456789abcdef0123456789abcdef"
```

### Context ID

- **Format**: ASCII alphanumeric string with `_`, `-`, `.` allowed
- **Prefix**: Typically `"ash_"` followed by hex
- **Must NOT** be empty
- **Must NOT** contain the pipe character `|`
- **Maximum length**: 256 characters

```
Example: "ash_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
```

### Binding

- **Format**: `METHOD|PATH|CANONICAL_QUERY`
- **Separator**: Pipe character `|`
- **Method**: Uppercase HTTP method (ASCII only, no control characters, no `|`)
- **Path**: URL path starting with `/`, normalized:
  - Duplicate slashes collapsed (`//` -> `/`)
  - Trailing slashes removed (except root `/`)
  - `.` segments removed
  - `..` segments resolved by removing preceding segment
  - Cannot traverse above root (`/../api` -> `/api`)
  - Fragments stripped (`/api#section` -> `/api`)
  - Percent-decoded then re-encoded with uppercase hex
- **Query**: Canonicalized query string (may be empty)

```
Examples:
  "POST|/api/transfer|"
  "GET|/api/users|page=1&sort=name"
  "PUT|/api/users/123|"
```

### Timestamp

- **Format**: Unix timestamp as decimal string (seconds since epoch)
- **Must** contain only ASCII digits
- **Must NOT** have leading zeros (except `"0"` itself)
- **Maximum value**: 32503680000 (year 3000)

```
Example: "1704067200"
```

### Proof

- **Format**: Lowercase hex-encoded HMAC-SHA256 output
- **Length**: 64 characters (256 bits)
- **Alphabet**: `0-9a-f`

### Body Hash

- **Format**: Lowercase hex-encoded SHA-256 output
- **Length**: Exactly 64 characters
- **Validation**: Must contain only hex characters (`0-9a-fA-F`)
- **Normalization**: MUST be lowercased before inclusion in HMAC message

---

## Algorithms

### Client Secret Derivation

```
FUNCTION derive_client_secret(nonce, context_id, binding):
    VALIDATE:
        nonce.length >= 32 AND <= 512
        nonce matches /^[0-9a-fA-F]+$/
        context_id is not empty
        context_id.length <= 256
        context_id matches /^[a-zA-Z0-9_.\-]+$/
        context_id does not contain '|'

    NORMALIZE:
        nonce_key = lowercase(nonce)

    COMPUTE:
        key = utf8_bytes(nonce_key)
        message = context_id + "|" + binding
        hmac = HMAC-SHA256(key, utf8_bytes(message))

    RETURN:
        lowercase(hex_encode(hmac))    // 64 hex chars
```

### Proof Generation (Basic)

```
FUNCTION build_proof(client_secret, timestamp, binding, body_hash):
    VALIDATE:
        All inputs are non-empty
        timestamp passes format validation
        body_hash is 64 hex characters

    NORMALIZE:
        body_hash = lowercase(body_hash)

    COMPUTE:
        key = utf8_bytes(client_secret)
        message = timestamp + "|" + binding + "|" + body_hash
        hmac = HMAC-SHA256(key, utf8_bytes(message))

    RETURN:
        lowercase(hex_encode(hmac))    // 64 hex chars
```

### Body Hashing

```
FUNCTION hash_body(canonical_payload):
    VALIDATE:
        byte_length(canonical_payload) <= 10,485,760    // 10 MB

    COMPUTE:
        hash = SHA-256(utf8_bytes(canonical_payload))

    RETURN:
        lowercase(hex_encode(hash))    // 64 hex chars
```

### Proof Verification

```
FUNCTION verify_proof(nonce, context_id, binding, timestamp, body_hash, client_proof):
    client_secret = derive_client_secret(nonce, context_id, binding)
    expected_proof = build_proof(client_secret, timestamp, binding, body_hash)

    RETURN constant_time_equal(expected_proof, client_proof)
```

---

## Canonicalization

### JSON Canonicalization (RFC 8785)

JSON MUST be transformed to a deterministic byte sequence per JCS (JSON Canonicalization Scheme).

**Rules:**

| # | Rule | Example |
|---|------|---------|
| 1 | Sort object keys by **UTF-16 code unit order** (RFC 8785 Section 3.2.3) | `{"z":1,"a":2}` -> `{"a":2,"z":1}` |
| 2 | No whitespace between elements | `{ "a" : 1 }` -> `{"a":1}` |
| 3 | Preserve array order | `[3,1,2]` -> `[3,1,2]` |
| 4 | Apply Unicode NFC normalization to strings | Combining chars normalized |
| 5 | Convert `-0` to `0` | `{"a":-0}` -> `{"a":0}` |
| 6 | Whole floats become integers (if abs <= 2^53 - 1) | `{"a":5.0}` -> `{"a":5}` |
| 7 | Reject `NaN` and `Infinity` | Error |
| 8 | Escape control characters in strings | U+0000 through U+001F |
| 9 | Maximum nesting depth: 64 levels | Error on deeper nesting |
| 10 | ES6 float formatting (ECMA-262 7.1.12.1) | `1e21` -> `"1e+21"` (explicit `+`) |

**Float formatting (ES6 Number.prototype.toString):**

Given `k` significant digits and exponent `n`:

| Condition | Format | Example |
|-----------|--------|---------|
| k <= n <= 21 | Fixed with trailing zeros | `100000000000000000000` |
| 0 < n <= 21 | Decimal within digits | `1.5` |
| -6 < n <= 0 | Leading zeros | `0.000001` |
| Otherwise | Exponential with explicit sign | `1e+21`, `1e-7` |

**Pseudocode:**

```
FUNCTION canonicalize_json(input):
    IF byte_length(input) > 10,485,760:
        ERROR "Payload too large"
    value = parse_json(input)
    RETURN canonicalize_value(value, depth=0)

FUNCTION canonicalize_value(value, depth):
    IF depth >= 64:
        ERROR "Maximum nesting depth exceeded"

    SWITCH typeof(value):
        CASE null:    RETURN "null"
        CASE boolean: RETURN value ? "true" : "false"

        CASE number:
            IF is_nan(value) OR is_infinite(value):
                ERROR "NaN/Infinity not supported"
            IF value == -0:       value = 0
            IF is_integer(value) AND abs(value) <= 9007199254740991:
                RETURN format_integer(value)
            RETURN es6_format_number(value)

        CASE string:
            RETURN quote(nfc_normalize(escape_control_chars(value)))

        CASE array:
            parts = [canonicalize_value(el, depth+1) FOR el IN value]
            RETURN "[" + join(parts, ",") + "]"

        CASE object:
            keys = sort_by_utf16_code_units(object_keys(value))
            parts = []
            FOR key IN keys:
                k = quote(nfc_normalize(escape_control_chars(key)))
                v = canonicalize_value(value[key], depth+1)
                parts.append(k + ":" + v)
            RETURN "{" + join(parts, ",") + "}"
```

### Query String Canonicalization

**Rules:**

| # | Rule | Example |
|---|------|---------|
| 1 | Strip leading `?` if present | `?a=1` -> `a=1` |
| 2 | Strip fragment `#` and everything after | `a=1#section` -> `a=1` |
| 3 | Split on `&` to get pairs | `a=1&b=2` -> `[("a","1"),("b","2")]` |
| 4 | Keys without `=` get empty string value | `flag&a=1` -> `[("flag",""),("a","1")]` |
| 5 | Percent-decode keys and values | `a%20b=1` -> `("a b","1")` |
| 6 | `+` is literal plus, NOT space | `a+b=1` -> `("a+b","1")` |
| 7 | Apply Unicode NFC normalization | Combining chars normalized |
| 8 | Sort by key (byte order), then by value for duplicate keys | `z=1&a=2` -> `a=2&z=1` |
| 9 | Re-encode with uppercase hex | `%2f` -> `%2F` |
| 10 | Maximum 1024 parameters | Error if exceeded |

**Pseudocode:**

```
FUNCTION canonicalize_query(input):
    query = strip_prefix(input, "?")
    query = split(query, "#")[0]
    IF query is empty: RETURN ""

    pairs = []
    FOR part IN split(query, "&"):
        IF part is empty: CONTINUE
        IF "=" IN part:
            key = part[0:index_of("=")]
            value = part[index_of("=")+1:]
        ELSE:
            key = part; value = ""
        key = nfc_normalize(percent_decode(key))
        value = nfc_normalize(percent_decode(value))
        pairs.append((key, value))

    IF length(pairs) > 1024:
        ERROR "Too many query parameters"

    sort(pairs, by: key bytes, then value bytes)

    RETURN join([percent_encode_uppercase(k)+"="+percent_encode_uppercase(v)
                 FOR (k,v) IN pairs], "&")
```

### Binding Normalization

```
FUNCTION normalize_binding(method, path, query):
    method = uppercase(trim(method))
    VALIDATE method is non-empty, ASCII-only, no control chars, no '|'

    path = trim(path)
    VALIDATE path starts with "/"

    // Decode, strip fragment, normalize
    decoded = percent_decode(path)
    decoded = split(decoded, "#")[0]
    decoded = collapse_duplicate_slashes(decoded)
    decoded = resolve_dot_segments(decoded)       // . and ..
    decoded = remove_trailing_slash(decoded)      // except root "/"
    encoded = percent_encode_path(decoded)        // uppercase hex

    canonical_query = canonicalize_query(query)

    RETURN method + "|" + encoded + "|" + canonical_query
```

---

## Proof Generation

### Basic Proof

HMAC message format: `timestamp|binding|body_hash`

```
proof = HMAC-SHA256(client_secret, "timestamp|binding|body_hash")
```

### Scoped Proof

Protects only specific fields, allowing other fields to change.

```
FUNCTION build_proof_scoped(client_secret, timestamp, binding, payload, scope):
    scoped_payload = extract_scoped_fields(payload, scope)
    canonical = canonicalize_json(scoped_payload)
    body_hash = hash_body(canonical)
    scope_hash = hash_scope(scope)

    message = timestamp + "|" + binding + "|" + body_hash + "|" + scope_hash
    proof = HMAC-SHA256(client_secret, message)

    RETURN { proof, scope_hash }
```

### Unified Proof (Scoping + Chaining)

```
FUNCTION build_proof_unified(client_secret, timestamp, binding,
                              payload, scope, previous_proof):
    // Scope
    IF scope is not empty:
        scoped_payload = extract_scoped_fields(payload, scope)
        canonical = canonicalize_json(scoped_payload)
    ELSE:
        canonical = canonicalize_json(payload)
    body_hash = hash_body(canonical)
    scope_hash = hash_scope(scope)        // "" if no scope

    // Chain
    IF previous_proof is not empty:
        chain_hash = SHA-256(previous_proof)
    ELSE:
        chain_hash = ""

    // Build message
    message = timestamp + "|" + binding + "|" + body_hash
    IF scope_hash is not empty:
        message += "|" + scope_hash
    IF chain_hash is not empty:
        message += "|" + chain_hash

    proof = HMAC-SHA256(client_secret, message)

    RETURN { proof, scope_hash, chain_hash }
```

### Scope Hash Computation

```
FUNCTION hash_scope(scope):
    IF scope is empty: RETURN ""

    normalized = sort(unique(scope))      // auto-sort, auto-dedup
    FOR field IN normalized:
        VALIDATE field is non-empty
        VALIDATE field does not contain U+001F (unit separator)
        VALIDATE field.length <= 64

    joined = join(normalized, '\x1F')     // U+001F unit separator
    RETURN hash_body(joined)              // SHA-256 hex
```

### Field Extraction

```
FUNCTION extract_scoped_fields(payload, scope):
    result = {}
    FOR path IN scope:
        value = get_nested_value(payload, path)
        IF value is not null:
            set_nested_value(result, path, value)
    RETURN result
```

Path syntax supports dot notation and array indices:
- `"user.name"` -> nested object access
- `"items[0].price"` -> array index access
- Maximum path depth: 32 levels
- Maximum array index: 10,000
- Maximum scope fields: 100

### Chain Hash Computation

```
FUNCTION hash_proof(proof):
    VALIDATE proof is not empty
    RETURN lowercase(hex_encode(SHA-256(utf8_bytes(proof))))
```

---

## Proof Verification

### Basic Verification

```
FUNCTION verify_proof(nonce, context_id, binding, timestamp, body_hash, proof):
    client_secret = derive_client_secret(nonce, context_id, binding)
    expected = build_proof(client_secret, timestamp, binding, body_hash)
    RETURN constant_time_equal(expected, proof)
```

### Scoped Verification

```
FUNCTION verify_proof_scoped(nonce, context_id, binding, timestamp,
                              body_hash, scope_hash, scope, proof):
    expected_scope_hash = hash_scope(scope)
    IF NOT constant_time_equal(expected_scope_hash, scope_hash):
        RETURN false

    client_secret = derive_client_secret(nonce, context_id, binding)
    message = timestamp + "|" + binding + "|" + body_hash + "|" + scope_hash
    expected = HMAC-SHA256(client_secret, message)
    RETURN constant_time_equal(hex_encode(expected), proof)
```

### Unified Verification

```
FUNCTION verify_proof_unified(nonce, context_id, binding, timestamp,
                                body_hash, scope_hash, scope,
                                chain_hash, previous_proof, proof):
    // Verify scope
    IF scope is not empty:
        expected_scope_hash = hash_scope(scope)
        IF NOT constant_time_equal(expected_scope_hash, scope_hash):
            RETURN false

    // Verify chain
    IF previous_proof is not empty:
        expected_chain_hash = hash_proof(previous_proof)
        IF NOT constant_time_equal(expected_chain_hash, chain_hash):
            RETURN false

    // Verify proof
    client_secret = derive_client_secret(nonce, context_id, binding)
    message = timestamp + "|" + binding + "|" + body_hash
    IF scope_hash is not empty:  message += "|" + scope_hash
    IF chain_hash is not empty:  message += "|" + chain_hash

    expected = HMAC-SHA256(client_secret, message)
    RETURN constant_time_equal(hex_encode(expected), proof)
```

---

## Timestamp Validation

### Format Validation

```
FUNCTION is_valid_timestamp(timestamp):
    IF timestamp is empty:                          RETURN false
    IF NOT matches(timestamp, /^[0-9]+$/):          RETURN false
    IF length > 1 AND starts_with(timestamp, "0"):  RETURN false
    IF parse_int(timestamp) > 32503680000:          RETURN false
    RETURN true
```

### Freshness Validation

```
DEFAULT_MAX_AGE_SECONDS    = 300    // 5 minutes
DEFAULT_CLOCK_SKEW_SECONDS = 30     // 30 seconds

FUNCTION validate_timestamp_freshness(timestamp, current_time, max_age, clock_skew):
    ts = parse_int(timestamp)

    IF ts > current_time + clock_skew:
        ERROR "Timestamp is in the future"

    IF current_time > ts AND (current_time - ts) > max_age:
        ERROR "Timestamp has expired"

    RETURN true
```

---

## Error Codes

All implementations MUST use these error codes with the `ASH_` prefix:

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context ID not found in store |
| `ASH_CTX_EXPIRED` | 451 | Context has expired (TTL exceeded) |
| `ASH_CTX_ALREADY_USED` | 452 | Context already consumed (replay attempt) |
| `ASH_PROOF_INVALID` | 460 | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Request endpoint doesn't match context binding |
| `ASH_SCOPE_MISMATCH` | 473 | Scope hash does not match expected scope |
| `ASH_CHAIN_BROKEN` | 474 | Chain hash does not match previous proof |
| `ASH_SCOPED_FIELD_MISSING` | 475 | Required scoped field missing from payload |
| `ASH_TIMESTAMP_INVALID` | 482 | Invalid timestamp format or value |
| `ASH_PROOF_MISSING` | 483 | Required proof header not provided |
| `ASH_CANONICALIZATION_ERROR` | 484 | Payload cannot be canonicalized |
| `ASH_VALIDATION_ERROR` | 485 | Input validation failure |
| `ASH_MODE_VIOLATION` | 486 | Security mode requirements not met |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Content type not supported |
| `ASH_INTERNAL_ERROR` | 500 | Internal server error |

**Retryable errors**: `ASH_TIMESTAMP_INVALID`, `ASH_INTERNAL_ERROR`, `ASH_CTX_ALREADY_USED`

---

## HTTP Headers

### Request Headers (Client -> Server)

| Header | Required | Description |
|--------|----------|-------------|
| `x-ash-proof` | Yes | Computed proof (64 hex chars) |
| `x-ash-ts` | Yes | Unix timestamp used in proof |
| `x-ash-context-id` | Yes | Context ID from server |
| `x-ash-body-hash` | If applicable | SHA-256 hash of canonical body |
| `x-ash-nonce` | If applicable | Server-generated nonce |

### Header Rules

- Case-insensitive lookup
- Leading/trailing whitespace trimmed
- Control characters (U+0000-U+001F, U+007F) rejected
- Multi-value headers rejected (no duplicate header names)
- Comma-concatenated values rejected
- Maximum header value length: 4096 bytes
- Whitespace-only values rejected for required headers

---

## Test Vectors

### JSON Canonicalization

```
Input:  {"z":1,"a":{"c":3,"b":2}}
Output: {"a":{"b":2,"c":3},"z":1}

Input:  {"a":5.0}
Output: {"a":5}

Input:  {"a":-0.0}
Output: {"a":0}

Input:  {"b":true,"a":false}
Output: {"a":false,"b":true}
```

### Query Canonicalization

```
Input:  "z=3&a=1&b=2"
Output: "a=1&b=2&z=3"

Input:  "a=2&a=1"
Output: "a=1&a=2"

Input:  "a=hello+world"
Output: "a=hello%2Bworld"

Input:  "a=1#fragment"
Output: "a=1"
```

### Binding Normalization

```
Input:  method="post", path="/api//users/", query=""
Output: "POST|/api/users|"

Input:  method="GET", path="/api/users", query="z=3&a=1"
Output: "GET|/api/users|a=1&z=3"
```

### Body Hash

```
Input:  ""
Output: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

Input:  "{}"
Output: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
```

### Constant-Time Comparison

All comparisons MUST take the same time regardless of where differences occur.

```
equal("abc", "abc")   = true
equal("abc", "abd")   = false
equal("abc", "abcd")  = false
```

---

## Security Requirements

### MUST Implement

- Constant-time comparison for all proof and secret comparisons
- Cryptographically secure random number generation for nonces
- Input validation on all external inputs (non-empty, format, length)
- Timestamp format and freshness validation
- Nonce minimum length enforcement (32 hex chars)
- Context ID format validation (no `|`, no control chars)
- Body hash format validation (64 hex chars)
- Maximum nesting depth enforcement for JSON (64 levels)
- Maximum payload size enforcement (10 MB)
- Zeroization of secrets (client_secret, nonce key material) after use
- Unicode NFC normalization for strings and binding values

### MUST NOT

- Store nonces or client secrets in logs
- Use non-constant-time comparison for proofs or secrets
- Allow nonces shorter than 32 hex characters
- Reuse context IDs across requests
- Accept timestamps more than 5 minutes old (default)
- Accept timestamps with leading zeros (except `"0"`)
- Accept empty context_id values
- Accept non-ASCII HTTP method names
- Accept body hashes that aren't valid 64-char hex

---

## Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Max JSON nesting depth | 64 | Prevent stack overflow |
| Max payload size | 10,485,760 bytes (10 MB) | Prevent memory exhaustion |
| Max query parameters | 1,024 | Prevent sort amplification |
| Min nonce length | 32 hex chars | Minimum 128-bit entropy |
| Max nonce length | 512 chars | Prevent oversized keys |
| Max context ID length | 256 chars | Prevent oversized IDs |
| Max binding length | 8,192 bytes | Prevent oversized bindings |
| Max header value length | 4,096 bytes | Prevent oversized headers |
| Max scope fields | 100 | Prevent processing DoS |
| Max scope field name | 64 chars | Prevent oversized names |
| Max total scope length | 4,096 bytes | Prevent memory exhaustion |
| Max scope path depth | 32 levels | Prevent deep recursion |
| Max array index | 10,000 | Prevent sparse array DoS |
| Max total array allocation | 10,000 | Prevent memory exhaustion |
| Max timestamp | 32,503,680,000 (year 3000) | Prevent overflow |
| Min constant-time comparison | 2,048 bytes | Full proof comparison |
| Default max timestamp age | 300 seconds (5 min) | Replay window |
| Default clock skew | 30 seconds | NTP tolerance |

---

## License

ASH is released under the Apache License 2.0.
