# ASH Troubleshooting Guide

This guide covers common issues and their solutions when integrating ASH into your applications.

---

## Table of Contents

1. [Proof Verification Failures](#proof-verification-failures)
2. [Context Errors](#context-errors)
3. [Canonicalization Issues](#canonicalization-issues)
4. [Clock Drift and Timing](#clock-drift-and-timing)
5. [Rust / Node.js Interoperability](#rust--nodejs-interoperability)
6. [Performance Issues](#performance-issues)
7. [Debugging Tips](#debugging-tips)
8. [HTTP Status Code Reference](#http-status-code-reference)

---

## Proof Verification Failures

### ASH_PROOF_INVALID (HTTP 460)

**Symptom:** Server returns `ASH_PROOF_INVALID` error (HTTP 460) despite correct implementation.

**Common Causes:**

1. **Payload modified after canonicalization**
   ```javascript
   // WRONG: Modifying after canonicalization
   const canonical = ashCanonicalizeJson(JSON.stringify(payload));
   payload.timestamp = Date.now(); // Modifies original!
   const bodyHash = ashHashBody(canonical);

   // CORRECT: Canonicalize final payload
   payload.timestamp = Date.now();
   const canonical = ashCanonicalizeJson(JSON.stringify(payload));
   const bodyHash = ashHashBody(canonical);
   ```

2. **JSON serialization differences**
   ```javascript
   // WRONG: Different serialization
   const body = JSON.stringify(payload); // May differ from canonical
   fetch(url, { body });

   // CORRECT: Use canonicalized form
   const canonical = ashCanonicalizeJson(JSON.stringify(payload));
   fetch(url, { body: canonical });
   ```

3. **Binding mismatch**
   ```javascript
   // WRONG: Different binding on client vs server
   // Client: "POST /api/users"
   // Server expects: "POST|/api/users|"

   // CORRECT: Use ashNormalizeBinding on both sides
   const binding = ashNormalizeBinding('POST', '/api/users', '');
   // Returns: "POST|/api/users|"
   ```

4. **Wrong parameter order in ashBuildProof**
   ```javascript
   // WRONG: bodyHash before timestamp
   const proof = ashBuildProof(clientSecret, bodyHash, timestamp, binding);

   // CORRECT: timestamp, binding, bodyHash
   const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
   ```

**Solution Checklist:**
- [ ] Client and server use same binding format (`METHOD|PATH|QUERY`)
- [ ] Payload is canonicalized before proof generation
- [ ] Same canonicalized payload is sent in request body
- [ ] contextId matches between context issuance and verification
- [ ] Parameter order: `ashBuildProof(clientSecret, timestamp, binding, bodyHash)`

---

### Proof Mismatch Between SDKs

**Symptom:** Client SDK generates proof that server SDK rejects, even with same inputs.

**Diagnosis:**

1. Check canonicalization output:
   ```javascript
   // Node.js
   const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
   console.log(canonical);  // {"a":2,"z":1}
   ```

   ```rust
   // Rust
   let canonical = ash_canonicalize_json(r#"{"z":1,"a":2}"#).unwrap();
   assert_eq!(canonical, r#"{"a":2,"z":1}"#);
   ```

2. Compare intermediate values:
   ```javascript
   console.log('clientSecret:', clientSecret);
   console.log('timestamp:', timestamp);
   console.log('binding:', binding);
   console.log('bodyHash:', bodyHash);
   console.log('proof:', proof);
   ```

**Common Interop Issues:**

| Issue | Cause | Solution |
|-------|-------|----------|
| Different body hash | Encoding differences | Ensure UTF-8 encoding |
| Different proof | Parameter order mismatch | Use `(clientSecret, timestamp, binding, bodyHash)` |
| Binding format | Version mismatch | Use `METHOD\|PATH\|QUERY` format |

---

## Context Errors

### ASH_CTX_NOT_FOUND (HTTP 450)

**Symptom:** Context not found (HTTP 450) even though it was just created.

**Causes:**

1. **Store not shared across instances**
   ```javascript
   // WRONG: Memory store in clustered environment
   const store = new AshMemoryStore(); // Not shared across processes!

   // CORRECT: Use Redis for production
   const store = new AshRedisStore({ client: redisClient });
   ```

2. **Context consumed by previous request**
   - Contexts are single-use
   - Network retries may consume the context
   - Check for duplicate requests

3. **Typo in contextId**
   - Copy from server response exactly
   - Check for extra whitespace

---

### ASH_CTX_EXPIRED (HTTP 451)

**Symptom:** Context expires (HTTP 451) before request reaches server.

**Causes:**

1. **TTL too short** -- Default TTL is 300 seconds (5 minutes). Reduce time between context issuance and request.

2. **Clock drift** (see [Clock Drift section](#clock-drift-and-timing))

3. **Slow client processing** -- Pre-compute payload canonicalization before requesting a context.

---

### ASH_CTX_ALREADY_USED (HTTP 452)

**Symptom:** Second request with same context fails (HTTP 452).

**This is expected behavior!** Contexts are single-use (replay protection).

**Solutions:**

1. **Request new context for each operation**
   ```javascript
   async function makeProtectedRequest(data) {
     // Always get fresh context from your server
     const ctx = await fetch('/ash/context').then(r => r.json());

     // Derive secret and build proof
     const clientSecret = ashDeriveClientSecret(ctx.nonce, ctx.id, binding);
     const bodyHash = ashHashBody(ashCanonicalizeJson(JSON.stringify(data)));
     const timestamp = String(Math.floor(Date.now() / 1000));
     const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

     return fetch('/api/endpoint', {
       method: 'POST',
       headers: {
         'x-ash-ts': timestamp,
         'x-ash-nonce': ctx.nonce,
         'x-ash-body-hash': bodyHash,
         'x-ash-proof': proof,
         'x-ash-context-id': ctx.id,
       },
       body: ashCanonicalizeJson(JSON.stringify(data)),
     });
   }
   ```

2. **Handle retries properly**
   ```javascript
   async function retryWithNewContext(data, retries = 3) {
     for (let i = 0; i < retries; i++) {
       const ctx = await getNewContext();
       try {
         return await makeRequest(ctx, data);
       } catch (e) {
         if (e.code === 'ASH_CTX_ALREADY_USED') continue;
         throw e;
       }
     }
   }
   ```

---

## Canonicalization Issues

### ASH_CANONICALIZATION_ERROR (HTTP 484)

**Symptom:** Payload cannot be canonicalized (HTTP 484).

**Common Causes:**

1. **Invalid JSON**
   ```javascript
   // WRONG
   ashCanonicalizeJson('{invalid}');  // Error: invalid JSON

   // CORRECT
   ashCanonicalizeJson('{"key":"value"}');
   ```

2. **Non-JSON content type**
   ```javascript
   // For form data, use URL-encoded canonicalization
   ashCanonicalizeUrlencoded('name=John&age=30');
   ```

3. **Binary or file data**
   - ASH doesn't support binary payloads directly
   - Base64 encode binary data first

### Inconsistent Canonicalization

**Symptom:** Same logical data produces different canonical forms.

**Causes:**

1. **Floating point precision**
   ```javascript
   // May vary across platforms
   JSON.stringify({ n: 0.1 + 0.2 }); // "0.30000000000000004"

   // Use fixed precision for financial data
   { amount: "100.00" }  // String, not number
   ```

2. **Object key order in source**
   - Don't rely on insertion order
   - Canonicalization handles key sorting automatically (RFC 8785)

3. **Unicode normalization**
   - ASH applies NFC normalization automatically during canonicalization
   - No manual pre-normalization is needed

---

## Clock Drift and Timing

### Handling Clock Drift

**Symptom:** Requests fail intermittently with `ASH_TIMESTAMP_INVALID` (HTTP 482).

**Built-in tolerance:**
- Default max timestamp age: 300 seconds (5 minutes)
- Default clock skew tolerance: 30 seconds
- These can be configured via `maxAgeSeconds` and `clockSkewSeconds` in middleware options

**Client-Side Best Practices:**
```javascript
// Generate timestamp as Unix seconds (not milliseconds)
const timestamp = String(Math.floor(Date.now() / 1000));
```

### NTP Recommendations

- Ensure all servers use NTP
- Use same NTP source for client/server when possible
- Default 30-second clock skew tolerance handles most NTP drift

---

## Rust / Node.js Interoperability

### Testing Interoperability

Before deploying, verify:

1. **Canonicalization produces identical output**
   ```bash
   # Run conformance test vectors (both SDKs share the same vectors.json)
   cd packages/ash-node-sdk && npm test
   cd packages/ashcore && cargo test
   ```

2. **Proofs are compatible**
   - Generate proof with client SDK
   - Verify with server SDK
   - Test both directions

### Common Compatibility Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| Binding format | Proof mismatch | Use `METHOD\|PATH\|QUERY` format |
| Number handling | Different hash | Use string for precise decimals |
| Unicode | Different canonical form | Both SDKs apply NFC normalization |
| Line endings | Hash mismatch | Normalize to `\n` |

---

## Performance Issues

### Slow Proof Generation

**Symptom:** Proof generation takes too long.

**Solutions:**

1. **Use the orchestrator for the full pipeline**
   ```javascript
   import { ashBuildRequest } from '@3maem/ash-node-sdk';

   const result = ashBuildRequest({
     nonce,
     contextId,
     method: 'POST',
     path: '/api/transfer',
     body: JSON.stringify({ amount: 100 }),
   });
   // result.proof, result.bodyHash, result.binding, result.timestamp
   result.destroy(); // Clean up when done
   ```

2. **Pre-canonicalize static payloads**
   ```javascript
   // Cache canonical form if payload structure is known
   const templateCanonical = ashCanonicalizeJson(template);
   ```

### High Memory Usage

**Symptom:** Context store uses too much memory.

**Solutions:**

1. **Use Redis in production**
   ```javascript
   const store = new AshRedisStore({ client: redisClient });
   // Redis handles TTL-based expiry natively
   ```

2. **Reduce TTL for AshMemoryStore**
   ```javascript
   // Shorter TTL = faster cleanup (default: 300 seconds)
   const store = new AshMemoryStore({ ttlSeconds: 60 });
   // Auto-cleanup runs every 60 seconds by default
   ```

---

## Debugging Tips

### Enable Debug Tracing

**Node.js:**
```javascript
import { ashBuildRequestDebug, ashFormatTrace } from '@3maem/ash-node-sdk';

const result = ashBuildRequestDebug({
  nonce,
  contextId,
  method: 'POST',
  path: '/api/transfer',
  body: JSON.stringify({ amount: 100 }),
});

console.log(ashFormatTrace(result.trace));
// Shows each pipeline step with timing, inputs, and outputs
// Sensitive values (clientSecret) are REDACTED
```

### Log All Inputs

When debugging proof failures, log:
```javascript
console.log('=== ASH Debug ===');
console.log('contextId:', contextId);
console.log('binding:', binding);
console.log('timestamp:', timestamp);
console.log('payload (canonical):', canonical);
console.log('bodyHash:', bodyHash);
console.log('proof:', proof);
console.log('=====================');
```

### Compare Hashes Step by Step

```javascript
// Client
const canonical = ashCanonicalizeJson(payload);
const bodyHash = ashHashBody(canonical);
console.log('Client bodyHash:', bodyHash);

// Server
const serverCanonical = ashCanonicalizeJson(receivedBody);
const serverBodyHash = ashHashBody(serverCanonical);
console.log('Server bodyHash:', serverBodyHash);

// These MUST match
```

### Use Conformance Vectors

Run the conformance test vectors to verify your implementation:

```bash
# Node.js
cd packages/ash-node-sdk && npm test

# Rust
cd packages/ashcore && cargo test
```

---

## Getting Help

If you've tried the above and still have issues:

1. **Check the error code** -- See [Error Codes Reference](reference/error-codes.md)
2. **Search existing issues** -- [GitHub Issues](https://github.com/3maem/ashcore/issues)
3. **Open a new issue** with:
   - SDK and version (`ashcore` or `@3maem/ash-node-sdk`)
   - Error message and code
   - Minimal reproduction steps
   - Debug trace output (sanitize secrets!)

---

## HTTP Status Code Reference

| Code | Error | Description |
|------|-------|-------------|
| 415 | `ASH_UNSUPPORTED_CONTENT_TYPE` | Content type not supported |
| 450 | `ASH_CTX_NOT_FOUND` | Context not found |
| 451 | `ASH_CTX_EXPIRED` | Context expired |
| 452 | `ASH_CTX_ALREADY_USED` | Replay detected |
| 460 | `ASH_PROOF_INVALID` | Proof verification failed |
| 461 | `ASH_BINDING_MISMATCH` | Endpoint mismatch |
| 473 | `ASH_SCOPE_MISMATCH` | Scope hash mismatch |
| 474 | `ASH_CHAIN_BROKEN` | Chain verification failed |
| 475 | `ASH_SCOPED_FIELD_MISSING` | Required scoped field missing |
| 482 | `ASH_TIMESTAMP_INVALID` | Timestamp validation failed |
| 483 | `ASH_PROOF_MISSING` | Missing required header |
| 484 | `ASH_CANONICALIZATION_ERROR` | Canonicalization failed |
| 485 | `ASH_VALIDATION_ERROR` | Input validation failed |
| 486 | `ASH_MODE_VIOLATION` | Security mode constraint violated |
| 500 | `ASH_INTERNAL_ERROR` | Internal server error |

See [Error Codes Reference](reference/error-codes.md) for full details.

---

**Document Version:** v1.0.0-beta
**Last Updated:** 2026-02-14
