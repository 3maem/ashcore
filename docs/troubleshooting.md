# ASH SDK Troubleshooting Guide

This guide covers common issues and their solutions when integrating ASH into your applications.

---

## Table of Contents

1. [Proof Verification Failures](#proof-verification-failures)
2. [Context Errors](#context-errors)
3. [Canonicalization Issues](#canonicalization-issues)
4. [Clock Drift and Timing](#clock-drift-and-timing)
5. [Cross-SDK Compatibility](#cross-sdk-compatibility)
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
   const canonical = ashCanonicalizeJson(payload);
   payload.timestamp = Date.now(); // Modifies original!
   const bodyHash = ashHashBody(canonical);

   // CORRECT: Canonicalize final payload
   payload.timestamp = Date.now();
   const canonical = ashCanonicalizeJson(JSON.stringify(payload));
   const bodyHash = ashHashBody(canonical);
   const proof = ashBuildProofHmac(clientSecret, bodyHash, timestamp, binding);
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

   // CORRECT: Use consistent binding format
   const binding = ashNormalizeBinding('POST', '/api/users', '');
   ```

4. **Using wrong client secret**
   - Verify `contextId` matches
   - Verify `nonce` (if using strict mode) is correct
   - Check for copy/paste errors

**Solution Checklist:**
- [ ] Client and server use same binding format
- [ ] Payload is canonicalized before proof generation
- [ ] Same canonicalized payload is sent in request body
- [ ] contextId matches between context issuance and verification

---

### Proof Mismatch Between SDKs

**Symptom:** Client SDK generates proof that server SDK rejects, even with same inputs.

**Diagnosis:**

1. Check canonicalization output:
   ```python
   # Both should produce identical output
   # Python
   canonical = ash_canonicalize_json('{"z":1,"a":2}')
   print(repr(canonical))  # '{"a":2,"z":1}'

   # Node.js
   const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
   console.log(canonical);  // {"a":2,"z":1}
   ```

2. Compare intermediate values:
   ```python
   # Debug: Print all inputs
   print(f"clientSecret: {client_secret}")
   print(f"timestamp: {timestamp}")
   print(f"binding: {binding}")
   print(f"bodyHash: {body_hash}")
   print(f"proof: {proof}")
   ```

**Common Cross-SDK Issues:**

| Issue | Cause | Solution |
|-------|-------|----------|
| Different body hash | Encoding differences | Ensure UTF-8 encoding |
| Different proof | Algorithm mismatch | Verify HMAC-SHA256 implementation |
| Binding format | Version mismatch | Use binding format `METHOD\|PATH\|QUERY` |

---

## Context Errors

### ASH_CTX_NOT_FOUND (HTTP 450)

**Symptom:** Context not found (HTTP 450) even though it was just created.

**Causes:**

1. **Store not shared across instances**
   ```javascript
   // WRONG: Memory store in clustered environment
   const store = new AshMemoryStore(); // Not shared!

   // CORRECT: Use Redis for production
   const store = new AshRedisStore(redisClient);
   ```

2. **Context consumed by previous request**
   - Contexts are single-use
   - Network retries may consume the context
   - Check for duplicate requests

3. **Typo in contextId**
   - Copy from server response exactly
   - Check for extra whitespace

**Debugging:**
```javascript
// Server: Log context creation
const ctx = await store.create({ binding, ttlMs: 30000 });
console.log('Created context:', ctx.id);

// Client: Log context usage
console.log('Using context:', contextId);
```

---

### ASH_CTX_EXPIRED (HTTP 451)

**Symptom:** Context expires (HTTP 451) before request reaches server.

**Causes:**

1. **TTL too short**
   ```javascript
   // WRONG: 5 second TTL with slow network
   const ctx = await store.create({ ttlMs: 5000 });

   // CORRECT: Use appropriate TTL
   const ctx = await store.create({ ttlMs: 30000 }); // 30 seconds
   ```

2. **Clock drift** (see [Clock Drift section](#clock-drift-and-timing))

3. **Slow client processing**
   - Reduce time between context issuance and request
   - Pre-fetch contexts if needed

**Best Practices:**
- Use 30 second TTL for normal operations
- Use shorter TTL (10s) for high-value transactions
- Never exceed 5 minutes

---

### ASH_CTX_ALREADY_USED (HTTP 452)

**Symptom:** Second request with same context fails (HTTP 452).

**This is expected behavior!** Contexts are single-use (replay protection).

**Solutions:**

1. **Request new context for each operation**
   ```javascript
   async function makeProtectedRequest(data) {
     // Always get fresh context
     const ctx = await fetch('/ash/context').then(r => r.json());
     const proof = buildProof(ctx, data);
     return fetch('/api/endpoint', { ... });
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

### ASH_CANONICALIZATION_ERROR (HTTP 422)

**Symptom:** Payload cannot be canonicalized (HTTP 422).

**Common Causes:**

1. **Invalid JSON**
   ```javascript
   // WRONG
   ashCanonicalizeJson('{invalid}');  // Error!
   ashCanonicalizeJson('hello');       // Error! (not an object)

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
   - Canonicalization handles sorting

3. **Unicode normalization**
   - ASH uses NFC normalization
   - Pre-normalize if using unusual Unicode

---

## Clock Drift and Timing

### Handling Clock Drift

**Symptom:** Requests fail intermittently with timing-related errors.

**Server-Side Tolerance:**
```javascript
const MAX_CLOCK_DRIFT_MS = 5000; // 5 seconds

function verifyTimestamp(clientTimestamp) {
  const serverTime = Date.now();
  const drift = Math.abs(serverTime - parseInt(clientTimestamp));

  if (drift > MAX_CLOCK_DRIFT_MS) {
    throw new Error('Timestamp outside acceptable range');
  }
}
```

**Client-Side Best Practices:**
```javascript
// Sync time with server if possible
async function getSyncedTimestamp() {
  const serverTime = await fetch('/api/time').then(r => r.json());
  const localTime = Date.now();
  const offset = serverTime.timestamp - localTime;

  return Date.now() + offset;
}
```

### NTP Recommendations

- Ensure all servers use NTP
- Use same NTP source for client/server when possible
- Allow 5-10 second drift tolerance

---

## Cross-SDK Compatibility

### Testing Interoperability

Before deploying, verify:

1. **Canonicalization produces identical output**
   ```bash
   # Test with cross-SDK test vectors
   cd tests/cross-sdk
   python run_tests.py
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
| Unicode | Different canonical form | Ensure NFC normalization |
| Line endings | Hash mismatch | Normalize to `\n` |

---

## Performance Issues

### Slow Proof Generation

**Symptom:** Proof generation takes too long.

**Solutions:**

1. **Use appropriate security mode**
   ```javascript
   // Create context with appropriate mode
   const ctx = await store.create({ binding, ttlMs: 30000, mode: 'balanced' });

   // Generate proof using v2.1+ HMAC style
   const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
   const bodyHash = ashHashBody(canonical);
   const proof = ashBuildProofHmac(clientSecret, bodyHash, timestamp, binding);
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
   const store = new AshRedisStore(redisClient);
   ```

2. **Reduce TTL**
   ```javascript
   // Shorter TTL = faster cleanup
   store.create({ ttlMs: 15000 });
   ```

3. **Run cleanup regularly**
   ```javascript
   setInterval(() => store.cleanup(), 60000);
   ```

---

## Debugging Tips

### Enable Debug Logging

**Node.js:**
```javascript
import { ashInit } from '@3maem/ash-node-sdk';
ashInit({ debug: true });
```

**Python:**
```python
import logging
logging.getLogger('ash').setLevel(logging.DEBUG)
```

### Log All Inputs

When debugging proof failures, log:
```javascript
console.log('=== ASH Debug ===');
console.log('contextId:', contextId);
console.log('binding:', binding);
console.log('timestamp:', timestamp);
console.log('payload (raw):', payload);
console.log('payload (canonical):', canonical);
console.log('bodyHash:', bodyHash);
console.log('proof:', proof);
console.log('=================');
```

### Compare Hashes Step by Step

```javascript
// Client
const canonical = ashCanonicalizeJson(payload);
const bodyHash = ashHashBody(canonical);
console.log('Client bodyHash:', bodyHash);

// Server
const canonical = ashCanonicalizeJson(receivedBody);
const bodyHash = ashHashBody(canonical);
console.log('Server bodyHash:', bodyHash);

// These MUST match
```

### Use Test Vectors

Run the cross-SDK test vectors to verify your implementation:

```bash
cd tests/cross-sdk
# Run against your SDK
python verify_sdk.py --sdk node
```

---

## Getting Help

If you've tried the above and still have issues:

1. **Check the error code** - See [Error Codes Reference](docs/reference/error-codes.md)
2. **Search existing issues** - [GitHub Issues](https://github.com/3maem/ashcore/issues)
3. **Open a new issue** with:
   - SDK version
   - Error message and code
   - Minimal reproduction steps
   - Debug output (sanitize secrets!)

---

## HTTP Status Code Reference

| Code | Error | Description |
|------|-------|-------------|
| 450 | `ASH_CTX_NOT_FOUND` | Context not found |
| 451 | `ASH_CTX_EXPIRED` | Context expired |
| 452 | `ASH_CTX_ALREADY_USED` | Replay detected |
| 460 | `ASH_PROOF_INVALID` | Proof verification failed |
| 461 | `ASH_BINDING_MISMATCH` | Endpoint mismatch |
| 473 | `ASH_SCOPE_MISMATCH` | Scope hash mismatch |
| 474 | `ASH_CHAIN_BROKEN` | Chain verification failed |
| 482 | `ASH_TIMESTAMP_INVALID` | Timestamp validation failed |
| 483 | `ASH_PROOF_MISSING` | Missing proof header |
| 422 | `ASH_CANONICALIZATION_ERROR` | Canonicalization failed |

---

**Document Version:** 1.0.0
**Last Updated:** 2026-02-06
