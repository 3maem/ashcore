# ASH WASM SDK API Reference

**Version:** 1.0.0
**Package:** `@3maem/ash-wasm-sdk`

## Installation

### npm (Node.js / Browsers)

```bash
npm install @3maem/ash-wasm-sdk
```

### Cargo (Rust projects using WASM)

```bash
cargo add ash-wasm-sdk
```

---

## Overview

ASH WASM provides browser and cross-platform access to the ASH protocol through WebAssembly. It wraps the Rust `ashcore` implementation for use in:

- **Browsers** (Chrome, Firefox, Safari, Edge)
- **Node.js** (via WASM)
- **Deno**
- **Any WASM runtime** (Python, Go, .NET, PHP)

---

## Initialization

```javascript
import * as ash from '@3maem/ash-wasm-sdk';

// Initialize (call once)
ash.ashInit();
```

---

## Canonicalization

| Function | Description |
|----------|-------------|
| `ashCanonicalizeJson(input)` | Canonicalize JSON to RFC 8785 form |
| `ashCanonicalizeUrlencoded(input)` | Canonicalize URL-encoded form data |
| `ashCanonicalizeQuery(query)` | Canonicalize URL query string |

### Example

```javascript
const canonical = ash.ashCanonicalizeJson('{"z":1,"a":2}');
// => '{"a":2,"z":1}'
```

---

## Proof Functions (v1)

| Function | Description |
|----------|-------------|
| `ashBuildProof(mode, binding, contextId, nonce, payload)` | Build legacy proof |
| `ashVerifyProof(expected, actual)` | Constant-time proof comparison |

---

## Proof Functions (v2.1)

| Function | Description |
|----------|-------------|
| `ashGenerateNonce(bytes?)` | Generate cryptographic nonce |
| `ashGenerateContextId()` | Generate unique context ID |
| `ashDeriveClientSecret(nonce, contextId, binding)` | Derive client secret |
| `ashBuildProofHmac(secret, bodyHash, timestamp, binding)` | Build HMAC-SHA256 proof |
| `ashVerifyProofHmac(nonce, contextId, proof, bodyHash, timestamp, binding)` | Verify proof |
| `ashHashBody(body)` | SHA-256 hash of body |

---

## Proof Functions (v2.2 - Scoping)

| Function | Description |
|----------|-------------|
| `ashBuildProofScoped(secret, timestamp, binding, payload, scope)` | Build scoped proof |
| `ashVerifyProofScoped(...)` | Verify scoped proof |
| `ashHashScopedBody(payload, scope)` | Hash scoped fields |

---

## Proof Functions (v2.3 - Unified)

| Function | Description |
|----------|-------------|
| `ashBuildProofUnified(secret, timestamp, binding, payload, scope, previousProof)` | Build unified proof |
| `ashVerifyProofUnified(...)` | Verify unified proof |
| `ashHashProof(proof)` | Hash proof for chaining |

---

## Binding & Utilities

| Function | Description |
|----------|-------------|
| `ashNormalizeBinding(method, path, query)` | Normalize endpoint binding |
| `ashNormalizeBindingFromUrl(method, fullPath)` | Normalize from full URL |
| `ashTimingSafeEqual(a, b)` | Constant-time string comparison |
| `ashVersion()` | Get protocol version |
| `ashLibraryVersion()` | Get library version |

---

## Quick Start (Browser)

```javascript
import * as ash from '@3maem/ash-wasm-sdk';

ash.ashInit();

// Canonicalize JSON
const canonical = ash.ashCanonicalizeJson('{"z":1,"a":2}');

// Build a proof
const proof = ash.ashBuildProof(
  'balanced',           // mode
  'POST /api/transfer', // binding
  'ctx_abc123',         // contextId
  null,                 // nonce (optional)
  canonical             // payload
);
```

---

## Full Client-Server Flow

```javascript
import * as ash from '@3maem/ash-wasm-sdk';

ash.ashInit();

// 1. Get context from server
const { contextId, clientSecret } = await fetch('/ash/context', {
  method: 'POST',
  body: JSON.stringify({ binding: 'POST|/api/transfer|' })
}).then(r => r.json());

// 2. Prepare request
const payload = { amount: 100, to: 'account123' };
const canonical = ash.ashCanonicalizeJson(JSON.stringify(payload));
const bodyHash = ash.ashHashBody(canonical);
const timestamp = Date.now().toString();
const binding = ash.ashNormalizeBinding('POST', '/api/transfer', '');

// 3. Build proof
const proof = ash.ashBuildProofHmac(clientSecret, bodyHash, timestamp, binding);

// 4. Send protected request
const response = await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ASH-Context-ID': contextId,
    'X-ASH-Proof': proof,
    'X-ASH-Timestamp': timestamp
  },
  body: JSON.stringify(payload)
});
```

---

## Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Proof invalid |
| `ASH_BINDING_MISMATCH` | 461 | Binding mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Scope mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Chain broken |
| `ASH_TIMESTAMP_INVALID` | 482 | Timestamp invalid |
| `ASH_PROOF_MISSING` | 483 | Proof missing |

---

## Browser Compatibility

| Browser | Version |
|---------|---------|
| Chrome | 57+ |
| Firefox | 52+ |
| Safari | 11+ |
| Edge | 16+ |

---

## Bundle Size

| Build | Size (gzip) |
|-------|-------------|
| Bundler | ~45KB |
| Web | ~50KB |
| Node.js | ~48KB |

---

## Performance

| Operation | WASM | Native Rust |
|-----------|------|-------------|
| JSON canonicalization | ~60μs | ~50μs |
| Proof generation | ~4μs | ~3μs |
| Proof verification | ~8μs | ~6μs |

---

## Input Validation

| Parameter | Rule |
|-----------|------|
| `nonce` | Minimum 32 hex characters |
| `nonce` | Maximum 128 characters |
| `nonce` | Hexadecimal only (0-9, a-f, A-F) |
| `contextId` | Cannot be empty |
| `contextId` | Maximum 256 characters |
| `contextId` | Alphanumeric, underscore, hyphen, dot only |
| `binding` | Maximum 8192 bytes |

---

## Building from Source

```bash
# For webpack/vite/rollup
wasm-pack build --target bundler

# For Node.js require()
wasm-pack build --target nodejs

# For <script> tag (no bundler)
wasm-pack build --target web

# For Deno
wasm-pack build --target deno
```

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
