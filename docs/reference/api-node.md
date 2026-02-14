# ASH Node.js SDK API Reference

**Version:** 1.0.0
**Package:** `@3maem/ash-node-sdk`

## Installation

```bash
npm install @3maem/ash-node-sdk
```

**Requirements:** Node.js 18.0.0 or later

---

## Exports

```typescript
import {
  ashBuildRequest,
  ashVerifyRequest,
  ashExpressMiddleware,
  ashFastifyPlugin,
  AshMemoryStore,
  ashDebugTrace,
} from '@3maem/ash-node-sdk';
```

---

## Constants

### Version Constants

```typescript
const ASH_SDK_VERSION = "1.0.0";
const ASH_VERSION_PREFIX = "ASHv2.1";
```

### Security Modes

```typescript
type AshMode = 'minimal' | 'balanced' | 'strict';
```

| Mode | Description |
|------|-------------|
| `minimal` | Basic integrity checking |
| `balanced` | Recommended for most applications |
| `strict` | Maximum security with nonce requirement |

### Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Binding mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Scope mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Chain broken |
| `ASH_TIMESTAMP_INVALID` | 482 | Timestamp invalid |
| `ASH_PROOF_MISSING` | 483 | Proof missing |

---

## Canonicalization

### ashCanonicalizeJson

```typescript
function ashCanonicalizeJson(input: string): string
```

Canonicalizes JSON to deterministic form per RFC 8785 (JCS).

```typescript
const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
// Result: '{"a":2,"z":1}'
```

### ashCanonicalizeUrlencoded

```typescript
function ashCanonicalizeUrlencoded(input: string): string
```

Canonicalizes URL-encoded form data.

```typescript
const canonical = ashCanonicalizeUrlencoded('z=1&a=2');
// Result: 'a=2&z=1'
```

---

## Proof Generation

### ashBuildProof

```typescript
function ashBuildProof(
  mode: AshMode,
  binding: string,
  contextId: string,
  nonce: string | null,
  canonicalPayload: string
): string
```

Builds a cryptographic proof for request integrity.

### ashBuildProofHmac

```typescript
function ashBuildProofHmac(
  clientSecret: string,
  bodyHash: string,
  timestamp: string,
  binding: string
): string
```

Builds an HMAC-SHA256 proof (v2.1 format).

---

## Proof Verification

### ashVerifyProof

```typescript
function ashVerifyProof(expected: string, actual: string): boolean
```

Verifies two proofs match using constant-time comparison.

### ashTimingSafeEqual

```typescript
function ashTimingSafeEqual(a: string, b: string): boolean
```

Constant-time string comparison to prevent timing attacks.

---

## Binding

### ashNormalizeBinding

```typescript
function ashNormalizeBinding(method: string, path: string): string
```

Normalizes a binding string to canonical form.

```typescript
const binding = ashNormalizeBinding('post', '/api//test/');
// Result: 'POST /api/test'
```

---

## Cryptographic Utilities

| Function | Description |
|----------|-------------|
| `ashGenerateNonce(bytes)` | Generate cryptographic nonce |
| `ashGenerateContextId()` | Generate unique context ID |
| `ashDeriveClientSecret(nonce, contextId, binding)` | Derive client secret |
| `ashHashBody(body)` | SHA-256 hash of body |

---

## Build / Verify Orchestrators

### ashBuildRequest

```typescript
function ashBuildRequest(input: AshBuildRequestInput): AshBuildRequestResult
```

One-call orchestrator that canonicalizes, hashes, derives the secret, and builds the proof + headers.

### ashVerifyRequest

```typescript
function ashVerifyRequest(input: AshVerifyRequestInput): AshVerifyResult
```

One-call orchestrator that extracts headers, looks up context, and verifies the proof.

---

## Context Stores

### AshMemoryStore

In-memory store for development and testing.

```typescript
import { AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();
```

### AshRedisStore

Production-ready store with atomic operations.

```typescript
import { AshRedisStore } from '@3maem/ash-node-sdk';
import Redis from 'ioredis';

const redis = new Redis('redis://localhost:6379');
const store = new AshRedisStore(redis);
```

---

## Express Middleware

```typescript
import { ashExpressMiddleware, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

app.post(
  '/api/update',
  ashExpressMiddleware({
    store,
    expectedBinding: 'POST /api/update',
  }),
  handler
);
```

---

## Fastify Plugin

```typescript
import { ashFastifyPlugin, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

fastify.register(ashFastifyPlugin, {
  store,
  protectedPaths: ['/api/*'],
});
```

---

## Debug Trace

```typescript
import { ashDebugTrace } from '@3maem/ash-node-sdk';

const trace = ashDebugTrace(buildResult);
console.log(trace);
```

---

## HTTP Headers

| Header | Description |
|--------|-------------|
| `X-ASH-Context-ID` | Context identifier |
| `X-ASH-Proof` | Cryptographic proof |
| `X-ASH-Mode` | Security mode |
| `X-ASH-Timestamp` | Request timestamp |
| `X-ASH-Scope` | Comma-separated scoped fields |
| `X-ASH-Scope-Hash` | Hash of scoped fields |
| `X-ASH-Chain-Hash` | Hash of previous proof |

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

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
