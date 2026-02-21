# @3maem/ash-node-sdk

ASH (Application Security Hash) Node.js SDK — HMAC-SHA256 request signing and verification for tamper-proof API communication.

> **⚠️ Beta Notice:** This is v1.0.0-beta. Feature-complete but may undergo internal refinements. Not recommended for production-critical environments yet.

## Features

- **Zero runtime dependencies** — uses only Node.js `crypto`
- **134/134 conformance vectors** — byte-identical output to Rust ASH
- **Three proof modes** — basic, scoped (field-level), unified (scoped + request chaining)
- **Express & Fastify middleware** — drop-in server-side verification
- **Context lifecycle** — one-time-use nonce/proof contexts with TTL
- **Scope policy registry** — route-level field enforcement (exact, param, wildcard patterns)
- **Redis adapter** — production-ready context store via `AshRedisStore`
- **CLI tool** — `ash build`, `ash verify`, `ash inspect` from the terminal
- **Debug trace** — step-by-step pipeline inspection with timing
- **CJS + ESM + DTS** — dual build with full TypeScript declarations
- **1490+ tests** — conformance, PT, security audit, QA, fuzz, property-based

## Install

```bash
npm install @3maem/ash-node-sdk
```

## Quick Start

### Client: Build a proof

```ts
import { ashBuildRequest } from '@3maem/ash-node-sdk';

// After receiving nonce + contextId from the server:
const result = ashBuildRequest({
  nonce,           // Server-provided nonce (32+ hex chars)
  contextId,       // Server-provided context ID
  method: 'POST',
  path: '/api/orders',
  body: JSON.stringify({ amount: 100, currency: 'USD' }),
});

// Send request with ASH headers:
// x-ash-ts, x-ash-nonce, x-ash-body-hash, x-ash-proof, x-ash-context-id

result.destroy(); // Clear sensitive data (best-effort in JS)
```

### Server: Express middleware

```ts
import express from 'express';
import { AshMemoryStore, ashExpressMiddleware } from '@3maem/ash-node-sdk';

const app = express();
const store = new AshMemoryStore({ ttlSeconds: 300 });

app.use('/api', ashExpressMiddleware({ store }));

app.get('/api/users', (req, res) => {
  // req.ash contains: { verified, contextId, mode, timestamp, binding }
  res.json({ users: [] });
});
```

### Server: Fastify plugin

```ts
import Fastify from 'fastify';
import { AshMemoryStore, ashFastifyPlugin } from '@3maem/ash-node-sdk';

const fastify = Fastify();
const store = new AshMemoryStore({ ttlSeconds: 300 });

fastify.register(ashFastifyPlugin, { store });

fastify.get('/api/users', async (request) => {
  // request.ash contains: { verified, contextId, mode, timestamp, binding }
  return { users: [] };
});
```

## Full Client → Server Flow

```
┌──────────┐                          ┌──────────┐
│  Client   │                          │  Server   │
└─────┬────┘                          └─────┬────┘
      │  1. POST /context                    │
      │     { method: "GET", path: "/api/x" }│
      │─────────────────────────────────────>│
      │                                      │ Creates context:
      │                                      │   nonce, contextId,
      │                                      │   clientSecret, binding
      │                                      │ Stores in AshMemoryStore
      │  { contextId, nonce, expiresAt }     │
      │<─────────────────────────────────────│
      │                                      │
      │  2. ashBuildRequest(...)              │
      │     → proof, bodyHash, timestamp     │
      │                                      │
      │  3. GET /api/x                       │
      │     x-ash-ts: ...             │
      │     x-ash-nonce: ...                 │
      │     x-ash-body-hash: ...             │
      │     x-ash-proof: ...                 │
      │     x-ash-context-id: ...            │
      │─────────────────────────────────────>│
      │                                      │ Middleware:
      │                                      │   consume(contextId)
      │                                      │   ashVerifyRequest(...)
      │                                      │   req.ash = { verified, ... }
      │  { users: [...] }                    │
      │<─────────────────────────────────────│
      │                                      │
      │  4. Replay same request → 452        │
      │─────────────────────────────────────>│
      │  { error: "ASH_CTX_ALREADY_USED" }  │
      │<─────────────────────────────────────│
```

## API Reference

### Layer 1: Pure Crypto

#### `ashDeriveClientSecret(nonce, contextId, binding): string`
Derive HMAC-SHA256 client secret from server nonce.

#### `ashBuildProof(clientSecret, timestamp, binding, bodyHash): string`
Build basic HMAC-SHA256 proof.

#### `ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, clientProof): boolean`
Verify basic proof (re-derives secret, timing-safe compare).

#### `ashBuildProofScoped(clientSecret, timestamp, binding, payload, scopeFields): ScopedProofResult`
Build scoped proof with field extraction.

#### `ashBuildProofUnified(clientSecret, timestamp, binding, payload, scopeFields, previousProof): UnifiedProofResult`
Build unified proof with scope + request chaining.

#### `ashNormalizeBinding(method, path, rawQuery): string`
Normalize request binding to `METHOD|PATH|QUERY` format.

#### `ashHashBody(body): string`
SHA-256 hash of body content (hex).

#### `ashCanonicalizeJson(json): string`
RFC 8785 JSON canonicalization (JCS).

#### `ashCanonicalizeQuery(query): string`
Query string canonicalization with sorted keys and percent encoding.

#### `ashTimingSafeEqual(a, b): boolean`
Constant-time string comparison.

#### `ashValidateNonce(nonce): void`
Validate nonce format (32-512 hex chars).

#### `ashValidateTimestamp(timestamp, maxAge, clockSkew): number`
Validate timestamp freshness. Returns parsed timestamp value.

### Layer 2: Server Integration

#### `ashBuildRequest(input): BuildRequestResult`
7-step build orchestrator. Auto-detects mode:
- No scope, no previousProof → **basic**
- Scope present → **scoped**
- previousProof present → **unified**

```ts
interface BuildRequestInput {
  nonce: string;
  contextId: string;
  method: string;
  path: string;
  rawQuery?: string;
  body?: string;
  timestamp?: string;     // Auto-generated if omitted
  scope?: string[];
  previousProof?: string;
}

interface BuildRequestResult {
  proof: string;
  bodyHash: string;
  binding: string;
  timestamp: string;
  nonce: string;
  scopeHash?: string;
  chainHash?: string;
  destroy(): void;        // Clear sensitive data (best-effort in JS)
}
```

#### `ashVerifyRequest(input): VerifyResult`
9-step verify orchestrator. Errors returned (not thrown).

```ts
interface VerifyRequestInput {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  rawQuery?: string;
  body?: string;
  nonce: string;
  contextId: string;
  scope?: string[];
  previousProof?: string;
  maxAgeSeconds?: number;     // Default: 300
  clockSkewSeconds?: number;  // Default: 30
}

interface VerifyResult {
  ok: boolean;
  error?: AshError;
  meta?: { mode: 'basic' | 'scoped' | 'unified'; timestamp: number; binding: string };
}
```

#### `ashExtractHeaders(headers): AshHeaderBundle`
Extract and validate ASH headers (case-insensitive, control char rejection, length limits).

#### `AshMemoryStore`
In-memory context store with TTL and auto-cleanup.

```ts
const store = new AshMemoryStore({
  ttlSeconds: 300,              // Default: 300 (5 min)
  cleanupIntervalSeconds: 60,   // Default: 60 (1 min)
});

await store.store(ctx);
await store.get(id);       // Returns AshContext | null
await store.consume(id);   // Atomic one-time-use (throws on reuse)
await store.cleanup();     // Manual expired entry removal
store.destroy();           // Stop timers, clear store (AshMemoryStore only, not on AshContextStore interface)
```

#### `AshRedisStore`
Redis-backed context store for production deployments. Uses Lua scripting for atomic consume.

```ts
import { AshRedisStore } from '@3maem/ash-node-sdk';
import Redis from 'ioredis';

const store = new AshRedisStore({
  client: new Redis(),
  keyPrefix: 'ash:ctx:',  // Default
  ttlSeconds: 300,         // Default: 300
});
```

#### `AshScopePolicyRegistry`
Route-level scope field enforcement.

```ts
const registry = new AshScopePolicyRegistry();

// Exact match (required: true rejects requests without scope headers)
registry.register({ pattern: 'POST /api/orders', fields: ['amount', 'currency'], required: true });

// Param match
registry.register({ pattern: 'PUT /api/orders/:id', fields: ['status'] });

// Wildcard match
registry.register({ pattern: 'GET /api/*', fields: [] });

// Match priority: exact (3) > param (2) > wildcard (1)
const match = registry.match('POST', '/api/orders');
// → { policy: { pattern: 'POST /api/orders', fields: ['amount', 'currency'] }, params: {} }
```

#### `ashExpressMiddleware(options)`
Express middleware factory.

```ts
interface AshMiddlewareOptions {
  store: AshContextStore;
  scopeRegistry?: AshScopePolicyRegistry;
  maxAgeSeconds?: number;        // Default: 300
  clockSkewSeconds?: number;     // Default: 30
  onError?: (error: AshError, req: unknown, res: unknown) => void;
  extractBody?: (req: unknown) => string | undefined;
}
```

#### `ashFastifyPlugin(fastify, options)`
Fastify plugin with same options as Express middleware.

### Error Handling

All errors use `AshError` with typed codes and HTTP status mapping:

| Code | HTTP | Description |
|------|------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context has expired |
| `ASH_CTX_ALREADY_USED` | 452 | Context already consumed |
| `ASH_PROOF_INVALID` | 460 | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Binding mismatch |
| `ASH_SCOPE_MISMATCH` | 473 | Scope mismatch |
| `ASH_CHAIN_BROKEN` | 474 | Chain broken |
| `ASH_SCOPED_FIELD_MISSING` | 475 | Scoped field missing |
| `ASH_TIMESTAMP_INVALID` | 482 | Timestamp invalid |
| `ASH_PROOF_MISSING` | 483 | Proof missing |
| `ASH_CANONICALIZATION_ERROR` | 484 | Canonicalization error |
| `ASH_VALIDATION_ERROR` | 485 | Validation error |
| `ASH_MODE_VIOLATION` | 486 | Mode violation |
| `ASH_UNSUPPORTED_CONTENT_TYPE` | 415 | Unsupported content type |
| `ASH_INTERNAL_ERROR` | 500 | Internal error |

### Layer 3: CLI & Debug

#### CLI Tool

The SDK ships with an `ash` CLI for terminal-based proof operations. Zero dependencies — uses Node.js built-in `parseArgs`.

```bash
# Build a proof
ash build --nonce <hex> --context-id <id> --method POST --path /api/orders \
  --body '{"amount":100}' --json

# Verify a proof
ash verify --nonce <hex> --context-id <id> --method POST --path /api/orders \
  --proof <hex> --body-hash <hex> --timestamp <unix> \
  --max-age 300 --clock-skew 30 --json

# Hash operations
ash hash body '{"amount":100}'       # SHA-256 of canonical body
ash hash scope amount currency       # SHA-256 of sorted scope fields
ash hash proof <hex>                 # SHA-256 of proof for chaining

# Derive client secret
ash derive --nonce <hex> --context-id <id> --binding "POST|/api/orders|"

# Debug trace (step-by-step pipeline inspection)
ash inspect build --nonce <hex> --context-id <id> --method GET --path /api
ash inspect verify --nonce <hex> --context-id <id> --method GET --path /api \
  --proof <hex> --body-hash <hex> --timestamp <unix>

# Version
ash version
# @3maem/ash-node-sdk v1.2.0
```

**Exit codes:** `0` success, `1` invalid proof, `2` usage error, `3` internal error

All commands support `--json` for machine-readable output and `--help` for usage info.

#### Debug Trace (Programmatic)

```ts
import { ashBuildRequestDebug, ashVerifyRequestDebug, ashFormatTrace } from '@3maem/ash-node-sdk';

// Build with trace
const result = ashBuildRequestDebug({
  nonce, contextId, method: 'POST', path: '/api/orders',
  body: '{"amount":100}',
});

console.log(result.proof);          // Same output as ashBuildRequest()
console.log(result.mode);           // 'basic' | 'scoped' | 'unified'
console.log(result.totalDurationMs);
console.log(ashFormatTrace(result.trace));
// [1/7] validate_nonce .............. OK (0.01ms)
// [2/7] validate_timestamp ......... OK (0.00ms)
// [3/7] normalize_binding .......... OK (0.02ms)
// [4/7] hash_body .................. OK (0.03ms)
// [5/7] derive_secret .............. OK (0.01ms)
//       clientSecret: "[REDACTED]"
// [6/7] build_proof ................ OK (0.02ms)
// [7/7] assemble_result ............ OK (0.00ms)

// Verify with trace
const verifyResult = ashVerifyRequestDebug({
  headers, method: 'POST', path: '/api/orders',
  body: '{"amount":100}', nonce, contextId,
});

console.log(verifyResult.ok);       // true/false
console.log(verifyResult.trace);    // 9 steps with timing
```

Sensitive values (client secrets, full proofs) are always REDACTED in trace output.

### Header Constants

```ts
import {
  X_ASH_TIMESTAMP,    // 'x-ash-ts'
  X_ASH_NONCE,        // 'x-ash-nonce'
  X_ASH_BODY_HASH,    // 'x-ash-body-hash'
  X_ASH_PROOF,        // 'x-ash-proof'
  X_ASH_CONTEXT_ID,   // 'x-ash-context-id'
} from '@3maem/ash-node-sdk';
```

## Examples

See [`examples/`](./examples/) for complete working examples:
- `express-example.ts` — Full Express client→server flow
- `fastify-example.ts` — Full Fastify client→server flow with scoped proofs

## Requirements

- Node.js >= 18.0.0

### Peer Dependencies (optional)

- `express` >= 4.0.0 — for `ashExpressMiddleware()`
- `fastify` >= 4.0.0 — for `ashFastifyPlugin()`
- `ioredis` >= 5.0.0 — for `AshRedisStore`

## Links

- [Website](https://ashcore.ai)
- [GitHub](https://github.com/3maem/ashcore)
- [npm](https://www.npmjs.com/package/@3maem/ash-node-sdk)

## License

Apache-2.0
