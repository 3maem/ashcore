# ASH Middleware Reference

**Version:** v1.0.0-beta

---

## Overview

ASH middleware integrates with web frameworks to automatically verify request integrity. Each middleware:

- Extracts ASH headers from incoming requests
- Verifies cryptographic proofs against stored contexts
- Rejects requests that fail verification
- Passes verified requests to application handlers

---

## Available Middleware

| Framework | SDK | Package |
|-----------|-----|---------|
| Express | Node.js | `@3maem/ash-node-sdk` |
| Fastify | Node.js | `@3maem/ash-node-sdk` |

---

## Express Middleware

```typescript
import { ashExpressMiddleware, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

app.use(ashExpressMiddleware({ store }));
```

## Fastify Plugin

```typescript
import { ashFastifyPlugin, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

fastify.register(ashFastifyPlugin, { store });
```

See [Node.js API Reference](api-node.md) for full documentation.

---

## Configuration Options

```typescript
export interface AshMiddlewareOptions {
  store: AshContextStore;
  scopeRegistry?: AshScopePolicyRegistry;
  maxAgeSeconds?: number;       // default: 300
  clockSkewSeconds?: number;    // default: 30
  onError?: (error: AshError, req: unknown, res: unknown) => void;
  extractBody?: (req: unknown) => string | undefined;
}
```

---

## Required HTTP Headers

All middleware implementations expect these 5 headers (case-insensitive):

| Header | Required | Description |
|--------|----------|-------------|
| `x-ash-ts` | Yes | Unix timestamp (seconds) |
| `x-ash-nonce` | Yes | Cryptographic nonce (hex) |
| `x-ash-body-hash` | Yes | SHA-256 hash of canonical body |
| `x-ash-proof` | Yes | HMAC-SHA256 proof |
| `x-ash-context-id` | Yes | Context identifier |

---

## Error Responses

When verification fails, middleware returns:

| Code | HTTP | Description |
|------|------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Binding mismatch |
| `ASH_PROOF_MISSING` | 483 | Required header missing |

See [Error Codes Reference](error-codes.md) for the complete list.

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
