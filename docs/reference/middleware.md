# ASH Middleware Reference

**Version:** 1.0.0

This document provides an overview of all available ASH middleware implementations.

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

## Node.js Middleware

### Express

```javascript
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

### Fastify

```javascript
import { ashFastifyPlugin, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

fastify.register(ashFastifyPlugin, {
  store,
  protectedPaths: ['/api/*'],
});
```

See [Node.js API Reference](api-node.md) for full documentation.

---

## Common Configuration Options

All middleware implementations support these common options:

| Option | Description |
|--------|-------------|
| `store` | Context store instance (Memory or Redis) |
| `protectedPaths` | URL patterns to protect |
| `skip` | Function to conditionally skip verification |
| `onError` | Custom error handler |

---

## HTTP Headers

All middleware implementations expect these headers:

| Header | Required | Description |
|--------|----------|-------------|
| `X-ASH-Context-ID` | Yes | Context identifier |
| `X-ASH-Proof` | Yes | Cryptographic proof |
| `X-ASH-Timestamp` | Yes | Request timestamp (Unix ms) |
| `X-ASH-Mode` | No | Security mode |
| `X-ASH-Scope` | No | Scoped fields (v2.2+) |
| `X-ASH-Scope-Hash` | No | Scope hash (v2.2+) |
| `X-ASH-Chain-Hash` | No | Chain hash (v2.3+) |

---

## Error Responses

When verification fails, middleware returns these error codes:

| Code | HTTP | Description |
|------|------|-------------|
| `ASH_CTX_NOT_FOUND` | 450 | Context not found |
| `ASH_CTX_EXPIRED` | 451 | Context expired |
| `ASH_CTX_ALREADY_USED` | 452 | Replay detected |
| `ASH_PROOF_INVALID` | 460 | Proof verification failed |
| `ASH_BINDING_MISMATCH` | 461 | Binding mismatch |
| `ASH_PROOF_MISSING` | 483 | Proof header missing |

See [Error Codes Reference](error-codes.md) for complete error code documentation.

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
