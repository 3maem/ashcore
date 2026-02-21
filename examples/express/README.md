# ASH Express.js Integration Example

This example demonstrates how to integrate ASH with Express.js for request integrity verification.

## Quick Start

```bash
# Install dependencies
npm install

# Run the server
npm start
```

## How It Works

### 1. Server Issues a Context

The server generates a nonce and contextId, derives the client secret, stores the context, and returns `{ nonce, contextId, binding }` to the client.

```javascript
import crypto from 'node:crypto';
import {
  AshMemoryStore,
  ashDeriveClientSecret,
  ashNormalizeBinding,
} from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

app.get('/api/context', async (req, res) => {
  const binding = ashNormalizeBinding('POST', '/api/update', '');
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = crypto.randomBytes(16).toString('hex');
  const now = Math.floor(Date.now() / 1000);

  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

  await store.store({
    id: contextId,
    nonce,
    binding,
    clientSecret,
    used: false,
    createdAt: now,
    expiresAt: now + 300,
  });

  res.json({ contextId, nonce, binding });
});
```

### 2. Server Protects Endpoints

```javascript
import { ashExpressMiddleware } from '@3maem/ash-node-sdk';

app.post('/api/update', ashExpressMiddleware({ store }), (req, res) => {
  // req.ash contains verification metadata:
  //   { verified: true, contextId, mode, timestamp, binding }
  res.json({ success: true, data: req.body });
});
```

### 3. Client Sends Protected Request

Clients must:
1. Request a context from `/api/context`
2. Derive a client secret and build an HMAC-SHA256 proof
3. Include all 5 ASH headers in the request

```javascript
import {
  ashDeriveClientSecret,
  ashBuildProof,
  ashHashBody,
  ashCanonicalizeJson,
} from '@3maem/ash-node-sdk';

// 1. Get context from server
const ctx = await fetch('/api/context?method=POST&path=/api/update').then(r => r.json());

// 2. Build proof
const body = JSON.stringify({ key: 'value' });
const canonical = ashCanonicalizeJson(body);
const bodyHash = ashHashBody(canonical);
const timestamp = String(Math.floor(Date.now() / 1000));
const clientSecret = ashDeriveClientSecret(ctx.nonce, ctx.contextId, ctx.binding);
const proof = ashBuildProof(clientSecret, timestamp, ctx.binding, bodyHash);

// 3. Send request with all 5 headers
const response = await fetch('/api/update', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-ash-ts': timestamp,
    'x-ash-nonce': ctx.nonce,
    'x-ash-body-hash': bodyHash,
    'x-ash-proof': proof,
    'x-ash-context-id': ctx.contextId,
  },
  body: canonical,
});
```

## Production Considerations

1. **Use Redis Store**: Replace `AshMemoryStore` with `AshRedisStore` for multi-instance deployments
   ```javascript
   import { AshRedisStore } from '@3maem/ash-node-sdk';
   const store = new AshRedisStore({ client: redisClient });
   ```
2. **HTTPS Only**: Always use HTTPS in production
3. **Configure TTL**: Default context TTL is 300 seconds (5 minutes)
4. **Scope Policies**: Use `AshScopePolicyRegistry` for field-level protection

## Error Handling

ASH errors return specific HTTP status codes:

| Code | Error | Description |
|------|-------|-------------|
| 450 | `ASH_CTX_NOT_FOUND` | Context doesn't exist |
| 451 | `ASH_CTX_EXPIRED` | Context has expired |
| 452 | `ASH_CTX_ALREADY_USED` | Context already consumed (replay attempt) |
| 460 | `ASH_PROOF_INVALID` | Invalid proof (tampering detected) |
| 461 | `ASH_BINDING_MISMATCH` | Request doesn't match context binding |
| 483 | `ASH_PROOF_MISSING` | Required header missing |

See [Error Codes Reference](../../docs/reference/error-codes.md) for the complete list.
