# ASH Express.js Integration Example

This example demonstrates how to integrate ASH with Express.js for request integrity verification.

## Quick Start

```bash
# Install dependencies
npm install express @3maem/ash-node-sdk

# Run the server
node server.js

# In another terminal, run the client
node client.js
```

## Server Setup

The server configures ASH middleware to protect specific endpoints:

```javascript
import { AshMemoryStore, ashExpressMiddleware } from '@3maem/ash-node-sdk';

const ashStore = new AshMemoryStore();

app.use('/api/transfer', ashExpressMiddleware({
  store: ashStore,
  expectedBinding: 'POST|/api/transfer|',
  mode: 'balanced',
}));
```

## Client Usage

Clients must:
1. Request a context from `/api/context`
2. Build a proof using the payload and context
3. Include ASH headers in the request

```javascript
const response = await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-ASH-Context-ID': context.contextId,
    'X-ASH-Timestamp': timestamp,
    'X-ASH-Proof': proof,
  },
  body: JSON.stringify(payload),
});
```

## Production Considerations

1. **Use Redis Store**: Replace `AshMemoryStore` with `AshRedisStore` for multi-instance deployments
2. **Configure TTL**: Adjust context TTL based on your security requirements
3. **Enable Strict Mode**: Use `mode: 'strict'` for high-security endpoints
4. **HTTPS Only**: Always use HTTPS in production

## Error Handling

ASH errors return 403 Forbidden with error codes:
- `ASH_CTX_NOT_FOUND`: Context doesn't exist
- `ASH_CTX_EXPIRED`: Context has expired
- `ASH_CTX_USED`: Context already consumed (replay attempt)
- `ASH_PROOF_MISMATCH`: Invalid proof (tampering detected)
