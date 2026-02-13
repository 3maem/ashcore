# ASH Flask Integration Example

This example demonstrates how to integrate ASH with Flask for request integrity verification.

## Quick Start

```bash
# Install dependencies
pip install flask ash-python-sdk

# Run the server
python app.py

# Test with curl
curl http://localhost:5000/health
```

## Server Setup

The server uses a decorator to protect endpoints:

```python
from ash.server import context
from ash.server.stores import Memory as MemoryStore

ash_store = MemoryStore()

@ash_protected
async def transfer():
    # This code only runs if ASH verification passes
    data = request.get_json()
    # Process transfer...
```

## Client Usage

```python
import requests
from ash.core import (
    ash_canonicalize_json,
    ash_build_proof_v21,
    ash_hash_body,
)

# 1. Get context
ctx = requests.post('http://localhost:5000/api/context', json={
    'endpoint': '/api/transfer',
    'ttlMs': 30000
}).json()

# 2. Prepare request
payload = {'fromAccount': 'ACC_001', 'toAccount': 'ACC_002', 'amount': 100}
body_hash = ash_hash_body(ash_canonicalize_json(payload))
timestamp = str(int(time.time() * 1000))

# 3. Build proof
proof = ash_build_proof_v21(ctx['clientSecret'], timestamp, binding, body_hash)

# 4. Make request
response = requests.post('http://localhost:5000/api/transfer',
    json=payload,
    headers={
        'X-ASH-Context-ID': ctx['contextId'],
        'X-ASH-Timestamp': timestamp,
        'X-ASH-Proof': proof,
    }
)
```

## Production Considerations

1. **Use Redis Store**: Replace `MemoryStore` with `RedisStore`
2. **Run with Gunicorn**: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker app:app`
3. **Enable HTTPS**: Use a reverse proxy like nginx
4. **Configure CORS**: Add flask-cors for cross-origin requests

## Error Codes

| Code | Description |
|------|-------------|
| ASH_CTX_NOT_FOUND | Context doesn't exist |
| ASH_CTX_EXPIRED | Context has expired |
| ASH_CTX_USED | Context already consumed |
| ASH_PROOF_MISMATCH | Invalid proof |
