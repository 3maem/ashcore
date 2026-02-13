# ASH Python SDK API Reference

**Version:** 1.0.0
**Package:** `ash-python-sdk`

## Installation

```bash
# Basic installation
pip install ash-python-sdk

# With Flask support
pip install ash-python-sdk[flask]

# With FastAPI support
pip install ash-python-sdk[fastapi]

# With Redis support
pip install ash-python-sdk[redis]

# All features
pip install ash-python-sdk[all]
```

**Requirements:** Python 3.10 or later

---

## Constants

### Version Constants

```python
ASH_SDK_VERSION = "1.0.0"
ASH_VERSION_PREFIX = "ASHv2.1"
```

### Security Modes

```python
from ash.core import AshMode

class AshMode(Enum):
    MINIMAL = "minimal"    # Basic integrity checking
    BALANCED = "balanced"  # Recommended for most applications
    STRICT = "strict"      # Maximum security with nonce requirement
```

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

### ash_canonicalize_json

```python
def ash_canonicalize_json(input_json: str) -> str
```

Canonicalizes JSON to deterministic form per RFC 8785 (JCS).

```python
from ash.canonicalize import ash_canonicalize_json

canonical = ash_canonicalize_json('{"z":1,"a":2}')
# Result: '{"a":2,"z":1}'
```

### ash_canonicalize_urlencoded

```python
def ash_canonicalize_urlencoded(input_data: str) -> str
```

Canonicalizes URL-encoded data.

```python
from ash.canonicalize import ash_canonicalize_urlencoded

canonical = ash_canonicalize_urlencoded('z=1&a=2')
# Result: 'a=2&z=1'
```

---

## Proof Generation

### ash_build_proof

```python
def ash_build_proof(
    mode: AshMode,
    binding: str,
    context_id: str,
    nonce: Optional[str],
    canonical_payload: str
) -> str
```

Builds a cryptographic proof.

```python
from ash.proof import ash_build_proof
from ash.core import AshMode

proof = ash_build_proof(
    mode=AshMode.BALANCED,
    binding="POST /api/update",
    context_id="ctx_abc123",
    nonce=None,
    canonical_payload='{"name":"John"}'
)
```

### ash_build_proof_hmac

```python
def ash_build_proof_hmac(
    client_secret: str,
    body_hash: str,
    timestamp: str,
    binding: str
) -> str
```

Builds an HMAC-SHA256 proof (v2.1 format).

---

## Proof Verification

### ash_verify_proof

```python
def ash_verify_proof(expected: str, actual: str) -> bool
```

Verifies two proofs match using constant-time comparison.

### ash_timing_safe_equal

```python
def ash_timing_safe_equal(a: Union[str, bytes], b: Union[str, bytes]) -> bool
```

Performs constant-time comparison to prevent timing attacks.

```python
from ash.compare import ash_timing_safe_equal

is_equal = ash_timing_safe_equal("secret1", "secret2")
```

---

## Binding

### ash_normalize_binding

```python
def ash_normalize_binding(method: str, path: str) -> str
```

Normalizes a binding string to canonical form.

```python
from ash.binding import ash_normalize_binding

binding = ash_normalize_binding("post", "/api//test/")
# Result: 'POST /api/test'
```

---

## Context Stores

### MemoryStore

In-memory store for development and testing.

```python
from ash.stores import MemoryStore

store = MemoryStore()
```

### RedisStore

Production-ready store with atomic operations.

```python
import redis
from ash.stores import RedisStore

redis_client = redis.Redis(host='localhost', port=6379, db=0)
store = RedisStore(redis_client)
```

---

## Flask Middleware

```python
from flask import Flask
from ash.stores import MemoryStore
from ash.middleware.flask import ash_flask_middleware

app = Flask(__name__)
store = MemoryStore()

@app.route("/api/update", methods=["POST"])
@ash_flask_middleware(store, expected_binding="POST /api/update")
def update():
    return {"status": "success"}
```

---

## FastAPI Middleware

```python
from fastapi import FastAPI
from ash.stores import MemoryStore
from ash.middleware.fastapi import AshMiddleware

app = FastAPI()
store = MemoryStore()

app.add_middleware(AshMiddleware, store=store, protected_paths=["/api/*"])
```

---

## Django Middleware

```python
# settings.py
MIDDLEWARE = [
    'ash.middleware.django.AshMiddleware',
]

ASH_SETTINGS = {
    'STORE': 'ash.stores.RedisStore',
    'REDIS_URL': 'redis://localhost:6379/0',
    'PROTECTED_PATHS': ['/api/*'],
}
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
| `context_id` | Cannot be empty |
| `context_id` | Maximum 256 characters |
| `context_id` | Alphanumeric, underscore, hyphen, dot only |
| `binding` | Maximum 8192 bytes |

---

## Error Handling

```python
from ash.core.errors import (
    InvalidContextError,      # HTTP 450
    ContextExpiredError,      # HTTP 451
    ReplayDetectedError,      # HTTP 452
    IntegrityFailedError,     # HTTP 460
    BindingMismatchError,     # HTTP 461
    ScopeMismatchError,       # HTTP 473
    ChainBrokenError,         # HTTP 474
    TimestampInvalidError,    # HTTP 482
    ProofMissingError,        # HTTP 483
    CanonicalizationError,    # HTTP 422
    ValidationError,          # HTTP 400
)
```

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
