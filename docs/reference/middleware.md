# ASH Middleware Reference

**Version:** 1.0.0

This document provides an overview of all available ASH middleware implementations across different frameworks and platforms.

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
| Flask | Python | `ash-python-sdk[flask]` |
| FastAPI | Python | `ash-python-sdk[fastapi]` |
| Django | Python | `ash-python-sdk[all]` |
| Gin | Go | `github.com/3maem/ash-go-sdk` |
| Laravel | PHP | `3maem/ash-php-sdk` |
| CodeIgniter | PHP | `3maem/ash-php-sdk` |
| WordPress | PHP | `3maem/ash-php-sdk` |
| Drupal | PHP | `3maem/ash-php-sdk` |

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

## Python Middleware

### Flask

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

### FastAPI

```python
from fastapi import FastAPI
from ash.stores import MemoryStore
from ash.middleware.fastapi import AshMiddleware

app = FastAPI()
store = MemoryStore()

app.add_middleware(AshMiddleware, store=store, protected_paths=["/api/*"])
```

### Django

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

See [Python API Reference](api-python.md) for full documentation.

---

## Go Middleware

### Gin

```go
import (
    ash "github.com/3maem/ash-go-sdk"
    "github.com/3maem/ash-go-sdk/middleware"
    "github.com/gin-gonic/gin"
)

func main() {
    store := ash.NewMemoryStore()

    r := gin.Default()

    api := r.Group("/api")
    api.Use(middleware.AshGin(store, middleware.AshGinOptions{
        GetBinding: func(c *gin.Context) string {
            binding, _ := ash.NormalizeBinding(
                c.Request.Method,
                c.Request.URL.Path,
                c.Request.URL.RawQuery,
            )
            return binding
        },
    }))

    api.POST("/transfer", handler)
    r.Run(":8080")
}
```

See [Go API Reference](api-go.md) for full documentation.

---

## PHP Middleware

### Laravel

```php
// Register in app/Http/Kernel.php
protected $routeMiddleware = [
    'ash' => \Ash\Middleware\LaravelMiddleware::class,
];

// Use in routes
Route::post('/api/update', function () {
    return response()->json(['status' => 'success']);
})->middleware('ash');
```

### CodeIgniter

```php
// Register in app/Config/Filters.php
public $aliases = [
    'ash' => \Ash\Middleware\CodeIgniterFilter::class,
];

// Use in routes
$routes->post('api/update', 'ApiController::update', ['filter' => 'ash']);
```

### WordPress

```php
use Ash\Middleware\WordPressHandler;

$handler = new WordPressHandler();

add_filter('rest_pre_dispatch', function ($result, $server, $request) use ($handler) {
    if (str_starts_with($request->get_route(), '/myapi/v1/')) {
        $verification = $handler->verify($request);
        if (!$verification->valid) {
            return new WP_Error('ash_failed', $verification->errorMessage, ['status' => 403]);
        }
    }
    return $result;
}, 10, 3);
```

### Drupal

```php
use Ash\Middleware\DrupalMiddleware;

$middleware = new DrupalMiddleware();
$result = $middleware->verify($request);
```

See [PHP API Reference](api-php.md) for full documentation.

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
