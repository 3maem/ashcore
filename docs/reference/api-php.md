# ASH PHP SDK API Reference

**Version:** 1.0.0
**Package:** `3maem/ash-php-sdk`

## Installation

```bash
composer require 3maem/ash-php-sdk
```

## Requirements

- PHP 8.1 or later
- Extensions: `hash`, `intl`, `json`, `mbstring`

---

## Namespaces

```php
use Ash\Ash;
use Ash\AshMode;
use Ash\AshContext;
use Ash\AshVerifyResult;
use Ash\Core\AshErrorCode;
use Ash\Canonicalize\JsonCanonicalizer;
use Ash\Canonicalize\UrlencodedCanonicalizer;
use Ash\Proof\ProofBuilder;
use Ash\Binding\BindingNormalizer;
use Ash\Store\MemoryStore;
use Ash\Store\RedisStore;
```

---

## Enums

### AshMode

```php
enum AshMode: string
{
    case Minimal = 'minimal';    // Basic integrity checking
    case Balanced = 'balanced';  // Recommended for most applications
    case Strict = 'strict';      // Maximum security with nonce requirement
}
```

### AshErrorCode

```php
enum AshErrorCode: string
{
    case CtxNotFound = 'ASH_CTX_NOT_FOUND';
    case CtxExpired = 'ASH_CTX_EXPIRED';
    case CtxAlreadyUsed = 'ASH_CTX_ALREADY_USED';
    case BindingMismatch = 'ASH_BINDING_MISMATCH';
    case ProofMissing = 'ASH_PROOF_MISSING';
    case ProofInvalid = 'ASH_PROOF_INVALID';
    case CanonicalizationError = 'ASH_CANONICALIZATION_ERROR';
    case ModeViolation = 'ASH_MODE_VIOLATION';
    case UnsupportedContentType = 'ASH_UNSUPPORTED_CONTENT_TYPE';
    case ScopeMismatch = 'ASH_SCOPE_MISMATCH';
    case ChainBroken = 'ASH_CHAIN_BROKEN';

    public function httpStatus(): int;
    public function message(): string;
}
```

---

## Classes

### AshContext

```php
class AshContext
{
    public readonly string $id;
    public readonly string $binding;
    public readonly AshMode $mode;
    public readonly int $issuedAt;      // Unix timestamp (ms)
    public readonly int $expiresAt;     // Unix timestamp (ms)
    public readonly ?string $nonce;
    public readonly bool $used;
    public readonly ?array $metadata;

    public function isExpired(): bool;
    public function toPublicInfo(): array;
}
```

### AshVerifyResult

```php
class AshVerifyResult
{
    public readonly bool $valid;
    public readonly ?AshErrorCode $errorCode;
    public readonly ?string $errorMessage;
    public readonly ?array $metadata;

    public static function success(?array $metadata = null): self;
    public static function failure(AshErrorCode $code, string $message): self;
}
```

### AshException

```php
class AshException extends \Exception
{
    public function __construct(
        public readonly AshErrorCode $code,
        string $message
    );

    public function getHttpStatus(): int;
}
```

---

## Canonicalization

### JsonCanonicalizer

```php
class JsonCanonicalizer
{
    /**
     * Canonicalize JSON string to RFC 8785 form.
     *
     * @param string $json JSON string to canonicalize
     * @return string Canonical JSON
     * @throws AshException On invalid JSON
     */
    public static function canonicalize(string $json): string;

    /**
     * Canonicalize a PHP value to JSON.
     *
     * @param mixed $value PHP value (array, object, scalar)
     * @return string Canonical JSON
     */
    public static function canonicalizeValue(mixed $value): string;
}
```

**Example:**
```php
$canonical = JsonCanonicalizer::canonicalize('{"z":1,"a":2}');
// Result: {"a":2,"z":1}

$canonical = JsonCanonicalizer::canonicalizeValue(['z' => 1, 'a' => 2]);
// Result: {"a":2,"z":1}
```

### UrlencodedCanonicalizer

```php
class UrlencodedCanonicalizer
{
    /**
     * Canonicalize URL-encoded data by sorting parameters.
     *
     * @param string $data URL-encoded string
     * @return string Canonical form
     */
    public static function canonicalize(string $data): string;

    /**
     * Canonicalize from array.
     *
     * @param array<string, string|array> $params Parameters
     * @return string Canonical form
     */
    public static function canonicalizeArray(array $params): string;
}
```

**Example:**
```php
$canonical = UrlencodedCanonicalizer::canonicalize('z=1&a=2');
// Result: a=2&z=1
```

---

## Binding

### BindingNormalizer

```php
class BindingNormalizer
{
    /**
     * Normalize endpoint binding.
     *
     * Format: METHOD|PATH|QUERY
     *
     * @param string $method HTTP method
     * @param string $path URL path
     * @param string $query Query string (optional)
     * @return string Canonical binding
     */
    public static function normalize(string $method, string $path, string $query = ''): string;

    /**
     * Normalize from full URL.
     *
     * @param string $method HTTP method
     * @param string $url Full URL or path with query
     * @return string Canonical binding
     */
    public static function normalizeFromUrl(string $method, string $url): string;
}
```

**Example:**
```php
$binding = BindingNormalizer::normalize('post', '/api//users/', 'z=1&a=2');
// Result: POST|/api/users|a=2&z=1
```

---

## Proof Generation

### ProofBuilder

```php
class ProofBuilder
{
    /**
     * Build legacy v1 proof.
     */
    public static function build(
        AshMode $mode,
        string $binding,
        string $contextId,
        ?string $nonce,
        string $canonicalPayload
    ): string;

    /**
     * Build HMAC-SHA256 proof (v2.1).
     */
    public static function buildV21(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash
    ): string;

    /**
     * Build scoped proof (v2.2).
     */
    public static function buildV21Scoped(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash,
        string $scopeHash
    ): string;

    /**
     * Build unified proof (v2.3).
     */
    public static function buildV21Unified(
        string $clientSecret,
        string $timestamp,
        string $binding,
        string $bodyHash,
        string $scopeHash,
        string $chainHash
    ): string;
}
```

---

## Cryptographic Utilities

### Crypto

```php
class Crypto
{
    /**
     * Constant-time string comparison.
     */
    public static function timingSafeEqual(string $a, string $b): bool;

    /**
     * Generate cryptographic nonce.
     */
    public static function generateNonce(int $bytes = 32): string;

    /**
     * Generate context ID.
     */
    public static function generateContextId(): string;

    /**
     * Derive client secret from nonce (one-way).
     */
    public static function deriveClientSecret(
        string $nonce,
        string $contextId,
        string $binding
    ): string;

    /**
     * Hash request body.
     */
    public static function hashBody(string $body): string;

    /**
     * Hash proof for chaining.
     */
    public static function hashProof(string $proof): string;

    /**
     * Hash scoped fields.
     */
    public static function hashScopedBody(array $payload, array $scope): string;

    /**
     * Extract scoped fields from payload.
     */
    public static function extractScopedFields(array $payload, array $scope): array;

    /**
     * Base64URL encode.
     */
    public static function base64UrlEncode(string $data): string;

    /**
     * Base64URL decode.
     */
    public static function base64UrlDecode(string $data): string;
}
```

---

## Main Service Class

### Ash

```php
class Ash
{
    public function __construct(ContextStoreInterface $store, AshMode $defaultMode = AshMode::Balanced);

    /**
     * Issue a new context.
     */
    public function issueContext(
        string $binding,
        int $ttlMs = 30000,
        ?AshMode $mode = null,
        ?array $metadata = null
    ): AshContext;

    /**
     * Verify a request.
     */
    public function verify(
        string $contextId,
        string $proof,
        string $binding,
        string $payload,
        string $contentType
    ): AshVerifyResult;

    /**
     * Verify with scoping (v2.2+).
     */
    public function verifyScoped(
        string $contextId,
        string $proof,
        string $binding,
        string $payload,
        string $contentType,
        array $scope,
        string $scopeHash
    ): AshVerifyResult;

    /**
     * Verify unified (v2.3+).
     */
    public function verifyUnified(
        string $contextId,
        string $proof,
        string $binding,
        string $payload,
        string $contentType,
        array $scope,
        string $scopeHash,
        ?string $previousProof,
        string $chainHash
    ): AshVerifyResult;

    /**
     * Canonicalize payload based on content type.
     */
    public function canonicalize(string $payload, string $contentType): string;

    /**
     * Timing-safe comparison.
     */
    public static function timingSafeEqual(string $a, string $b): bool;
}
```

---

## Context Stores

### ContextStoreInterface

```php
interface ContextStoreInterface
{
    public function create(
        string $binding,
        int $ttlMs,
        AshMode $mode,
        ?array $metadata = null
    ): AshContext;

    public function get(string $id): ?AshContext;
    public function consume(string $id): bool;
    public function cleanup(): int;
}
```

### MemoryStore

```php
class MemoryStore implements ContextStoreInterface
{
    public function __construct();
}
```

### RedisStore

```php
class RedisStore implements ContextStoreInterface
{
    public function __construct(\Redis $redis, string $prefix = 'ash:ctx:');
}
```

---

## Middleware

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

## Complete Example

```php
<?php

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\RedisStore;
use Ash\Canonicalize\JsonCanonicalizer;
use Ash\Proof\ProofBuilder;
use Ash\Crypto;

// Setup
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$store = new RedisStore($redis);
$ash = new Ash($store);

// Server: Issue context
$context = $ash->issueContext(
    binding: 'POST|/api/transfer|',
    ttlMs: 30000,
    mode: AshMode::Balanced
);

// Client: Build proof
$payload = ['amount' => 100, 'to' => 'account123'];
$payloadJson = json_encode($payload);
$canonical = JsonCanonicalizer::canonicalize($payloadJson);
$clientSecret = Crypto::deriveClientSecret(
    $context->nonce,
    $context->id,
    'POST|/api/transfer|'
);
$bodyHash = Crypto::hashBody($canonical);
$timestamp = (string) (time() * 1000);

$proof = ProofBuilder::buildV21($clientSecret, $timestamp, 'POST|/api/transfer|', $bodyHash);

// Server: Verify
$result = $ash->verify(
    contextId: $context->id,
    proof: $proof,
    binding: 'POST|/api/transfer|',
    payload: $payloadJson,
    contentType: 'application/json'
);

if ($result->valid) {
    echo "Request verified successfully\n";
}
```

---

## License

ASH Source-Available License (ASAL-1.0)

See [LICENSE](../LICENSE) for full terms.
