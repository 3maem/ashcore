# ASH Laravel Integration Example

This example demonstrates how to integrate ASH with Laravel for request integrity verification.

## Quick Start

```bash
# Install ASH SDK
composer require 3maem/ash-php-sdk

# Copy middleware
cp AshMiddleware.php app/Http/Middleware/

# Copy controller
cp AshController.php app/Http/Controllers/

# Register middleware in app/Http/Kernel.php
```

## Setup

### 1. Register Middleware

```php
// app/Http/Kernel.php
protected $routeMiddleware = [
    // ...
    'ash' => \App\Http\Middleware\AshMiddleware::class,
];
```

### 2. Define Routes

```php
// routes/api.php
Route::post('/context', [AshController::class, 'issueContext']);

Route::middleware(['ash'])->group(function () {
    Route::post('/transfer', [AshController::class, 'transfer']);
    Route::post('/payment', [AshController::class, 'payment']);
});
```

### 3. Configure Redis

```php
// config/database.php
'redis' => [
    'default' => [
        'host' => env('REDIS_HOST', '127.0.0.1'),
        'password' => env('REDIS_PASSWORD', null),
        'port' => env('REDIS_PORT', 6379),
        'database' => 0,
    ],
],
```

## Client Usage (PHP)

```php
use Ash\Core\Ash;

// 1. Get context
$response = Http::post('http://localhost:8000/api/context', [
    'endpoint' => '/api/transfer',
    'ttlMs' => 30000,
]);
$context = $response->json();

// 2. Build proof
$payload = json_encode(['fromAccount' => 'ACC_001', 'toAccount' => 'ACC_002', 'amount' => 100]);
$binding = Ash::normalizeBinding('POST', '/api/transfer', '');
$bodyHash = Ash::hashBody($payload);
$timestamp = (string)(int)(microtime(true) * 1000);
$proof = Ash::buildProofV21($context['clientSecret'], $timestamp, $binding, $bodyHash);

// 3. Make request
$response = Http::withHeaders([
    'X-ASH-Context-ID' => $context['contextId'],
    'X-ASH-Timestamp' => $timestamp,
    'X-ASH-Proof' => $proof,
])->post('http://localhost:8000/api/transfer', json_decode($payload, true));
```

## Production Considerations

1. **Use Redis Store**: Already configured in example
2. **Queue Context Cleanup**: Schedule cleanup of expired contexts
3. **Enable HTTPS**: Configure in nginx/Apache
4. **Add Logging**: Use Laravel's logging for audit trails

## Error Codes

| Code | Description |
|------|-------------|
| ASH_HEADERS_MISSING | Required headers not present |
| ASH_CTX_NOT_FOUND | Context doesn't exist |
| ASH_CTX_EXPIRED | Context has expired |
| ASH_CTX_USED | Context already consumed |
| ASH_PROOF_MISMATCH | Invalid proof |
