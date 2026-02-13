<?php
/**
 * ASH Integration Example: Laravel Middleware
 *
 * This example demonstrates how to integrate ASH with Laravel
 * for request integrity verification and anti-replay protection.
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Ash\Ash;
use Ash\Store\RedisStore;
use Ash\Core\Proof;
use Ash\Core\Canonicalize;

class AshMiddleware
{
    private $store;

    public function __construct()
    {
        // Use Redis store (configured in config/database.php)
        $this->store = new RedisStore(config('database.redis.default'));
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Get ASH headers
        $contextId = $request->header('X-ASH-Context-ID');
        $timestamp = $request->header('X-ASH-Timestamp');
        $proof = $request->header('X-ASH-Proof');

        if (!$contextId || !$timestamp || !$proof) {
            return response()->json([
                'error' => 'Missing ASH headers',
                'code' => 'ASH_HEADERS_MISSING',
            ], 460);
        }

        // Get stored context
        $stored = $this->store->get($contextId);
        if (!$stored) {
            return response()->json([
                'error' => 'Context not found',
                'code' => 'ASH_CTX_NOT_FOUND',
            ], 460);
        }

        // Check expiration
        $nowMs = (int)(microtime(true) * 1000);
        if ($nowMs > $stored['expires_at']) {
            return response()->json([
                'error' => 'Context expired',
                'code' => 'ASH_CTX_EXPIRED',
            ], 460);
        }

        // Build binding
        $binding = Canonicalize::ashNormalizeBinding(
            $request->method(),
            '/' . ltrim($request->path(), '/'),
            $request->getQueryString() ?? ''
        );

        // Canonicalize and hash body
        $body = $request->getContent() ?: '';
        $canonical = Canonicalize::ashCanonicalizeJson($body);
        $bodyHash = Proof::ashHashBody($canonical);

        // Verify proof
        $isValid = Proof::ashVerifyProof(
            $stored['nonce'],
            $contextId,
            $binding,
            $timestamp,
            $bodyHash,
            $proof
        );

        if (!$isValid) {
            return response()->json([
                'error' => 'Invalid proof',
                'code' => 'ASH_PROOF_INVALID',
            ], 460);
        }

        // Consume context (prevent replay)
        $result = $this->store->consume($contextId, $nowMs);
        if ($result !== 'consumed') {
            return response()->json([
                'error' => 'Context already used',
                'code' => 'ASH_CTX_ALREADY_USED',
            ], 460);
        }

        return $next($request);
    }
}
