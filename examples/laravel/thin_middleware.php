<?php
// Laravel thin-wrapper middleware (ASH v1.0.0)

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Ash\Ash;
use Ash\Core\Proof;
use Ash\Core\Canonicalize;

class AshVerifyMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        // 1. Extract ASH headers
        $contextId = $request->header('X-ASH-Context-ID');
        $clientProof = $request->header('X-ASH-Proof');
        $timestamp = $request->header('X-ASH-Timestamp');

        if (!$contextId || !$clientProof || !$timestamp) {
            return response()->json([
                'code' => 'ASH_PROOF_INVALID',
                'message' => 'Missing required ASH headers (X-ASH-Context-ID, X-ASH-Proof, X-ASH-Timestamp)',
            ], 460);
        }

        // 2. Look up the stored context
        $stored = $this->lookupContext($contextId);
        if (!$stored || empty($stored['nonce'])) {
            return response()->json([
                'code' => 'ASH_PROOF_INVALID',
                'message' => 'Unknown or expired context',
            ], 460);
        }

        $nonce = $stored['nonce'];

        // 3. Normalize binding from the incoming request
        $binding = Canonicalize::ashNormalizeBinding(
            $request->method(),
            '/' . ltrim($request->path(), '/'),
            $request->getQueryString() ?? ''
        );

        // 4. Canonicalize and hash body
        $canonical = Canonicalize::ashCanonicalizeJson($request->getContent() ?: '');
        $bodyHash = Proof::ashHashBody($canonical);

        // 5. Derive client secret from context
        $clientSecret = Proof::ashDeriveClientSecret($nonce, $contextId, $binding);

        // 6. Verify the proof
        $valid = Proof::ashVerifyProof($nonce, $contextId, $binding, $timestamp, $bodyHash, $clientProof);

        if ($valid) {
            // NOTE: In production, replay protection (context consumption) should be
            // implemented here to prevent the same context from being reused.
            return $next($request);
        }

        return response()->json([
            'code' => 'ASH_PROOF_INVALID',
            'message' => 'Proof verification failed',
        ], 460);
    }

    /**
     * Look up a stored ASH context by ID.
     *
     * In production, this should retrieve the context from a persistent store
     * (e.g., Redis) and return an array with 'nonce' and 'binding' keys,
     * or null if the context is not found or expired.
     */
    private function lookupContext(string $contextId): ?array
    {
        // TODO: Replace with actual context store lookup
        return null;
    }
}
