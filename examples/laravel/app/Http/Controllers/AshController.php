<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Ash\Ash;
use Ash\AshMode;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;

/**
 * ASH Laravel Example Controller
 *
 * Demonstrates ASH integration with Laravel for request integrity protection.
 */
class AshController extends Controller
{
    private Ash $ash;

    public function __construct(Ash $ash)
    {
        $this->ash = $ash;
    }

    /**
     * Issue a context for protected endpoints.
     *
     * GET /api/context?binding=POST+/api/update
     */
    public function issueContext(Request $request): JsonResponse
    {
        $binding = $request->query('binding', 'POST /api/update');
        $mode = $request->query('mode', 'balanced');

        try {
            $context = $this->ash->ashIssueContext(
                binding: $binding,
                ttlMs: 30000, // 30 seconds
                mode: AshMode::from($mode),
                metadata: [
                    'userId' => $request->user()?->id ?? 'anonymous',
                    'issuedAt' => now()->toISOString(),
                ],
            );

            return response()->json([
                'contextId' => $context->id,
                'binding' => $context->binding,
                'expiresAt' => $context->expiresAt,
                'mode' => $context->mode->value,
                'nonce' => $context->nonce, // Only present in strict mode
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'CONTEXT_CREATION_FAILED',
                'message' => 'Failed to create context',
            ], 500);
        }
    }

    /**
     * Protected endpoint - requires valid ASH context and proof.
     * Apply 'ash' middleware to this route.
     *
     * POST /api/update
     */
    public function update(Request $request): JsonResponse
    {
        // Request is verified by middleware - safe to process
        $metadata = $request->attributes->get('ash_metadata', []);

        return response()->json([
            'success' => true,
            'message' => 'Update processed successfully',
            'data' => $request->all(),
            'metadata' => $metadata,
        ]);
    }

    /**
     * Protected profile update endpoint.
     *
     * PUT /api/profile
     */
    public function updateProfile(Request $request): JsonResponse
    {
        $request->validate([
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|email',
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Profile updated',
            'profile' => $request->only(['name', 'email']),
        ]);
    }

    /**
     * Unprotected public endpoint.
     *
     * GET /api/public
     */
    public function publicEndpoint(): JsonResponse
    {
        return response()->json([
            'message' => 'This endpoint is not protected by ASH',
            'timestamp' => now()->toISOString(),
        ]);
    }

    /**
     * Health check.
     *
     * GET /health
     */
    public function health(): JsonResponse
    {
        return response()->json([
            'status' => 'healthy',
            'ash' => [
                'version' => $this->ash->ashVersion(),
                'libraryVersion' => $this->ash->ashLibraryVersion(),
            ],
        ]);
    }
}
