<?php

declare(strict_types=1);

namespace App\Controllers;

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\MemoryStore;
use CodeIgniter\RESTful\ResourceController;

/**
 * ASH CodeIgniter 4 Example Controller
 */
class AshController extends ResourceController
{
    protected $format = 'json';
    private Ash $ash;

    public function __construct()
    {
        // NOTE: MemoryStore is for demo/testing only. In production, use RedisStore
        // or another persistent store that supports atomic consume operations.
        $store = new MemoryStore();
        $this->ash = new Ash($store);
    }

    /**
     * Issue a context.
     *
     * GET /api/context
     */
    public function context()
    {
        $binding = $this->request->getGet('binding') ?? 'POST /api/update';
        $mode = $this->request->getGet('mode') ?? 'balanced';

        try {
            $context = $this->ash->createContext(
                binding: $binding,
                ttlMs: 30000,
                mode: AshMode::from($mode),
                metadata: [
                    'issuedAt' => date('c'),
                ],
            );

            // SECURITY: Never expose the nonce in the API response.
            // The nonce must stay server-side only. Send the derived
            // clientSecret to the client instead.
            return $this->respond([
                'contextId' => $context->id,
                'binding' => $context->binding,
                'expiresAt' => $context->expiresAt,
                'mode' => $context->mode->value,
            ]);
        } catch (\Exception $e) {
            return $this->fail('Failed to create context', 500);
        }
    }

    /**
     * Protected update endpoint.
     *
     * POST /api/update (requires 'ash' filter)
     */
    public function update()
    {
        $metadata = $this->request->getGet('_ash_metadata') ?? [];

        return $this->respond([
            'success' => true,
            'message' => 'Update processed',
            'data' => $this->request->getJSON(true),
            'metadata' => $metadata,
        ]);
    }

    /**
     * Public endpoint.
     *
     * GET /api/public
     */
    public function publicEndpoint()
    {
        return $this->respond([
            'message' => 'This endpoint is not protected by ASH',
            'timestamp' => date('c'),
        ]);
    }

    /**
     * Health check.
     *
     * GET /api/health
     */
    public function health()
    {
        return $this->respond([
            'status' => 'healthy',
            'ash' => [
                'version' => Ash::VERSION,
            ],
        ]);
    }
}
