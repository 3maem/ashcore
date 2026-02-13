<?php
/**
 * ASH Integration Example: Laravel Controller
 *
 * Example controller for ASH context management.
 */

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Ash\Core\Ash;
use Ash\Core\Context;
use Ash\Core\Stores\RedisStore;

class AshController extends Controller
{
    private $store;

    public function __construct()
    {
        $this->store = new RedisStore(config('database.redis.default'));
    }

    /**
     * Issue a new ASH context.
     */
    public function issueContext(Request $request): JsonResponse
    {
        $endpoint = $request->input('endpoint', '/api/transfer');
        $ttlMs = $request->input('ttlMs', 30000);

        $binding = Ash::normalizeBinding('POST', $endpoint, '');

        $context = Context::create($this->store, [
            'binding' => $binding,
            'ttl_ms' => $ttlMs,
            'mode' => 'balanced',
            'issue_nonce' => true,
        ]);

        $clientSecret = Ash::deriveClientSecret(
            $context['nonce'],
            $context['context_id'],
            $binding
        );

        return response()->json([
            'contextId' => $context['context_id'],
            'clientSecret' => $clientSecret,
            'expiresAt' => $context['expires_at'],
        ]);
    }

    /**
     * Protected endpoint: Money transfer.
     */
    public function transfer(Request $request): JsonResponse
    {
        // If we reach here, ASH verification passed
        $fromAccount = $request->input('fromAccount');
        $toAccount = $request->input('toAccount');
        $amount = $request->input('amount');

        \Log::info("Transfer: {$amount} from {$fromAccount} to {$toAccount}");

        return response()->json([
            'success' => true,
            'message' => 'Transfer completed',
            'transactionId' => 'TXN_' . (int)(microtime(true) * 1000),
        ]);
    }

    /**
     * Protected endpoint: Payment.
     */
    public function payment(Request $request): JsonResponse
    {
        $merchantId = $request->input('merchantId');
        $amount = $request->input('amount');
        $currency = $request->input('currency', 'USD');

        \Log::info("Payment: {$amount} {$currency} to merchant {$merchantId}");

        return response()->json([
            'success' => true,
            'paymentId' => 'PAY_' . (int)(microtime(true) * 1000),
        ]);
    }
}
