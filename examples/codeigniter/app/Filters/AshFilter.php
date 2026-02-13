<?php

declare(strict_types=1);

namespace App\Filters;

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\MemoryStore;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * ASH Filter for CodeIgniter 4
 *
 * Supports:
 * - Context scoping (selective field protection)
 * - IP binding with X-Forwarded-For support
 * - User binding
 * - Server-side scope policies
 *
 * Configuration (via .env):
 *    ASH_TRUST_PROXY=false
 *    ASH_TRUSTED_PROXIES=
 *    ASH_TIMESTAMP_TOLERANCE=30
 *
 * Register in app/Config/Filters.php:
 *
 *   public $aliases = [
 *       'ash' => \App\Filters\AshFilter::class,
 *   ];
 *
 *   public $filters = [
 *       // Basic usage
 *       'ash' => ['before' => ['api/update', 'api/profile']],
 *       
 *       // With IP binding
 *       'ash' => ['before' => ['api/secure/*' => ['enforce_ip']]],
 *       
 *       // With user binding  
 *       'ash' => ['before' => ['api/user/*' => ['enforce_user']]],
 *   ];
 */
final class AshFilter implements FilterInterface
{
    private Ash $ash;

    public function __construct()
    {
        // In production, inject via Services
        $store = new MemoryStore();
        $this->ash = new Ash($store, AshMode::Balanced);
    }

    /**
     * Handle incoming request.
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        // Parse arguments for binding enforcement
        $arguments = $arguments ?? [];
        $enforceIp = in_array('enforce_ip', $arguments, true);
        $enforceUser = in_array('enforce_user', $arguments, true);

        // Get headers
        $contextId = $request->getHeaderLine('X-ASH-Context-ID');
        $proof = $request->getHeaderLine('X-ASH-Proof');

        if (!$contextId) {
            return $this->errorResponse('ASH_CTX_NOT_FOUND', 'Missing X-ASH-Context-ID header', 450);
        }

        if (!$proof) {
            return $this->errorResponse('ASH_PROOF_MISSING', 'Missing X-ASH-Proof header', 483);
        }

        // Normalize binding
        $binding = $this->ash->ashNormalizeBinding(
            $request->getMethod(),
            (string)$request->getUri()->getPath()
        );

        // Get payload
        $body = $request->getBody();
        $payload = is_string($body) ? $body : (string)$body;
        $contentType = $request->getHeaderLine('Content-Type');

        // Get optional v2.3 headers
        $scope = $request->getHeaderLine('X-ASH-Scope');
        $scopeHash = $request->getHeaderLine('X-ASH-Scope-Hash');
        $chainHash = $request->getHeaderLine('X-ASH-Chain-Hash');

        // Build options
        $options = [];
        if (!empty($scope)) {
            $options['scope'] = array_map('trim', explode(',', $scope));
        }
        if (!empty($scopeHash)) {
            $options['scopeHash'] = $scopeHash;
        }
        if (!empty($chainHash)) {
            $options['chainHash'] = $chainHash;
        }

        // Verify
        $result = $this->ash->ashVerify(
            $contextId,
            $proof,
            $binding,
            $payload,
            $contentType,
            $options
        );

        if (!$result->valid) {
            $httpStatus = $result->errorCode?->httpStatus() ?? 460;
            return $this->errorResponse(
                $result->errorCode?->value ?? 'VERIFICATION_FAILED',
                $result->errorMessage ?? 'Verification failed',
                $httpStatus
            );
        }

        // Verify IP binding if requested
        if ($enforceIp) {
            $clientIp = Ash::getClientIp();
            $contextIp = $result->metadata['ip'] ?? null;
            if ($contextIp !== null && $contextIp !== $clientIp) {
                return $this->errorResponse('ASH_BINDING_MISMATCH', 'IP address mismatch', 461);
            }
        }

        // Verify user binding if requested
        if ($enforceUser) {
            // CodeIgniter auth - adjust based on your auth library
            $currentUserId = session()->get('user_id') ?? null;
            $contextUserId = $result->metadata['user_id'] ?? null;
            if ($contextUserId !== null && (int)$currentUserId !== (int)$contextUserId) {
                return $this->errorResponse('ASH_BINDING_MISMATCH', 'User mismatch', 461);
            }
        }

        // Store metadata for downstream use
        $request->setGlobal('get', array_merge(
            $request->getGet(),
            [
                '_ash_metadata' => $result->metadata,
                '_ash_client_ip' => Ash::getClientIp(),
            ]
        ));

        return $request;
    }

    /**
     * After filter - not used.
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        return $response;
    }

    /**
     * Create error response.
     */
    private function errorResponse(string $code, string $message, int $httpStatus = 403): ResponseInterface
    {
        return service('response')
            ->setStatusCode($httpStatus)
            ->setJSON([
                'error' => $code,
                'message' => $message,
            ]);
    }

    /**
     * Get ASH instance.
     */
    public function getAsh(): Ash
    {
        return $this->ash;
    }
}
