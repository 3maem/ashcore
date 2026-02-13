<?php
/**
 * Plugin Name: ASH SDK
 * Plugin URI: https://github.com/3maem/ashcore
 * Description: Anti-tamper Security Hash protection for WordPress REST API
 * Version: 1.0.0
 * Author: 3maem Co. | شركة عمائم
 * Author URI: https://3maem.com
 * License: ASAL-1.0
 * Text Domain: ash-sdk
 */

declare(strict_types=1);

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Autoloader for ASH classes
require_once __DIR__ . '/vendor/autoload.php';

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\MemoryStore;
use Ash\Middleware\WordPressHandler;

/**
 * ASH WordPress Plugin
 */
final class AshSecurityPlugin
{
    private static ?self $instance = null;
    private Ash $ash;
    private WordPressHandler $handler;

    private function __construct()
    {
        // Initialize ASH with memory store
        // In production, use Redis or database store
        $store = new MemoryStore();
        $this->ash = new Ash($store, AshMode::Balanced);
        $this->handler = new WordPressHandler($this->ash);
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Initialize the plugin.
     */
    public function init(): void
    {
        // Register ASH handler
        $this->handler->register();

        // Protect API routes (customize as needed)
        $this->handler->protectRoutes(
            '#^/wp-json/ash/v1/protected#',
            '#^/wp-json/myapp/v1/(update|profile|transactions)#',
        );

        // Register REST API routes
        add_action('rest_api_init', [$this, 'registerRoutes']);

        // Admin menu
        add_action('admin_menu', [$this, 'addAdminMenu']);
    }

    /**
     * Register REST API routes.
     */
    public function registerRoutes(): void
    {
        // Context issuance endpoint
        register_rest_route('ash/v1', '/context', [
            'methods' => 'GET',
            'callback' => [$this, 'issueContext'],
            'permission_callback' => '__return_true',
            'args' => [
                'binding' => [
                    'required' => false,
                    'default' => 'POST /wp-json/ash/v1/protected',
                    'type' => 'string',
                ],
                'mode' => [
                    'required' => false,
                    'default' => 'balanced',
                    'enum' => ['minimal', 'balanced', 'strict'],
                ],
            ],
        ]);

        // Protected endpoint example
        register_rest_route('ash/v1', '/protected', [
            'methods' => 'POST',
            'callback' => [$this, 'protectedEndpoint'],
            'permission_callback' => '__return_true',
        ]);

        // Public endpoint for comparison
        register_rest_route('ash/v1', '/public', [
            'methods' => 'GET',
            'callback' => [$this, 'publicEndpoint'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * Issue a context for protected endpoints.
     */
    public function issueContext(\WP_REST_Request $request): \WP_REST_Response
    {
        $binding = $request->get_param('binding');
        $mode = AshMode::from($request->get_param('mode'));

        try {
            $context = $this->ash->ashIssueContext(
                binding: $binding,
                ttlMs: 30000, // 30 seconds
                mode: $mode,
                metadata: [
                    'userId' => get_current_user_id() ?: 'anonymous',
                    'issuedAt' => gmdate('c'),
                ],
            );

            return new \WP_REST_Response([
                'contextId' => $context->id,
                'binding' => $context->binding,
                'expiresAt' => $context->expiresAt,
                'mode' => $context->mode->value,
                'nonce' => $context->nonce,
            ], 200);
        } catch (\Exception $e) {
            return new \WP_REST_Response([
                'error' => 'CONTEXT_CREATION_FAILED',
                'message' => 'Failed to create context',
            ], 500);
        }
    }

    /**
     * Protected endpoint handler.
     */
    public function protectedEndpoint(\WP_REST_Request $request): \WP_REST_Response
    {
        // Request is verified by ASH handler
        $metadata = $request->get_param('_ash_metadata') ?? [];

        return new \WP_REST_Response([
            'success' => true,
            'message' => 'Protected endpoint accessed successfully',
            'data' => $request->get_json_params(),
            'metadata' => $metadata,
        ], 200);
    }

    /**
     * Public endpoint handler.
     */
    public function publicEndpoint(): \WP_REST_Response
    {
        return new \WP_REST_Response([
            'message' => 'This endpoint is not protected by ASH',
            'timestamp' => gmdate('c'),
        ], 200);
    }

    /**
     * Add admin menu page.
     */
    public function addAdminMenu(): void
    {
        add_options_page(
            'ASH Security',
            'ASH Security',
            'manage_options',
            'ash-sdk',
            [$this, 'renderAdminPage'],
        );
    }

    /**
     * Render admin settings page.
     */
    public function renderAdminPage(): void
    {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <div class="card">
                <h2>ASH Status</h2>
                <p><strong>Version:</strong> <?php echo esc_html($this->ash->ashVersion()); ?></p>
                <p><strong>Library Version:</strong> <?php echo esc_html($this->ash->ashLibraryVersion()); ?></p>
                <p><strong>Status:</strong> <span style="color: green;">Active</span></p>
            </div>

            <div class="card">
                <h2>Protected Routes</h2>
                <ul>
                    <li><code>/wp-json/ash/v1/protected</code></li>
                    <li><code>/wp-json/myapp/v1/update</code></li>
                    <li><code>/wp-json/myapp/v1/profile</code></li>
                    <li><code>/wp-json/myapp/v1/transactions/*</code></li>
                </ul>
            </div>

            <div class="card">
                <h2>Test Endpoints</h2>
                <p><a href="<?php echo esc_url(rest_url('ash/v1/context')); ?>" target="_blank">
                    Issue Context
                </a></p>
                <p><a href="<?php echo esc_url(rest_url('ash/v1/public')); ?>" target="_blank">
                    Public Endpoint
                </a></p>
            </div>
        </div>
        <?php
    }

    /**
     * Get the ASH instance.
     */
    public function getAsh(): Ash
    {
        return $this->ash;
    }
}

// Initialize plugin
add_action('plugins_loaded', function () {
    AshSecurityPlugin::getInstance()->init();
});
