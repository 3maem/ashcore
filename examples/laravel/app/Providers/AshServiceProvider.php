<?php

declare(strict_types=1);

namespace App\Providers;

use Ash\Ash;
use Ash\AshMode;
use Ash\Store\MemoryStore;
use Ash\Store\RedisStore;
use Ash\Store\ContextStoreInterface;
use Ash\Middleware\LaravelMiddleware;
use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Foundation\Application;

/**
 * ASH Service Provider for Laravel
 *
 * Register this in config/app.php providers array.
 */
class AshServiceProvider extends ServiceProvider
{
    /**
     * Register ASH services.
     */
    public function register(): void
    {
        // Register context store
        $this->app->singleton(ContextStoreInterface::class, function (Application $app) {
            // Use Redis in production, Memory in development
            if ($app->environment('production')) {
                $redis = $app->make('redis')->connection()->client();
                return new RedisStore($redis, config('ash.key_prefix', 'ash:ctx:'));
            }

            return new MemoryStore();
        });

        // Register main ASH instance
        $this->app->singleton(Ash::class, function (Application $app) {
            $store = $app->make(ContextStoreInterface::class);
            $defaultMode = AshMode::from(config('ash.default_mode', 'balanced'));

            return new Ash($store, $defaultMode);
        });

        // Register middleware
        $this->app->singleton(LaravelMiddleware::class, function (Application $app) {
            return new LaravelMiddleware($app->make(Ash::class));
        });
    }

    /**
     * Bootstrap ASH services.
     */
    public function boot(): void
    {
        // Register middleware alias
        $router = $this->app->make('router');
        $router->aliasMiddleware('ash', LaravelMiddleware::class);

        // Publish configuration
        $this->publishes([
            __DIR__ . '/../../config/ash.php' => config_path('ash.php'),
        ], 'ash-config');
    }
}
