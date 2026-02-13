<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Security Mode
    |--------------------------------------------------------------------------
    |
    | The default security mode for ASH contexts when not specified.
    | Options: 'minimal', 'balanced', 'strict'
    |
    */

    'default_mode' => env('ASH_DEFAULT_MODE', 'balanced'),

    /*
    |--------------------------------------------------------------------------
    | Redis Key Prefix
    |--------------------------------------------------------------------------
    |
    | The prefix used for ASH context keys in Redis.
    |
    */

    'key_prefix' => env('ASH_KEY_PREFIX', 'ash:ctx:'),

    /*
    |--------------------------------------------------------------------------
    | Default TTL
    |--------------------------------------------------------------------------
    |
    | Default time-to-live for contexts in milliseconds.
    |
    */

    'default_ttl_ms' => env('ASH_DEFAULT_TTL_MS', 30000),

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limiting for context creation per IP.
    |
    */

    'rate_limit_window' => env('ASH_RATE_LIMIT_WINDOW', 60),
    'rate_limit_max' => env('ASH_RATE_LIMIT_MAX', 10),

    /*
    |--------------------------------------------------------------------------
    | Timestamp Tolerance
    |--------------------------------------------------------------------------
    |
    | Acceptable time difference between client and server in seconds.
    | Prevents replay attacks with old timestamps while allowing clock skew.
    |
    */

    'timestamp_tolerance' => env('ASH_TIMESTAMP_TOLERANCE', 30),

    /*
    |--------------------------------------------------------------------------
    | Proxy Configuration
    |--------------------------------------------------------------------------
    |
    | Configure X-Forwarded-For handling for deployments behind proxies/CDNs.
    |
    | trust_proxy: Enable X-Forwarded-For handling
    | trusted_proxies: Comma-separated list of trusted proxy IPs (optional)
    |
    */

    'trust_proxy' => env('ASH_TRUST_PROXY', false),
    'trusted_proxies' => env('ASH_TRUSTED_PROXIES', ''),

    /*
    |--------------------------------------------------------------------------
    | Protected Routes
    |--------------------------------------------------------------------------
    |
    | Routes that should be automatically protected by ASH.
    | Use route patterns or explicit paths.
    |
    */

    'protected_routes' => [
        'api/update',
        'api/profile',
        'api/transactions/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Scope Policies (ENH-003)
    |--------------------------------------------------------------------------
    |
    | Server-side scope policies enforce which fields must be protected
    | for each endpoint. This provides additional security without requiring
    | client-side scope management.
    |
    | Register policies in AppServiceProvider:
    |
    |   ScopePolicies::register('POST|/api/transfer|', ['amount', 'recipient']);
    |
    */

    'scope_policies' => [],

];
