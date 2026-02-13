#!/usr/bin/env php
<?php
/**
 * Cross-SDK Test Vector Runner for PHP
 *
 * Runs the standard ASH test vectors against the PHP SDK to verify
 * interoperability with other language implementations.
 *
 * Usage:
 *   php run_tests.php
 *   php run_tests.php --verbose
 *   php run_tests.php --category canonicalization
 */

declare(strict_types=1);

// Add SDK to path
require_once __DIR__ . '/../../packages/ash-php-sdk/vendor/autoload.php';

use Ash\Core\Canonicalization;
use Ash\Core\Binding;
use Ash\Core\Crypto;

function loadTestVectors(): array
{
    $vectorsPath = __DIR__ . '/test-vectors.json';
    $content = file_get_contents($vectorsPath);
    if ($content === false) {
        throw new RuntimeException("Failed to read test vectors from {$vectorsPath}");
    }
    return json_decode($content, true, 512, JSON_THROW_ON_ERROR);
}

function runCanonicalizationTests(array $vectors, bool $verbose): array
{
    echo "\n=== JSON Canonicalization Tests ===\n";
    $passed = 0;
    $failed = 0;

    foreach ($vectors['canonicalization']['vectors'] as $test) {
        try {
            $result = Canonicalization::canonicalizeJson($test['input']);
            if ($result === $test['expected']) {
                $passed++;
                if ($verbose) {
                    echo "  ✓ {$test['id']}: {$test['description']}\n";
                }
            } else {
                $failed++;
                echo "  ✗ {$test['id']}: {$test['description']}\n";
                echo "    Expected: {$test['expected']}\n";
                echo "    Got:      {$result}\n";
            }
        } catch (Throwable $e) {
            $failed++;
            echo "  ✗ {$test['id']}: {$test['description']}\n";
            echo "    Error: {$e->getMessage()}\n";
        }
    }

    echo "\nCanonicalization: {$passed} passed, {$failed} failed\n";
    return ['passed' => $passed, 'failed' => $failed];
}

function runUrlencodedTests(array $vectors, bool $verbose): array
{
    echo "\n=== URL-Encoded Canonicalization Tests ===\n";
    $passed = 0;
    $failed = 0;

    foreach ($vectors['urlencoded_canonicalization']['vectors'] as $test) {
        try {
            $result = Canonicalization::canonicalizeUrlencoded($test['input']);
            if ($result === $test['expected']) {
                $passed++;
                if ($verbose) {
                    echo "  ✓ {$test['id']}: {$test['description']}\n";
                }
            } else {
                $failed++;
                echo "  ✗ {$test['id']}: {$test['description']}\n";
                echo "    Expected: {$test['expected']}\n";
                echo "    Got:      {$result}\n";
            }
        } catch (Throwable $e) {
            $failed++;
            echo "  ✗ {$test['id']}: {$test['description']}\n";
            echo "    Error: {$e->getMessage()}\n";
        }
    }

    echo "\nURL-Encoded: {$passed} passed, {$failed} failed\n";
    return ['passed' => $passed, 'failed' => $failed];
}

function runBindingTests(array $vectors, bool $verbose): array
{
    echo "\n=== Binding Normalization Tests ===\n";
    $passed = 0;
    $failed = 0;

    foreach ($vectors['binding_normalization']['vectors'] as $test) {
        try {
            $result = Binding::normalize($test['method'], $test['path'], $test['query']);
            if ($result === $test['expected']) {
                $passed++;
                if ($verbose) {
                    echo "  ✓ {$test['id']}: {$test['description']}\n";
                }
            } else {
                $failed++;
                echo "  ✗ {$test['id']}: {$test['description']}\n";
                echo "    Expected: {$test['expected']}\n";
                echo "    Got:      {$result}\n";
            }
        } catch (Throwable $e) {
            $failed++;
            echo "  ✗ {$test['id']}: {$test['description']}\n";
            echo "    Error: {$e->getMessage()}\n";
        }
    }

    echo "\nBinding: {$passed} passed, {$failed} failed\n";
    return ['passed' => $passed, 'failed' => $failed];
}

function runTimingSafeTests(array $vectors, bool $verbose): array
{
    echo "\n=== Timing-Safe Comparison Tests ===\n";
    $passed = 0;
    $failed = 0;

    foreach ($vectors['timing_safe_equal']['vectors'] as $test) {
        try {
            $result = Crypto::timingSafeEqual($test['a'], $test['b']);
            if ($result === $test['expected']) {
                $passed++;
                if ($verbose) {
                    echo "  ✓ {$test['id']}: a=\"{$test['a']}\", b=\"{$test['b']}\"\n";
                }
            } else {
                $failed++;
                echo "  ✗ {$test['id']}: a=\"{$test['a']}\", b=\"{$test['b']}\"\n";
                $expected = $test['expected'] ? 'true' : 'false';
                $got = $result ? 'true' : 'false';
                echo "    Expected: {$expected}\n";
                echo "    Got:      {$got}\n";
            }
        } catch (Throwable $e) {
            $failed++;
            echo "  ✗ {$test['id']}\n";
            echo "    Error: {$e->getMessage()}\n";
        }
    }

    echo "\nTiming-Safe: {$passed} passed, {$failed} failed\n";
    return ['passed' => $passed, 'failed' => $failed];
}

function main(): int
{
    $options = getopt('vc:', ['verbose', 'category:']);
    $verbose = isset($options['v']) || isset($options['verbose']);
    $category = $options['c'] ?? $options['category'] ?? null;

    echo str_repeat('=', 60) . "\n";
    echo "ASH Cross-SDK Test Vector Runner - PHP\n";
    echo str_repeat('=', 60) . "\n";

    try {
        $vectors = loadTestVectors();
    } catch (Throwable $e) {
        echo "ERROR: {$e->getMessage()}\n";
        return 1;
    }

    $totalPassed = 0;
    $totalFailed = 0;

    $categories = [
        'canonicalization' => 'runCanonicalizationTests',
        'urlencoded' => 'runUrlencodedTests',
        'binding' => 'runBindingTests',
        'timing' => 'runTimingSafeTests',
    ];

    if ($category !== null) {
        if (!isset($categories[$category])) {
            echo "Unknown category: {$category}\n";
            echo "Available: " . implode(', ', array_keys($categories)) . "\n";
            return 1;
        }
        $func = $categories[$category];
        $result = $func($vectors, $verbose);
        $totalPassed += $result['passed'];
        $totalFailed += $result['failed'];
    } else {
        foreach ($categories as $func) {
            $result = $func($vectors, $verbose);
            $totalPassed += $result['passed'];
            $totalFailed += $result['failed'];
        }
    }

    echo "\n" . str_repeat('=', 60) . "\n";
    echo "TOTAL: {$totalPassed} passed, {$totalFailed} failed\n";
    echo str_repeat('=', 60) . "\n";

    return $totalFailed > 0 ? 1 : 0;
}

exit(main());
