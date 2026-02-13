#!/usr/bin/env node
/**
 * Cross-SDK Test Vector Runner for Node.js
 *
 * Runs the standard ASH test vectors against the Node.js SDK to verify
 * interoperability with other language implementations.
 *
 * Usage:
 *   node run_tests.js
 *   node run_tests.js --verbose
 *   node run_tests.js --category canonicalization
 */

const fs = require('fs');
const path = require('path');

// Try to load the SDK
let ash;
try {
  ash = require('../../packages/ash-node-sdk/dist/index.js');
} catch (e) {
  console.log('Warning: Could not load compiled SDK, trying source...');
  try {
    // This would require ts-node or pre-compilation
    console.log('SDK not available. Build first: cd packages/ash-node-sdk && npm run build');
    process.exit(1);
  } catch (e2) {
    console.error('ERROR: ASH Node.js SDK not available');
    console.error('Build with: cd packages/ash-node-sdk && npm run build');
    process.exit(1);
  }
}

function loadTestVectors() {
  const vectorsPath = path.join(__dirname, 'test-vectors.json');
  return JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));
}

function runCanonicalizationTests(vectors, verbose) {
  console.log('\n=== JSON Canonicalization Tests ===');
  let passed = 0;
  let failed = 0;

  for (const test of vectors.canonicalization.vectors) {
    try {
      const result = ash.ashCanonicalizeJson(test.input);
      if (result === test.expected) {
        passed++;
        if (verbose) {
          console.log(`  [PASS] ${test.id}: ${test.description}`);
        }
      } else {
        failed++;
        console.log(`  [FAIL] ${test.id}: ${test.description}`);
        console.log(`    Expected: ${test.expected}`);
        console.log(`    Got:      ${result}`);
      }
    } catch (e) {
      failed++;
      console.log(`  [FAIL] ${test.id}: ${test.description}`);
      console.log(`    Error: ${e.message}`);
    }
  }

  console.log(`\nCanonicalization: ${passed} passed, ${failed} failed`);
  return { passed, failed };
}

function runUrlencodedTests(vectors, verbose) {
  console.log('\n=== URL-Encoded Canonicalization Tests ===');
  let passed = 0;
  let failed = 0;

  for (const test of vectors.urlencoded_canonicalization.vectors) {
    try {
      const result = ash.ashCanonicalizeUrlencoded(test.input);
      if (result === test.expected) {
        passed++;
        if (verbose) {
          console.log(`  [PASS] ${test.id}: ${test.description}`);
        }
      } else {
        failed++;
        console.log(`  [FAIL] ${test.id}: ${test.description}`);
        console.log(`    Expected: ${test.expected}`);
        console.log(`    Got:      ${result}`);
      }
    } catch (e) {
      failed++;
      console.log(`  [FAIL] ${test.id}: ${test.description}`);
      console.log(`    Error: ${e.message}`);
    }
  }

  console.log(`\nURL-Encoded: ${passed} passed, ${failed} failed`);
  return { passed, failed };
}

function runBindingTests(vectors, verbose) {
  console.log('\n=== Binding Normalization Tests ===');
  let passed = 0;
  let failed = 0;

  for (const test of vectors.binding_normalization.vectors) {
    try {
      const result = ash.ashNormalizeBinding(test.method, test.path, test.query);
      if (result === test.expected) {
        passed++;
        if (verbose) {
          console.log(`  [PASS] ${test.id}: ${test.description}`);
        }
      } else {
        failed++;
        console.log(`  [FAIL] ${test.id}: ${test.description}`);
        console.log(`    Expected: ${test.expected}`);
        console.log(`    Got:      ${result}`);
      }
    } catch (e) {
      failed++;
      console.log(`  [FAIL] ${test.id}: ${test.description}`);
      console.log(`    Error: ${e.message}`);
    }
  }

  console.log(`\nBinding: ${passed} passed, ${failed} failed`);
  return { passed, failed };
}

function runTimingSafeTests(vectors, verbose) {
  console.log('\n=== Timing-Safe Comparison Tests ===');
  let passed = 0;
  let failed = 0;

  for (const test of vectors.timing_safe_equal.vectors) {
    try {
      const result = ash.ashTimingSafeEqual(test.a, test.b);
      if (result === test.expected) {
        passed++;
        if (verbose) {
          console.log(`  [PASS] ${test.id}: a="${test.a}", b="${test.b}"`);
        }
      } else {
        failed++;
        console.log(`  [FAIL] ${test.id}: a="${test.a}", b="${test.b}"`);
        console.log(`    Expected: ${test.expected}`);
        console.log(`    Got:      ${result}`);
      }
    } catch (e) {
      failed++;
      console.log(`  [FAIL] ${test.id}`);
      console.log(`    Error: ${e.message}`);
    }
  }

  console.log(`\nTiming-Safe: ${passed} passed, ${failed} failed`);
  return { passed, failed };
}

function main() {
  const args = process.argv.slice(2);
  const verbose = args.includes('--verbose') || args.includes('-v');
  const categoryIndex = args.findIndex(a => a === '--category' || a === '-c');
  const category = categoryIndex >= 0 ? args[categoryIndex + 1] : null;

  console.log('='.repeat(60));
  console.log('ASH Cross-SDK Test Vector Runner - Node.js');
  console.log('='.repeat(60));

  const vectors = loadTestVectors();
  let totalPassed = 0;
  let totalFailed = 0;

  const categories = {
    canonicalization: runCanonicalizationTests,
    urlencoded: runUrlencodedTests,
    binding: runBindingTests,
    timing: runTimingSafeTests,
  };

  if (category) {
    if (categories[category]) {
      const { passed, failed } = categories[category](vectors, verbose);
      totalPassed += passed;
      totalFailed += failed;
    } else {
      console.log(`Unknown category: ${category}`);
      console.log(`Available: ${Object.keys(categories).join(', ')}`);
      process.exit(1);
    }
  } else {
    for (const [name, func] of Object.entries(categories)) {
      const { passed, failed } = func(vectors, verbose);
      totalPassed += passed;
      totalFailed += failed;
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`TOTAL: ${totalPassed} passed, ${totalFailed} failed`);
  console.log('='.repeat(60));

  process.exit(totalFailed === 0 ? 0 : 1);
}

main();
