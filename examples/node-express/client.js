/**
 * ASH Protocol - Node.js Client Example
 *
 * This example demonstrates:
 * 1. Getting a context from the server
 * 2. Building an ASH proof for the request
 * 3. Sending a verified request
 *
 * Run: node client.js (with server running)
 */

import crypto from 'crypto';

const SERVER_URL = 'http://localhost:3000';
const ASH_VERSION = 'ASHv1';

// ============================================================================
// ASH Client Implementation
// ============================================================================

/**
 * Step 1: Canonicalize JSON payload (must match server implementation)
 */
function canonicalizeJson(obj) {
  if (obj === null || obj === undefined) {
    return 'null';
  }
  if (typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }
  // Sort keys alphabetically
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    return JSON.stringify(key) + ':' + canonicalizeJson(obj[key]);
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Step 2: Build ASH proof (must match server implementation)
 */
function buildProof(mode, binding, contextId, nonce, canonicalPayload) {
  let input = `${ASH_VERSION}\n${mode}\n${binding}\n${contextId}\n`;

  if (nonce) {
    input += `${nonce}\n`;
  }

  input += canonicalPayload;

  const hash = crypto.createHash('sha256').update(input).digest();
  return hash.toString('base64url');
}

// ============================================================================
// Example Usage
// ============================================================================

async function makeProtectedRequest() {
  console.log('=== ASH Protocol Client Example ===\n');

  // The data we want to send
  const requestData = {
    action: 'update',
    userId: 123,
    settings: {
      notifications: true,
      theme: 'dark',
    },
  };

  try {
    // ========================================================================
    // Step 1: Get a context from the server
    // ========================================================================
    console.log('Step 1: Requesting context from server...');

    const binding = 'POST /api/protected';
    const contextResponse = await fetch(
      `${SERVER_URL}/api/context?binding=${encodeURIComponent(binding)}`
    );

    if (!contextResponse.ok) {
      throw new Error(`Failed to get context: ${contextResponse.statusText}`);
    }

    const context = await contextResponse.json();
    console.log('  Context received:', {
      contextId: context.contextId,
      binding: context.binding,
      mode: context.mode,
      expiresAt: new Date(context.expiresAt).toISOString(),
    });

    // ========================================================================
    // Step 2: Canonicalize the payload
    // ========================================================================
    console.log('\nStep 2: Canonicalizing payload...');

    const canonicalPayload = canonicalizeJson(requestData);
    console.log('  Original:', JSON.stringify(requestData));
    console.log('  Canonical:', canonicalPayload);

    // ========================================================================
    // Step 3: Build the ASH proof
    // ========================================================================
    console.log('\nStep 3: Building ASH proof...');

    const proof = buildProof(
      context.mode,           // Security mode (balanced)
      context.binding,        // Endpoint binding (POST /api/protected)
      context.contextId,      // Server-issued context ID
      context.nonce || null,  // Server nonce (for strict mode)
      canonicalPayload        // Canonicalized request body
    );
    console.log('  Proof:', proof);

    // ========================================================================
    // Step 4: Send the protected request
    // ========================================================================
    console.log('\nStep 4: Sending protected request...');

    const response = await fetch(`${SERVER_URL}/api/protected`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ASH-Context': context.contextId,  // Include context ID
        'X-ASH-Proof': proof,                 // Include computed proof
      },
      body: JSON.stringify(requestData),
    });

    const result = await response.json();

    if (response.ok) {
      console.log('  Success! Response:', result);
    } else {
      console.log('  Failed! Error:', result);
    }

    // ========================================================================
    // Step 5: Demonstrate replay protection
    // ========================================================================
    console.log('\nStep 5: Attempting replay attack (same context)...');

    const replayResponse = await fetch(`${SERVER_URL}/api/protected`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ASH-Context': context.contextId,
        'X-ASH-Proof': proof,
      },
      body: JSON.stringify(requestData),
    });

    const replayResult = await replayResponse.json();
    console.log('  Replay attempt result:', replayResult);
    console.log('  (Expected: ASH_REPLAY_DETECTED)');

    // ========================================================================
    // Step 6: Demonstrate tamper protection
    // ========================================================================
    console.log('\nStep 6: Attempting tampered request...');

    // Get a new context for the tamper test
    const context2Response = await fetch(
      `${SERVER_URL}/api/context?binding=${encodeURIComponent(binding)}`
    );
    const context2 = await context2Response.json();

    // Build proof with original data
    const originalData = { amount: 100 };
    const originalProof = buildProof(
      context2.mode,
      context2.binding,
      context2.contextId,
      context2.nonce || null,
      canonicalizeJson(originalData)
    );

    // But send different data (tampered!)
    const tamperedData = { amount: 1000000 };

    const tamperResponse = await fetch(`${SERVER_URL}/api/protected`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ASH-Context': context2.contextId,
        'X-ASH-Proof': originalProof,  // Proof for original data
      },
      body: JSON.stringify(tamperedData),  // But sending tampered data!
    });

    const tamperResult = await tamperResponse.json();
    console.log('  Tamper attempt result:', tamperResult);
    console.log('  (Expected: ASH_INTEGRITY_FAILED)');

  } catch (error) {
    console.error('Error:', error.message);
    console.log('\nMake sure the server is running: node server.js');
  }
}

// Run the example
makeProtectedRequest();
