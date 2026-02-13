/**
 * ASH Integration Example: Express.js Client
 *
 * This example demonstrates how to make ASH-protected requests
 * from a client application.
 */

import {
  ashCanonicalizeJson,
  ashBuildProofHmac,
  ashHashBody,
  ashNormalizeBinding,
} from '@3maem/ash-node-sdk';

const API_BASE = process.env.API_BASE || 'http://localhost:3000';

/**
 * Make an ASH-protected API request
 */
async function makeProtectedRequest(endpoint, payload) {
  // Step 1: Request a context from the server
  const contextResponse = await fetch(`${API_BASE}/api/context`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ endpoint, ttlMs: 30000 }),
  });

  if (!contextResponse.ok) {
    throw new Error('Failed to get ASH context');
  }

  const context = await contextResponse.json();
  console.log('Got context:', context.contextId);

  // Step 2: Prepare the request
  const binding = ashNormalizeBinding('POST', endpoint, '');
  const canonicalPayload = ashCanonicalizeJson(payload);
  const bodyHash = ashHashBody(canonicalPayload);
  const timestamp = Date.now().toString();

  // Step 3: Build the proof
  // The server derives the clientSecret from the nonce and returns it
  const clientSecret = context.clientSecret;
  if (!clientSecret) {
    throw new Error('Server did not provide clientSecret in context response');
  }
  const proof = ashBuildProofHmac(clientSecret, timestamp, binding, bodyHash);

  // Step 4: Make the protected request
  const response = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-ASH-Context-ID': context.contextId,
      'X-ASH-Timestamp': timestamp,
      'X-ASH-Proof': proof,
    },
    body: JSON.stringify(payload),
  });

  return response.json();
}

// Example: Make a transfer
async function exampleTransfer() {
  try {
    const result = await makeProtectedRequest('/api/transfer', {
      fromAccount: 'ACC_001',
      toAccount: 'ACC_002',
      amount: 100.00,
      currency: 'USD',
    });

    console.log('Transfer result:', result);
  } catch (error) {
    console.error('Transfer failed:', error.message);
  }
}

// Example: Make a payment
async function examplePayment() {
  try {
    const result = await makeProtectedRequest('/api/payment', {
      merchantId: 'MERCHANT_123',
      amount: 49.99,
      currency: 'USD',
    });

    console.log('Payment result:', result);
  } catch (error) {
    console.error('Payment failed:', error.message);
  }
}

// Run examples
console.log('ASH Client Example');
console.log('==================');
exampleTransfer();
