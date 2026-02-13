/**
 * ASH Protocol - Node.js Express Server Example
 *
 * This example demonstrates:
 * 1. Issuing a context for a protected endpoint
 * 2. Verifying requests with ASH proof
 *
 * Run: node server.js
 */

import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json());

// ============================================================================
// ASH Implementation (simplified for demonstration)
// In production, use the @3maem/ash-node-sdk package
// ============================================================================

const ASH_VERSION = 'ASHv1';

// In-memory context store (use Redis in production)
const contextStore = new Map();

/**
 * Step 1: Generate a unique context ID
 */
function generateContextId() {
  return 'ctx_' + crypto.randomBytes(16).toString('hex');
}

/**
 * Step 2: Generate server nonce for strict mode
 */
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Step 3: Canonicalize JSON payload
 * - Minified (no whitespace)
 * - Object keys sorted alphabetically
 * - Arrays preserve order
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
  // Sort keys and build canonical JSON
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    return JSON.stringify(key) + ':' + canonicalizeJson(obj[key]);
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Step 4: Build ASH proof
 *
 * Proof = SHA256(
 *   "ASHv1" + "\n" +
 *   mode + "\n" +
 *   binding + "\n" +
 *   contextId + "\n" +
 *   (nonce? + "\n" : "") +
 *   canonicalPayload
 * )
 *
 * Output: Base64URL encoded (no padding)
 */
function buildProof(mode, binding, contextId, nonce, canonicalPayload) {
  let input = `${ASH_VERSION}\n${mode}\n${binding}\n${contextId}\n`;

  // Add nonce if present (strict mode)
  if (nonce) {
    input += `${nonce}\n`;
  }

  input += canonicalPayload;

  // Hash with SHA-256
  const hash = crypto.createHash('sha256').update(input).digest();

  // Encode as Base64URL (no padding)
  return hash.toString('base64url');
}

/**
 * Step 5: Constant-time string comparison (prevents timing attacks)
 */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ============================================================================
// API Endpoints
// ============================================================================

/**
 * Context Issuance Endpoint
 *
 * Client calls this before making a protected request.
 * Returns a context ID that must be included with the protected request.
 */
app.get('/api/context', (req, res) => {
  // Step 1: Determine which endpoint this context is for
  const binding = req.query.binding || 'POST /api/protected';
  const mode = req.query.mode || 'balanced';

  // Step 2: Generate context ID
  const contextId = generateContextId();

  // Step 3: Calculate expiration (30 seconds)
  const ttlMs = 30000;
  const expiresAt = Date.now() + ttlMs;

  // Step 4: Generate nonce for strict mode
  const nonce = mode === 'strict' ? generateNonce() : null;

  // Step 5: Store context
  contextStore.set(contextId, {
    id: contextId,
    binding: binding,
    mode: mode,
    expiresAt: expiresAt,
    used: false,
    nonce: nonce,
  });

  // Step 6: Return context to client
  console.log(`[ASH] Issued context: ${contextId} for ${binding}`);

  res.json({
    contextId: contextId,
    binding: binding,
    mode: mode,
    expiresAt: expiresAt,
    // Only return nonce in strict mode
    ...(nonce && { nonce: nonce }),
  });
});

/**
 * Protected Endpoint
 *
 * Requires valid ASH context and proof.
 * Verifies request integrity before processing.
 */
app.post('/api/protected', (req, res) => {
  // Step 1: Extract ASH headers
  const contextId = req.headers['x-ash-context'];
  const clientProof = req.headers['x-ash-proof'];

  if (!contextId || !clientProof) {
    return res.status(401).json({
      error: 'ASH_MISSING_HEADERS',
      message: 'Missing X-ASH-Context or X-ASH-Proof headers',
    });
  }

  // Step 2: Retrieve context from store
  const context = contextStore.get(contextId);

  if (!context) {
    return res.status(401).json({
      error: 'ASH_INVALID_CONTEXT',
      message: 'Context not found or expired',
    });
  }

  // Step 3: Check if context expired
  if (Date.now() > context.expiresAt) {
    contextStore.delete(contextId);
    return res.status(401).json({
      error: 'ASH_CONTEXT_EXPIRED',
      message: 'Context has expired',
    });
  }

  // Step 4: Check for replay (already used)
  if (context.used) {
    return res.status(401).json({
      error: 'ASH_REPLAY_DETECTED',
      message: 'Context already used (replay attack detected)',
    });
  }

  // Step 5: Verify binding matches
  const actualBinding = `POST /api/protected`;
  if (context.binding !== actualBinding) {
    return res.status(401).json({
      error: 'ASH_ENDPOINT_MISMATCH',
      message: `Binding mismatch: expected ${context.binding}, got ${actualBinding}`,
    });
  }

  // Step 6: Canonicalize the request payload
  const canonicalPayload = canonicalizeJson(req.body);

  // Step 7: Build expected proof
  const expectedProof = buildProof(
    context.mode,
    context.binding,
    contextId,
    context.nonce,
    canonicalPayload
  );

  // Step 8: Verify proof using constant-time comparison
  if (!timingSafeEqual(expectedProof, clientProof)) {
    return res.status(401).json({
      error: 'ASH_INTEGRITY_FAILED',
      message: 'Proof verification failed - request may have been tampered',
    });
  }

  // Step 9: Mark context as used (prevents replay)
  context.used = true;

  console.log(`[ASH] Verified request with context: ${contextId}`);

  // Step 10: Process the verified request
  res.json({
    success: true,
    message: 'Request verified and processed',
    data: req.body,
  });
});

/**
 * Health check endpoint (unprotected)
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', contexts: contextStore.size });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ASH Express Example Server running on http://localhost:${PORT}`);
  console.log('');
  console.log('Endpoints:');
  console.log('  GET  /api/context    - Issue a new context');
  console.log('  POST /api/protected  - Protected endpoint (requires ASH)');
  console.log('  GET  /health         - Health check');
});
