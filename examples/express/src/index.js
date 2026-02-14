/**
 * ashcore Express.js Example
 *
 * Demonstrates ashcore integration with Express.js for request integrity protection.
 */

import crypto from 'node:crypto';
import express from 'express';
import {
  AshMemoryStore,
  ashExpressMiddleware,
  ashDeriveClientSecret,
  ashNormalizeBinding,
} from '@3maem/ash-node-sdk';

const app = express();
const store = new AshMemoryStore();

// Parse JSON bodies
app.use(express.json());

/**
 * Issue a context for protected endpoints.
 *
 * The server generates a nonce and contextId, derives the client secret,
 * stores the context, and returns { nonce, contextId, binding } to the client.
 */
app.get('/api/context', async (req, res) => {
  try {
    const binding = ashNormalizeBinding(
      String(req.query.method || 'POST'),
      String(req.query.path || '/api/update'),
      '',
    );

    // Generate nonce (128+ bits = 32+ hex chars)
    const nonce = crypto.randomBytes(32).toString('hex');
    const contextId = crypto.randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);

    // Derive client secret (server stores this for later verification)
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

    // Store context
    await store.store({
      id: contextId,
      nonce,
      binding,
      clientSecret,
      used: false,
      createdAt: now,
      expiresAt: now + 300, // 5 minutes
    });

    res.json({
      contextId,
      nonce,
      binding,
    });
  } catch (error) {
    console.error('Context creation error:', error);
    res.status(500).json({ error: 'Failed to create context' });
  }
});

/**
 * Protected endpoint — requires valid ashcore proof.
 *
 * The middleware handles:
 * 1. Extracting x-ash-context-id from headers
 * 2. Consuming the context from the store (single-use)
 * 3. Verifying the proof against the request
 */
app.post(
  '/api/update',
  ashExpressMiddleware({ store }),
  (req, res) => {
    // Request is verified — safe to process
    // req.ash contains verification metadata
    res.json({
      success: true,
      message: 'Update processed successfully',
      data: req.body,
      verification: req.ash,
    });
  },
);

/**
 * Unprotected endpoint for comparison.
 */
app.get('/api/public', (req, res) => {
  res.json({
    message: 'This endpoint is not protected by ashcore',
    timestamp: new Date().toISOString(),
  });
});

/**
 * Health check endpoint.
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    contexts: store.size,
  });
});

// Error handler
app.use((err, req, res, _next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ashcore Express example running on http://localhost:${PORT}`);
  console.log('');
  console.log('Endpoints:');
  console.log('  GET  /api/context  - Issue a context');
  console.log('  POST /api/update   - Protected endpoint');
  console.log('  GET  /api/public   - Unprotected endpoint');
  console.log('  GET  /health       - Health check');
});
