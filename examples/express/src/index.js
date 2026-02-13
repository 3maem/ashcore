/**
 * ASH Express.js Example
 *
 * Demonstrates ASH integration with Express.js for request integrity protection.
 */

import express from 'express';
import {
  ashInit,
  AshMemoryStore,
  ashExpressMiddleware,
  ashNormalizeBinding,
} from '@3maem/ash-node-sdk';

// Initialize ASH
ashInit();

const app = express();
const store = new AshMemoryStore();

// Parse JSON bodies
app.use(express.json());

/**
 * Issue a context for protected endpoints.
 *
 * In a real application, this would be called when rendering a form
 * or before making an API call.
 */
app.get('/api/context', async (req, res) => {
  const binding = req.query.binding || 'POST /api/update';

  try {
    const context = await store.create({
      binding: String(binding),
      ttlMs: 30000, // 30 seconds
      mode: 'balanced',
      metadata: {
        userId: req.headers['x-user-id'] || 'anonymous',
        issuedAt: new Date().toISOString(),
      },
    });

    res.json({
      contextId: context.id,
      binding: context.binding,
      expiresAt: context.expiresAt,
      mode: context.mode,
      nonce: context.nonce, // Only present in strict mode
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create context' });
  }
});

/**
 * Protected endpoint - requires valid ASH context and proof.
 */
app.post(
  '/api/update',
  ashExpressMiddleware({
    store,
    expectedBinding: 'POST /api/update',
  }),
  (req, res) => {
    // Request is verified - safe to process
    const { ashContext } = req;

    res.json({
      success: true,
      message: 'Update processed successfully',
      data: req.body,
      metadata: ashContext?.metadata,
    });
  }
);

/**
 * Protected endpoint for profile updates.
 */
app.put(
  '/api/profile',
  ashExpressMiddleware({
    store,
    expectedBinding: 'PUT /api/profile',
    mode: 'strict', // Require server nonce
  }),
  (req, res) => {
    res.json({
      success: true,
      message: 'Profile updated',
      profile: req.body,
    });
  }
);

/**
 * Unprotected endpoint for comparison.
 */
app.get('/api/public', (req, res) => {
  res.json({
    message: 'This endpoint is not protected by ASH',
    timestamp: new Date().toISOString(),
  });
});

/**
 * Health check endpoint.
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    ash: {
      storeSize: store.size(),
    },
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ASH Express example running on http://localhost:${PORT}`);
  console.log('');
  console.log('Endpoints:');
  console.log('  GET  /api/context  - Issue a context');
  console.log('  POST /api/update   - Protected endpoint');
  console.log('  PUT  /api/profile  - Protected endpoint (strict mode)');
  console.log('  GET  /api/public   - Unprotected endpoint');
  console.log('  GET  /health       - Health check');
});
