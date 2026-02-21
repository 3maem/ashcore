/**
 * ashcore Scoped Proof Example
 *
 * Demonstrates field-level protection: only `amount` and `currency` are
 * covered by the proof. Changing other fields (notes, preferences) does
 * not affect verification.
 */

import crypto from 'node:crypto';
import express from 'express';
import {
  AshMemoryStore,
  ashNormalizeBinding,
  ashDeriveClientSecret,
  ashBuildRequest,
  ashVerifyRequest,
} from '@3maem/ash-node-sdk';

const app = express();
const store = new AshMemoryStore();

app.use(express.json());

// ── Context endpoint ──────────────────────────────────────────────

app.get('/api/context', async (req, res) => {
  try {
    const binding = ashNormalizeBinding(
      String(req.query.method || 'POST'),
      String(req.query.path || '/api/orders'),
      '',
    );

    const nonce = crypto.randomBytes(32).toString('hex');
    const contextId = crypto.randomBytes(16).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

    await store.store({
      id: contextId,
      nonce,
      binding,
      clientSecret,
      used: false,
      createdAt: now,
      expiresAt: now + 300,
    });

    res.json({ contextId, nonce, binding });
  } catch (error) {
    console.error('Context creation error:', error);
    res.status(500).json({ error: 'Failed to create context' });
  }
});

// ── Protected endpoint (scoped) ───────────────────────────────────

app.post('/api/orders', async (req, res) => {
  try {
    const contextId = req.headers['x-ash-context-id'];
    const ctx = await store.consume(contextId);

    const result = ashVerifyRequest({
      headers: req.headers,
      method: 'POST',
      path: '/api/orders',
      body: JSON.stringify(req.body),
      nonce: ctx.nonce,
      contextId: ctx.id,
      scope: ['amount', 'currency'], // Only these fields are verified
    });

    if (!result.ok) {
      return res.status(460).json({
        error: result.error?.code,
        message: result.error?.message,
      });
    }

    console.log(`Verified (${result.meta.mode}): amount=${req.body.amount}, currency=${req.body.currency}`);

    res.json({
      orderId: crypto.randomUUID(),
      amount: req.body.amount,
      currency: req.body.currency,
      status: 'created',
    });
  } catch (error) {
    console.error('Order error:', error);
    res.status(error.statusCode || 500).json({
      error: error.code || 'INTERNAL_ERROR',
      message: error.message,
    });
  }
});

// ── Demo: client-side proof + request ─────────────────────────────

async function demo() {
  const base = 'http://localhost:3000';

  // 1. Get context
  const ctxRes = await fetch(`${base}/api/context?method=POST&path=/api/orders`);
  const { contextId, nonce } = await ctxRes.json();

  // 2. Build scoped proof
  const body = JSON.stringify({
    amount: 49.99,
    currency: 'SAR',
    notes: 'Gift wrap please',
    preferences: { color: 'blue' },
  });

  const result = ashBuildRequest({
    nonce,
    contextId,
    method: 'POST',
    path: '/api/orders',
    body,
    scope: ['amount', 'currency'],
  });

  // 3. Send protected request
  const orderRes = await fetch(`${base}/api/orders`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-ash-ts': result.timestamp,
      'x-ash-nonce': result.nonce,
      'x-ash-body-hash': result.bodyHash,
      'x-ash-proof': result.proof,
      'x-ash-context-id': result.contextId,
    },
    body,
  });

  const order = await orderRes.json();
  console.log('Order created:', order);

  result.destroy();
}

// Start server, then run demo
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ashcore Scoped Example running on http://localhost:${PORT}`);
  console.log('');
  console.log('Endpoints:');
  console.log('  GET  /api/context  - Issue a context');
  console.log('  POST /api/orders   - Protected endpoint (scoped: amount, currency)');
  console.log('');

  // Run demo after server starts
  if (!process.env.NO_DEMO) {
    demo().catch(console.error);
  }
});
