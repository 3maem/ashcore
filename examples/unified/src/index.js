/**
 * ashcore Unified Proof Example
 *
 * Demonstrates multi-step request chaining. Each step's proof includes
 * a hash of the previous step's proof, preventing step-skipping and replay.
 *
 * Flow:
 *   Step 1: Add items to cart (basic proof)
 *   Step 2: Set shipping address (chains to step 1)
 *   Step 3: Submit payment (chains to step 2, scoped on amount + currency)
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

// Track proof chain per session (in production, use Redis)
const proofChain = new Map();

app.use(express.json());

// ── Context endpoint ──────────────────────────────────────────────

app.get('/api/context', async (req, res) => {
  try {
    const binding = ashNormalizeBinding(
      String(req.query.method || 'POST'),
      String(req.query.path || '/api/cart'),
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

// ── Step 1: Add to cart (basic proof, no chain) ───────────────────

app.post('/api/cart', async (req, res) => {
  try {
    const contextId = req.headers['x-ash-context-id'];
    const ctx = await store.consume(contextId);

    const result = ashVerifyRequest({
      headers: req.headers,
      method: 'POST',
      path: '/api/cart',
      body: JSON.stringify(req.body),
      nonce: ctx.nonce,
      contextId: ctx.id,
    });

    if (!result.ok) {
      return res.status(460).json({ error: result.error?.code });
    }

    // Store proof for chain verification in next step
    const sessionId = req.headers['x-session-id'] || 'default';
    proofChain.set(sessionId, req.headers['x-ash-proof']);

    console.log(`Step 1 verified (${result.meta.mode}): ${req.body.items.length} items`);

    res.json({
      cartId: crypto.randomUUID(),
      items: req.body.items,
      step: 1,
    });
  } catch (error) {
    console.error('Cart error:', error);
    res.status(error.statusCode || 500).json({
      error: error.code || 'INTERNAL_ERROR',
      message: error.message,
    });
  }
});

// ── Step 2: Set shipping (chained to step 1) ─────────────────────

app.post('/api/shipping', async (req, res) => {
  try {
    const contextId = req.headers['x-ash-context-id'];
    const ctx = await store.consume(contextId);

    const sessionId = req.headers['x-session-id'] || 'default';
    const previousProof = proofChain.get(sessionId);

    const result = ashVerifyRequest({
      headers: req.headers,
      method: 'POST',
      path: '/api/shipping',
      body: JSON.stringify(req.body),
      nonce: ctx.nonce,
      contextId: ctx.id,
      previousProof,
    });

    if (!result.ok) {
      return res.status(460).json({ error: result.error?.code });
    }

    // Update chain with this step's proof
    proofChain.set(sessionId, req.headers['x-ash-proof']);

    console.log(`Step 2 verified (${result.meta.mode}): ${req.body.address}`);

    res.json({
      shipping: req.body.address,
      status: 'confirmed',
      step: 2,
    });
  } catch (error) {
    console.error('Shipping error:', error);
    res.status(error.statusCode || 500).json({
      error: error.code || 'INTERNAL_ERROR',
      message: error.message,
    });
  }
});

// ── Step 3: Payment (chained to step 2, scoped) ──────────────────

app.post('/api/payment', async (req, res) => {
  try {
    const contextId = req.headers['x-ash-context-id'];
    const ctx = await store.consume(contextId);

    const sessionId = req.headers['x-session-id'] || 'default';
    const previousProof = proofChain.get(sessionId);

    const result = ashVerifyRequest({
      headers: req.headers,
      method: 'POST',
      path: '/api/payment',
      body: JSON.stringify(req.body),
      nonce: ctx.nonce,
      contextId: ctx.id,
      scope: ['amount', 'currency'],
      previousProof,
    });

    if (!result.ok) {
      return res.status(460).json({ error: result.error?.code });
    }

    // Flow complete — clean up chain
    proofChain.delete(sessionId);

    console.log(`Step 3 verified (${result.meta.mode}): ${req.body.amount} ${req.body.currency}`);

    res.json({
      paymentId: crypto.randomUUID(),
      amount: req.body.amount,
      currency: req.body.currency,
      status: 'charged',
      step: 3,
    });
  } catch (error) {
    console.error('Payment error:', error);
    res.status(error.statusCode || 500).json({
      error: error.code || 'INTERNAL_ERROR',
      message: error.message,
    });
  }
});

// ── Demo: complete checkout flow ──────────────────────────────────

async function demo() {
  const base = 'http://localhost:3000';

  async function getContext(method, path) {
    const res = await fetch(`${base}/api/context?method=${method}&path=${encodeURIComponent(path)}`);
    return res.json();
  }

  // Step 1: Add to cart
  const ctx1 = await getContext('POST', '/api/cart');
  const cartBody = JSON.stringify({
    items: [
      { sku: 'SHIRT-001', qty: 2 },
      { sku: 'HAT-042', qty: 1 },
    ],
  });

  const step1 = ashBuildRequest({
    nonce: ctx1.nonce,
    contextId: ctx1.contextId,
    method: 'POST',
    path: '/api/cart',
    body: cartBody,
  });

  const cartRes = await fetch(`${base}/api/cart`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-ash-ts': step1.timestamp,
      'x-ash-nonce': step1.nonce,
      'x-ash-body-hash': step1.bodyHash,
      'x-ash-proof': step1.proof,
      'x-ash-context-id': step1.contextId,
    },
    body: cartBody,
  });
  console.log('Cart:', await cartRes.json());

  // Step 2: Set shipping — chains to step 1
  const ctx2 = await getContext('POST', '/api/shipping');
  const shippingBody = JSON.stringify({
    address: '123 King Abdulaziz St',
    city: 'Riyadh',
    zip: '11564',
  });

  const step2 = ashBuildRequest({
    nonce: ctx2.nonce,
    contextId: ctx2.contextId,
    method: 'POST',
    path: '/api/shipping',
    body: shippingBody,
    previousProof: step1.proof,
  });

  const shipRes = await fetch(`${base}/api/shipping`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-ash-ts': step2.timestamp,
      'x-ash-nonce': step2.nonce,
      'x-ash-body-hash': step2.bodyHash,
      'x-ash-proof': step2.proof,
      'x-ash-context-id': step2.contextId,
    },
    body: shippingBody,
  });
  console.log('Shipping:', await shipRes.json());

  // Step 3: Payment — chains to step 2, scoped on amount + currency
  const ctx3 = await getContext('POST', '/api/payment');
  const paymentBody = JSON.stringify({
    amount: 89.97,
    currency: 'SAR',
    cardLast4: '4242',
    saveCard: true,
  });

  const step3 = ashBuildRequest({
    nonce: ctx3.nonce,
    contextId: ctx3.contextId,
    method: 'POST',
    path: '/api/payment',
    body: paymentBody,
    scope: ['amount', 'currency'],
    previousProof: step2.proof,
  });

  const payRes = await fetch(`${base}/api/payment`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-ash-ts': step3.timestamp,
      'x-ash-nonce': step3.nonce,
      'x-ash-body-hash': step3.bodyHash,
      'x-ash-proof': step3.proof,
      'x-ash-context-id': step3.contextId,
    },
    body: paymentBody,
  });
  console.log('Payment:', await payRes.json());

  // Clean up
  step1.destroy();
  step2.destroy();
  step3.destroy();

  console.log('\nCheckout flow complete!');
}

// Start server, then run demo
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ashcore Unified Example running on http://localhost:${PORT}`);
  console.log('');
  console.log('Endpoints:');
  console.log('  GET  /api/context   - Issue a context');
  console.log('  POST /api/cart      - Step 1: Add items (basic)');
  console.log('  POST /api/shipping  - Step 2: Set shipping (chained)');
  console.log('  POST /api/payment   - Step 3: Payment (chained + scoped)');
  console.log('');

  if (!process.env.NO_DEMO) {
    demo().catch(console.error);
  }
});
