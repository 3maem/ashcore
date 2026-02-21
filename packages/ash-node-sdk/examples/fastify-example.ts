/**
 * ASH Node SDK — Fastify Integration Example
 *
 * Demonstrates the full client → server flow with Fastify:
 *   1. Server creates context (nonce + binding)
 *   2. Client builds proof using the context
 *   3. Client sends request with ASH headers
 *   4. Fastify plugin verifies the proof
 *
 * Prerequisites:
 *   npm install fastify @3maem/ash-node-sdk
 *
 * Run:
 *   npx tsx examples/fastify-example.ts
 */

import Fastify from 'fastify';
import crypto from 'node:crypto';
import {
  AshMemoryStore,
  ashBuildRequest,
  ashFastifyPlugin,
  ashDeriveClientSecret,
  ashNormalizeBinding,
  AshScopePolicyRegistry,
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '@3maem/ash-node-sdk';
import type { AshContext, AshRequestMeta } from '@3maem/ash-node-sdk';

// ── Setup ───────────────────────────────────────────────────────

const fastify = Fastify({ logger: false });

// Create store and scope registry
const store = new AshMemoryStore({ ttlSeconds: 300 });

// Scope policies: define which fields to include in scoped proofs per route
const scopeRegistry = new AshScopePolicyRegistry();
scopeRegistry.register({
  pattern: 'POST /api/orders',
  fields: ['amount', 'currency'],
  required: true,
});
scopeRegistry.register({
  pattern: 'GET /api/orders/:id',
  fields: [],
});

// Register ASH plugin for /api routes
fastify.register(async (instance) => {
  await instance.register(ashFastifyPlugin, {
    store,
    scopeRegistry,
    maxAgeSeconds: 300,
    clockSkewSeconds: 30,
  });

  // Protected: GET /api/orders/:id
  instance.get('/api/orders/:id', async (request, reply) => {
    const meta = (request as any).ash as AshRequestMeta;
    const { id } = request.params as { id: string };
    return {
      message: 'Order retrieved with verified request!',
      ash: { verified: meta.verified, mode: meta.mode },
      order: { id, amount: 99.99, currency: 'USD', status: 'completed' },
    };
  });

  // Protected: POST /api/orders (scoped proof — amount + currency)
  instance.post('/api/orders', async (request, reply) => {
    const meta = (request as any).ash as AshRequestMeta;
    return {
      message: 'Order created with scoped proof verification!',
      ash: { verified: meta.verified, mode: meta.mode },
      order: { id: 'ord-new', ...(request.body as object) },
    };
  });
});

// Public: POST /context (creates context for client)
fastify.post('/context', async (request, reply) => {
  const { method, path, scope } = request.body as {
    method: string;
    path: string;
    scope?: string[];
  };

  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = `ctx-${crypto.randomBytes(16).toString('hex')}`;
  const binding = ashNormalizeBinding(method, path, '');
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

  const now = Math.floor(Date.now() / 1000);
  const ctx: AshContext = {
    id: contextId,
    nonce,
    binding,
    clientSecret,
    used: false,
    createdAt: now,
    expiresAt: now + 300,
  };
  await store.store(ctx);

  return { contextId, nonce, expiresAt: ctx.expiresAt };
});

// ── Start Server ────────────────────────────────────────────────

const PORT = 3200;
fastify.listen({ port: PORT }, (err) => {
  if (err) throw err;
  console.log(`ASH Fastify example running on http://localhost:${PORT}`);
  console.log('');
  console.log('--- Simulating client flow ---');
  simulateClient().catch(console.error);
});

// ── Client Simulation ───────────────────────────────────────────

async function simulateClient() {
  const base = `http://localhost:${PORT}`;

  // === Example 1: Basic mode (GET /api/orders/42) ===
  console.log('=== Example 1: Basic proof (GET) ===');

  console.log('1. Requesting context for GET /api/orders/42...');
  const ctx1Res = await fetch(`${base}/context`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method: 'GET', path: '/api/orders/42' }),
  });
  const ctx1 = await ctx1Res.json() as { contextId: string; nonce: string };
  console.log(`   Context: ${ctx1.contextId.slice(0, 20)}...`);

  console.log('2. Building proof...');
  const build1 = ashBuildRequest({
    nonce: ctx1.nonce,
    contextId: ctx1.contextId,
    method: 'GET',
    path: '/api/orders/42',
    body: '',
  });

  console.log('3. Sending authenticated request...');
  const res1 = await fetch(`${base}/api/orders/42`, {
    headers: {
      [X_ASH_TIMESTAMP]: build1.timestamp,
      [X_ASH_NONCE]: build1.nonce,
      [X_ASH_BODY_HASH]: build1.bodyHash,
      [X_ASH_PROOF]: build1.proof,
      [X_ASH_CONTEXT_ID]: ctx1.contextId,
    },
  });
  console.log(`   Status: ${res1.status}`);
  console.log(`   Response:`, JSON.stringify(await res1.json(), null, 2));
  build1.destroy();

  // === Example 2: Scoped proof (POST /api/orders) ===
  console.log('\n=== Example 2: Scoped proof (POST with body) ===');

  const orderBody = JSON.stringify({ amount: 150.00, currency: 'EUR', description: 'Test order' });

  console.log('1. Requesting context for POST /api/orders...');
  const ctx2Res = await fetch(`${base}/context`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'POST',
      path: '/api/orders',
      scope: ['amount', 'currency'],
    }),
  });
  const ctx2 = await ctx2Res.json() as { contextId: string; nonce: string };
  console.log(`   Context: ${ctx2.contextId.slice(0, 20)}...`);

  console.log('2. Building scoped proof (fields: amount, currency)...');
  const build2 = ashBuildRequest({
    nonce: ctx2.nonce,
    contextId: ctx2.contextId,
    method: 'POST',
    path: '/api/orders',
    body: orderBody,
    scope: ['amount', 'currency'],
  });
  console.log(`   Mode: scoped (scopeHash: ${build2.scopeHash?.slice(0, 16)}...)`);

  console.log('3. Sending authenticated POST...');
  const res2 = await fetch(`${base}/api/orders`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      [X_ASH_TIMESTAMP]: build2.timestamp,
      [X_ASH_NONCE]: build2.nonce,
      [X_ASH_BODY_HASH]: build2.bodyHash,
      [X_ASH_PROOF]: build2.proof,
      [X_ASH_CONTEXT_ID]: ctx2.contextId,
    },
    body: orderBody,
  });
  console.log(`   Status: ${res2.status}`);
  console.log(`   Response:`, JSON.stringify(await res2.json(), null, 2));
  build2.destroy();

  // Clean up
  store.destroy();
  console.log('\nDone! Server shutting down.');
  process.exit(0);
}
