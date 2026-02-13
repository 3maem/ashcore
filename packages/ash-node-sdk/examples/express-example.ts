/**
 * ASH Node SDK — Express Integration Example
 *
 * Demonstrates the full client → server flow:
 *   1. Server creates context (nonce + binding)
 *   2. Client builds proof using the context
 *   3. Client sends request with ASH headers
 *   4. Express middleware verifies the proof
 *
 * Prerequisites:
 *   npm install express @3maem/ash-node-sdk
 *
 * Run:
 *   npx tsx examples/express-example.ts
 */

import express from 'express';
import crypto from 'node:crypto';
import {
  AshMemoryStore,
  ashBuildRequest,
  ashExpressMiddleware,
  ashDeriveClientSecret,
  ashNormalizeBinding,
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '@3maem/ash-node-sdk';
import type { AshContext } from '@3maem/ash-node-sdk';

// ── Setup ───────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// Create an in-memory context store (5-minute TTL, auto-cleanup every 60s)
const store = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 60 });

// Apply ASH middleware to all routes under /api
app.use('/api', ashExpressMiddleware({ store }));

// ── Step 1: Context endpoint (server creates context for client) ─

app.post('/context', async (req, res) => {
  const { method, path } = req.body as { method: string; path: string };

  // Generate a cryptographically random nonce (256 bits = 64 hex chars)
  const nonce = crypto.randomBytes(32).toString('hex');

  // Create a context ID
  const contextId = `ctx-${crypto.randomBytes(16).toString('hex')}`;

  // Normalize the binding for the target endpoint
  const binding = ashNormalizeBinding(method, path, '');

  // Derive the client secret (server keeps this for verification)
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);

  // Store the context
  const now = Math.floor(Date.now() / 1000);
  const ctx: AshContext = {
    id: contextId,
    nonce,
    binding,
    clientSecret,
    used: false,
    createdAt: now,
    expiresAt: now + 300, // 5 minutes
  };
  await store.store(ctx);

  // Return context to client (client needs nonce + contextId to build proof)
  res.json({
    contextId,
    nonce,
    expiresAt: ctx.expiresAt,
  });
});

// ── Step 4: Protected endpoint (middleware verifies before this runs) ─

app.get('/api/users', (req, res) => {
  // If we reach here, the ASH proof has been verified!
  const meta = (req as any).ash;
  res.json({
    message: 'Request verified successfully!',
    ash: {
      verified: meta.verified,
      mode: meta.mode,
      contextId: meta.contextId,
      binding: meta.binding,
    },
    users: [
      { id: 1, name: 'Alice' },
      { id: 2, name: 'Bob' },
    ],
  });
});

app.post('/api/users', (req, res) => {
  const meta = (req as any).ash;
  res.json({
    message: 'User created with verified request!',
    ash: { verified: meta.verified, mode: meta.mode },
    user: req.body,
  });
});

// ── Start Server ────────────────────────────────────────────────

const PORT = 3100;
app.listen(PORT, () => {
  console.log(`ASH Express example running on http://localhost:${PORT}`);
  console.log('');
  console.log('--- Simulating client flow ---');
  simulateClient().catch(console.error);
});

// ── Client Simulation (Steps 2 & 3) ────────────────────────────

async function simulateClient() {
  const base = `http://localhost:${PORT}`;

  // Step 2a: Get context from server
  console.log('1. Requesting context for GET /api/users...');
  const ctxRes = await fetch(`${base}/context`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method: 'GET', path: '/api/users' }),
  });
  const ctxData = await ctxRes.json() as { contextId: string; nonce: string };
  console.log(`   Context ID: ${ctxData.contextId}`);
  console.log(`   Nonce: ${ctxData.nonce.slice(0, 16)}...`);

  // Step 2b: Build proof
  console.log('2. Building proof...');
  const buildResult = ashBuildRequest({
    nonce: ctxData.nonce,
    contextId: ctxData.contextId,
    method: 'GET',
    path: '/api/users',
    body: '',
  });
  console.log(`   Proof: ${buildResult.proof.slice(0, 16)}...`);
  console.log(`   Body hash: ${buildResult.bodyHash.slice(0, 16)}...`);

  // Step 3: Send authenticated request
  console.log('3. Sending authenticated GET /api/users...');
  const apiRes = await fetch(`${base}/api/users`, {
    headers: {
      [X_ASH_TIMESTAMP]: buildResult.timestamp,
      [X_ASH_NONCE]: buildResult.nonce,
      [X_ASH_BODY_HASH]: buildResult.bodyHash,
      [X_ASH_PROOF]: buildResult.proof,
      [X_ASH_CONTEXT_ID]: ctxData.contextId,
    },
  });
  const apiData = await apiRes.json();
  console.log(`   Status: ${apiRes.status}`);
  console.log(`   Response:`, JSON.stringify(apiData, null, 2));

  // Step 4: Try replaying the same request (should fail — context consumed)
  console.log('4. Replaying same request (should fail)...');
  const replayRes = await fetch(`${base}/api/users`, {
    headers: {
      [X_ASH_TIMESTAMP]: buildResult.timestamp,
      [X_ASH_NONCE]: buildResult.nonce,
      [X_ASH_BODY_HASH]: buildResult.bodyHash,
      [X_ASH_PROOF]: buildResult.proof,
      [X_ASH_CONTEXT_ID]: ctxData.contextId,
    },
  });
  const replayData = await replayRes.json();
  console.log(`   Status: ${replayRes.status} (expected 452 — context already consumed)`);
  console.log(`   Error:`, JSON.stringify(replayData));

  // Clean up
  buildResult.destroy();
  store.destroy();
  console.log('\nDone! Server shutting down.');
  process.exit(0);
}
