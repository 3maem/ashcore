/**
 * ASH Node SDK — Phase 2: Fastify Plugin Tests
 *
 * Coverage: PT (bypass, missing headers, tampered) / AQ (plugin registration,
 * decoration, hook ordering) / SA (error format, no secret leak) / FUZZ (random req)
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ashFastifyPlugin } from '../../../src/middleware/fastify.js';
import type { FastifyRequest, FastifyReply, FastifyInstance } from '../../../src/middleware/fastify.js';
import { AshMemoryStore } from '../../../src/context.js';
import { ashBuildRequest } from '../../../src/build-request.js';
import {
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '../../../src/headers.js';
import { AshError } from '../../../src/errors.js';
import { ashDeriveClientSecret } from '../../../src/proof.js';
import { ashNormalizeBinding } from '../../../src/binding.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX_ID = 'ctx_fastify_test';
const METHOD = 'POST';
const PATH = '/api/users';
const BODY = '{"name":"Alice"}';

let store: AshMemoryStore;
let registeredHook: ((req: FastifyRequest, reply: FastifyReply) => Promise<void>) | null;

function mockFastify(): FastifyInstance {
  registeredHook = null;
  return {
    decorateRequest: vi.fn(),
    addHook: vi.fn((_name: string, handler: (req: FastifyRequest, reply: FastifyReply) => Promise<void>) => {
      registeredHook = handler;
    }),
  };
}

function mockReply(): FastifyReply & { _code: number; _body: unknown } {
  const reply: FastifyReply & { _code: number; _body: unknown } = {
    _code: 0,
    _body: null,
    code(statusCode: number) {
      reply._code = statusCode;
      return reply;
    },
    send(payload: unknown) {
      reply._body = payload;
    },
  };
  return reply;
}

beforeEach(() => {
  store = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
});

afterEach(() => {
  store.destroy();
});

async function setupContext(): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const binding = ashNormalizeBinding(METHOD, PATH, '');
  const clientSecret = ashDeriveClientSecret(NONCE, CTX_ID, binding);
  await store.store({
    id: CTX_ID,
    nonce: NONCE,
    binding,
    clientSecret,
    used: false,
    createdAt: now,
    expiresAt: now + 300,
  });
}

function buildValidRequest(): { request: FastifyRequest; buildResult: ReturnType<typeof ashBuildRequest> } {
  const ts = String(Math.floor(Date.now() / 1000));

  const buildResult = ashBuildRequest({
    nonce: NONCE,
    contextId: CTX_ID,
    method: METHOD,
    path: PATH,
    body: BODY,
    timestamp: ts,
  });

  const request: FastifyRequest = {
    headers: {
      [X_ASH_TIMESTAMP]: ts,
      [X_ASH_NONCE]: NONCE,
      [X_ASH_BODY_HASH]: buildResult.bodyHash,
      [X_ASH_PROOF]: buildResult.proof,
      [X_ASH_CONTEXT_ID]: CTX_ID,
    },
    method: METHOD,
    url: PATH,
    body: JSON.parse(BODY),
  };

  return { request, buildResult };
}

// ── AQ: Plugin Registration ────────────────────────────────────────

describe('AQ: Fastify plugin — registration', () => {
  it('AQ-FP-001: decorateRequest is called with "ash"', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });
    expect(fastify.decorateRequest).toHaveBeenCalledWith('ash', null);
  });

  it('AQ-FP-002: addHook is called with "onRequest"', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });
    expect(fastify.addHook).toHaveBeenCalledWith('onRequest', expect.any(Function));
  });

  it('AQ-FP-003: hook handler is registered', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });
    expect(registeredHook).not.toBeNull();
  });
});

// ── AQ: Successful Verification ────────────────────────────────────

describe('AQ: Fastify plugin — success', () => {
  it('AQ-FP-OK-001: valid request decorates with ash meta', async () => {
    await setupContext();
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(request.ash).toBeDefined();
    expect(request.ash!.verified).toBe(true);
    expect(request.ash!.contextId).toBe(CTX_ID);
    expect(request.ash!.mode).toBe('basic');
  });

  it('AQ-FP-OK-002: meta has timestamp and binding', async () => {
    await setupContext();
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(request.ash!.timestamp).toBeGreaterThan(0);
    expect(request.ash!.binding).toContain('POST|');
  });
});

// ── PT: Missing Headers ────────────────────────────────────────────

describe('PT: Fastify plugin — missing headers', () => {
  it('PT-FP-001: missing context ID returns PROOF_MISSING', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    delete (request.headers as Record<string, string>)[X_ASH_CONTEXT_ID];
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(reply._code).toBe(483);
  });

  it('PT-FP-002: unknown context ID returns CTX_NOT_FOUND', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(reply._code).toBe(450);
  });

  it('PT-FP-003: double consume returns CTX_ALREADY_USED', async () => {
    await setupContext();
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    // First request
    const { request: req1 } = buildValidRequest();
    const reply1 = mockReply();
    await registeredHook!(req1, reply1);
    expect(req1.ash).toBeDefined();

    // Second request with same context
    const { request: req2 } = buildValidRequest();
    const reply2 = mockReply();
    await registeredHook!(req2, reply2);
    expect(reply2._code).toBe(452);
  });
});

// ── PT: Tampered Request ───────────────────────────────────────────

describe('PT: Fastify plugin — tampered', () => {
  it('PT-FP-TAMP-001: forged proof is rejected', async () => {
    await setupContext();
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    request.headers[X_ASH_PROOF] = 'f'.repeat(64);
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(reply._code).toBe(460);
  });

  it('PT-FP-TAMP-002: tampered body is rejected', async () => {
    await setupContext();
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    request.body = { name: 'Bob' };
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(reply._code).toBe(460);
    expect(request.ash).toBeUndefined();
  });
});

// ── AQ: Custom Error Handler ───────────────────────────────────────

describe('AQ: Fastify plugin — custom error handler', () => {
  it('AQ-FP-ERR-001: onError is called on failure', async () => {
    const fastify = mockFastify();
    const onError = vi.fn();
    await ashFastifyPlugin(fastify, { store, onError });

    const { request } = buildValidRequest();
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0]).toBeInstanceOf(AshError);
  });
});

// ── SA: Error Format ───────────────────────────────────────────────

describe('SA: Fastify plugin — error format', () => {
  it('SA-FP-001: error response is JSON with error/message/status', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(reply._body).toHaveProperty('error');
    expect(reply._body).toHaveProperty('message');
    expect(reply._body).toHaveProperty('status');
  });

  it('SA-FP-002: no secrets in error response', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const { request } = buildValidRequest();
    const reply = mockReply();
    await registeredHook!(request, reply);

    const body = reply._body as Record<string, unknown>;
    expect(String(body.message)).not.toContain(NONCE);
  });
});

// ── AQ: URL parsing ────────────────────────────────────────────────

describe('AQ: Fastify plugin — URL parsing', () => {
  it('AQ-FP-URL-001: query string extracted from URL', async () => {
    const now = Math.floor(Date.now() / 1000);
    const binding = ashNormalizeBinding('GET', '/api/users', 'page=1');
    const clientSecret = ashDeriveClientSecret(NONCE, CTX_ID, binding);
    await store.store({
      id: CTX_ID,
      nonce: NONCE,
      binding,
      clientSecret,
      used: false,
      createdAt: now,
      expiresAt: now + 300,
    });

    const ts = String(now);
    const buildResult = ashBuildRequest({
      nonce: NONCE,
      contextId: CTX_ID,
      method: 'GET',
      path: '/api/users',
      rawQuery: 'page=1',
      body: '',
      timestamp: ts,
    });

    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const request: FastifyRequest = {
      headers: {
        [X_ASH_TIMESTAMP]: ts,
        [X_ASH_NONCE]: NONCE,
        [X_ASH_BODY_HASH]: buildResult.bodyHash,
        [X_ASH_PROOF]: buildResult.proof,
        [X_ASH_CONTEXT_ID]: CTX_ID,
      },
      method: 'GET',
      url: '/api/users?page=1',
      body: undefined,
    };

    const reply = mockReply();
    await registeredHook!(request, reply);

    expect(request.ash).toBeDefined();
    expect(request.ash!.verified).toBe(true);
  });
});

// ── FUZZ: Edge Cases ───────────────────────────────────────────────

describe('FUZZ: Fastify plugin — edge cases', () => {
  it('FUZZ-FP-001: empty URL defaults gracefully', async () => {
    const fastify = mockFastify();
    await ashFastifyPlugin(fastify, { store });

    const request: FastifyRequest = {
      headers: {},
      method: 'GET',
      url: '/',
    };
    const reply = mockReply();
    await registeredHook!(request, reply);

    // Should fail with PROOF_MISSING (no context ID header)
    expect(reply._code).toBe(483);
  });
});
