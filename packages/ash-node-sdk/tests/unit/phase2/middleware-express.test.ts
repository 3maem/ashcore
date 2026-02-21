/**
 * ASH Node SDK — Phase 2: Express Middleware Tests
 *
 * Coverage: PT (bypass attempts, missing headers, tampered) / AQ (all options,
 * custom error handler, body modes) / SA (error format, status codes) / FUZZ (random req)
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ashExpressMiddleware } from '../../../src/middleware/express.js';
import type { ExpressRequest, ExpressResponse } from '../../../src/middleware/express.js';
import { AshMemoryStore } from '../../../src/context.js';
import type { AshContext } from '../../../src/context.js';
import { AshScopePolicyRegistry } from '../../../src/scope-policy.js';
import { ashBuildRequest } from '../../../src/build-request.js';
import {
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '../../../src/headers.js';
import { AshError, AshErrorCode } from '../../../src/errors.js';
import { ashDeriveClientSecret } from '../../../src/proof.js';
import { ashNormalizeBinding } from '../../../src/binding.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX_ID = 'ctx_express_test';
const METHOD = 'POST';
const PATH = '/api/users';
const BODY = '{"name":"Alice"}';

let store: AshMemoryStore;

beforeEach(() => {
  store = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
});

afterEach(() => {
  store.destroy();
});

async function setupContext(): Promise<AshContext> {
  const now = Math.floor(Date.now() / 1000);
  const binding = ashNormalizeBinding(METHOD, PATH, '');
  const clientSecret = ashDeriveClientSecret(NONCE, CTX_ID, binding);

  const ctx: AshContext = {
    id: CTX_ID,
    nonce: NONCE,
    binding,
    clientSecret,
    used: false,
    createdAt: now,
    expiresAt: now + 300,
  };
  await store.store(ctx);
  return ctx;
}

function buildValidRequest(): { req: ExpressRequest; buildResult: ReturnType<typeof ashBuildRequest> } {
  const ts = String(Math.floor(Date.now() / 1000));

  const buildResult = ashBuildRequest({
    nonce: NONCE,
    contextId: CTX_ID,
    method: METHOD,
    path: PATH,
    body: BODY,
    timestamp: ts,
  });

  const req: ExpressRequest = {
    headers: {
      [X_ASH_TIMESTAMP]: ts,
      [X_ASH_NONCE]: NONCE,
      [X_ASH_BODY_HASH]: buildResult.bodyHash,
      [X_ASH_PROOF]: buildResult.proof,
      [X_ASH_CONTEXT_ID]: CTX_ID,
    },
    method: METHOD,
    path: PATH,
    originalUrl: PATH,
    body: JSON.parse(BODY),
  };

  return { req, buildResult };
}

function mockRes(): ExpressResponse & { _status: number; _body: unknown } {
  const res: ExpressResponse & { _status: number; _body: unknown } = {
    _status: 0,
    _body: null,
    status(code: number) {
      res._status = code;
      return res;
    },
    json(body: unknown) {
      res._body = body;
    },
  };
  return res;
}

// ── AQ: Successful Verification ────────────────────────────────────

describe('AQ: Express middleware — success', () => {
  it('AQ-EXP-001: valid request passes through', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.ash).toBeDefined();
    expect(req.ash!.verified).toBe(true);
    expect(req.ash!.contextId).toBe(CTX_ID);
    expect(req.ash!.mode).toBe('basic');
  });

  it('AQ-EXP-002: meta contains timestamp and binding', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(req.ash!.timestamp).toBeGreaterThan(0);
    expect(req.ash!.binding).toContain('POST|');
  });
});

// ── AQ: Custom Error Handler ───────────────────────────────────────

describe('AQ: Express middleware — custom error handler', () => {
  it('AQ-EXP-ERR-001: onError called on verification failure', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    req.headers[X_ASH_PROOF] = 'f'.repeat(64); // forge proof
    const res = mockRes();
    const next = vi.fn();
    const onError = vi.fn();

    const mw = ashExpressMiddleware({ store, onError });
    await mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0]).toBeInstanceOf(AshError);
  });

  it('AQ-EXP-ERR-002: onError called when context not found', async () => {
    // Don't set up context
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();
    const onError = vi.fn();

    const mw = ashExpressMiddleware({ store, onError });
    await mw(req, res, next);

    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0].code).toBe(AshErrorCode.CTX_NOT_FOUND);
  });
});

// ── AQ: Body Extraction ────────────────────────────────────────────

describe('AQ: Express middleware — body extraction', () => {
  it('AQ-EXP-BODY-001: custom extractBody is used', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({
      store,
      extractBody: () => BODY, // Return raw JSON string
    });
    await mw(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });

  it('AQ-EXP-BODY-002: string body handled directly', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    req.body = BODY; // String body instead of parsed object
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });
});

// ── AQ: Scope Registry ────────────────────────────────────────────

describe('AQ: Express middleware — scope registry', () => {
  it('AQ-EXP-SCOPE-001: scope registry integration', async () => {
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

    const scopeRegistry = new AshScopePolicyRegistry();
    scopeRegistry.register({ pattern: 'POST /api/users', fields: ['name'] });

    const ts = String(now);
    const buildResult = ashBuildRequest({
      nonce: NONCE,
      contextId: CTX_ID,
      method: METHOD,
      path: PATH,
      body: BODY,
      timestamp: ts,
      scope: ['name'],
    });

    const req: ExpressRequest = {
      headers: {
        [X_ASH_TIMESTAMP]: ts,
        [X_ASH_NONCE]: NONCE,
        [X_ASH_BODY_HASH]: buildResult.bodyHash,
        [X_ASH_PROOF]: buildResult.proof,
        [X_ASH_CONTEXT_ID]: CTX_ID,
      },
      method: METHOD,
      path: PATH,
      originalUrl: PATH,
      body: JSON.parse(BODY),
    };

    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store, scopeRegistry });
    await mw(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(req.ash!.mode).toBe('scoped');
  });
});

// ── PT: Missing / Invalid Headers ──────────────────────────────────

describe('PT: Express middleware — missing headers', () => {
  it('PT-EXP-001: missing context ID header returns error', async () => {
    const { req } = buildValidRequest();
    delete (req.headers as Record<string, string>)[X_ASH_CONTEXT_ID];
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res._status).toBe(483); // PROOF_MISSING
  });

  it('PT-EXP-002: unknown context ID returns CTX_NOT_FOUND', async () => {
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res._status).toBe(450); // CTX_NOT_FOUND
  });

  it('PT-EXP-003: double consume returns CTX_ALREADY_USED', async () => {
    await setupContext();
    const res1 = mockRes();
    const res2 = mockRes();
    const next1 = vi.fn();
    const next2 = vi.fn();

    const mw = ashExpressMiddleware({ store });

    // First request succeeds
    const { req: req1 } = buildValidRequest();
    await mw(req1, res1, next1);
    expect(next1).toHaveBeenCalledOnce();

    // Second request fails (context already consumed)
    const { req: req2 } = buildValidRequest();
    await mw(req2, res2, next2);
    expect(next2).not.toHaveBeenCalled();
    expect(res2._status).toBe(452); // CTX_ALREADY_USED
  });
});

// ── PT: Tampered Request ───────────────────────────────────────────

describe('PT: Express middleware — tampered request', () => {
  it('PT-EXP-TAMP-001: forged proof is rejected', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    req.headers[X_ASH_PROOF] = 'f'.repeat(64);
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res._status).toBe(460); // PROOF_INVALID
  });

  it('PT-EXP-TAMP-002: tampered body is rejected', async () => {
    await setupContext();
    const { req } = buildValidRequest();
    req.body = { name: 'Bob' }; // Different from original
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res._status).toBe(460);
  });
});

// ── SA: Error Response Format ──────────────────────────────────────

describe('SA: Express middleware — error format', () => {
  it('SA-EXP-001: error response is JSON with error/message/status', async () => {
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(res._body).toHaveProperty('error');
    expect(res._body).toHaveProperty('message');
    expect(res._body).toHaveProperty('status');
  });

  it('SA-EXP-002: error message does not contain secrets', async () => {
    const { req } = buildValidRequest();
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    const body = res._body as Record<string, unknown>;
    expect(String(body.message)).not.toContain(NONCE);
  });
});

// ── FUZZ: Edge Cases ───────────────────────────────────────────────

describe('FUZZ: Express middleware — edge cases', () => {
  it('FUZZ-EXP-001: request with no headers object', async () => {
    const req = { headers: {}, method: 'GET', path: '/' } as ExpressRequest;
    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).not.toHaveBeenCalled();
  });

  it('FUZZ-EXP-002: request with query string in URL', async () => {
    await setupContext();

    const ts = String(Math.floor(Date.now() / 1000));
    const buildResult = ashBuildRequest({
      nonce: NONCE,
      contextId: CTX_ID,
      method: 'GET',
      path: '/api/users',
      rawQuery: 'page=1',
      body: '',
      timestamp: ts,
    });

    // Need fresh context since previous was consumed
    store.destroy();
    store = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
    const now = Math.floor(Date.now() / 1000);
    const binding = ashNormalizeBinding('GET', '/api/users', 'page=1');
    await store.store({
      id: CTX_ID,
      nonce: NONCE,
      binding,
      clientSecret: ashDeriveClientSecret(NONCE, CTX_ID, binding),
      used: false,
      createdAt: now,
      expiresAt: now + 300,
    });

    const req: ExpressRequest = {
      headers: {
        [X_ASH_TIMESTAMP]: ts,
        [X_ASH_NONCE]: NONCE,
        [X_ASH_BODY_HASH]: buildResult.bodyHash,
        [X_ASH_PROOF]: buildResult.proof,
        [X_ASH_CONTEXT_ID]: CTX_ID,
      },
      method: 'GET',
      path: '/api/users',
      originalUrl: '/api/users?page=1',
      body: undefined,
    };

    const res = mockRes();
    const next = vi.fn();

    const mw = ashExpressMiddleware({ store });
    await mw(req, res, next);

    expect(next).toHaveBeenCalledOnce();
  });
});
