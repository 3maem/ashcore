/**
 * Comprehensive Production-Readiness Tests
 *
 * Coverage:
 *   Section 1: Redis Context Store — deep security & edge cases
 *   Section 2: E2E Integration — full client→server lifecycle
 *   Section 3: Barrel Export & Package Correctness
 *
 * Test types: PT (Penetration), AQ (API Quality), SA (Security Audit), FUZZ (Adversarial)
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';

import { AshRedisStore } from '../../../src/context-redis.js';
import type { RedisClient } from '../../../src/context-redis.js';
import { AshMemoryStore } from '../../../src/context.js';
import type { AshContext, AshContextStore } from '../../../src/context.js';
import { AshError, AshErrorCode } from '../../../src/errors.js';
import { ashBuildRequest } from '../../../src/build-request.js';
import { ashDeriveClientSecret } from '../../../src/proof.js';
import { ashNormalizeBinding } from '../../../src/binding.js';
import { ashExpressMiddleware } from '../../../src/middleware/express.js';
import { ashFastifyPlugin } from '../../../src/middleware/fastify.js';
import { AshScopePolicyRegistry } from '../../../src/scope-policy.js';
import {
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '../../../src/headers.js';

// ══════════════════════════════════════════════════════════════════
// Shared Mock Redis Client
// ══════════════════════════════════════════════════════════════════

function createMockRedis(): RedisClient & {
  _store: Map<string, { value: string; ttl: number }>;
  _callLog: { method: string; args: unknown[] }[];
} {
  const store = new Map<string, { value: string; ttl: number }>();
  const callLog: { method: string; args: unknown[] }[] = [];

  return {
    _store: store,
    _callLog: callLog,

    async get(key: string) {
      callLog.push({ method: 'get', args: [key] });
      const entry = store.get(key);
      if (!entry) return null;
      return entry.value;
    },

    async set(key: string, value: string, ...args: unknown[]) {
      callLog.push({ method: 'set', args: [key, value, ...args] });
      let ttl = -1;
      for (let i = 0; i < args.length; i++) {
        if (args[i] === 'EX' && typeof args[i + 1] === 'number') {
          ttl = args[i + 1] as number;
        }
      }
      store.set(key, { value, ttl });
      return 'OK';
    },

    async del(key: string | string[]) {
      callLog.push({ method: 'del', args: [key] });
      const keys = Array.isArray(key) ? key : [key];
      let count = 0;
      for (const k of keys) {
        if (store.delete(k)) count++;
      }
      return count;
    },

    async eval(script: string, numkeys: number, ...args: (string | number)[]) {
      callLog.push({ method: 'eval', args: [script.slice(0, 20), numkeys, ...args] });
      const redisKey = args[0] as string;
      const entry = store.get(redisKey);
      if (!entry) return 'ERR:CTX_NOT_FOUND';

      const ctx = JSON.parse(entry.value);
      if (ctx.used) return 'ERR:CTX_ALREADY_USED';

      const original = entry.value;
      ctx.used = true;
      store.set(redisKey, { value: JSON.stringify(ctx), ttl: entry.ttl });
      return original;
    },
  };
}

// ══════════════════════════════════════════════════════════════════
// Shared Helpers
// ══════════════════════════════════════════════════════════════════

function makeCtx(overrides?: Partial<AshContext>): AshContext {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `ctx-${crypto.randomBytes(8).toString('hex')}`,
    nonce: crypto.randomBytes(32).toString('hex'),
    binding: 'GET|/api/test|',
    clientSecret: crypto.randomBytes(32).toString('hex'),
    used: false,
    createdAt: now,
    expiresAt: now + 300,
    ...overrides,
  };
}

/** Build valid ASH headers for a given context and endpoint. */
function buildValidHeaders(ctx: AshContext, method: string, path: string, body = '') {
  const result = ashBuildRequest({
    nonce: ctx.nonce,
    contextId: ctx.id,
    method,
    path,
    body,
  });
  return {
    headers: {
      [X_ASH_TIMESTAMP]: result.timestamp,
      [X_ASH_NONCE]: result.nonce,
      [X_ASH_BODY_HASH]: result.bodyHash,
      [X_ASH_PROOF]: result.proof,
      [X_ASH_CONTEXT_ID]: ctx.id,
    },
    result,
  };
}

/** Create a valid context with proper derived clientSecret. */
function makeValidCtx(method: string, path: string, query = ''): AshContext {
  const now = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(32).toString('hex');
  const contextId = `ctx-${crypto.randomBytes(8).toString('hex')}`;
  const binding = ashNormalizeBinding(method, path, query);
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  return {
    id: contextId,
    nonce,
    binding,
    clientSecret,
    used: false,
    createdAt: now,
    expiresAt: now + 300,
  };
}

// ══════════════════════════════════════════════════════════════════
// SECTION 1: Redis Context Store — Deep Security & Edge Cases
// ══════════════════════════════════════════════════════════════════

describe('Section 1: Redis Context Store — Comprehensive', () => {
  let redis: ReturnType<typeof createMockRedis>;
  let store: AshRedisStore;

  beforeEach(() => {
    redis = createMockRedis();
    store = new AshRedisStore({ client: redis });
  });

  // ── PT: Redis Client Failure Modes ────────────────────────────

  describe('PT-REDIS-001: Redis client network errors', () => {
    it('propagates GET errors to caller', async () => {
      const failRedis = createMockRedis();
      failRedis.get = async () => { throw new Error('ECONNREFUSED'); };
      const failStore = new AshRedisStore({ client: failRedis });
      await expect(failStore.get('any')).rejects.toThrow('ECONNREFUSED');
    });

    it('propagates SET errors on store()', async () => {
      const failRedis = createMockRedis();
      failRedis.set = async () => { throw new Error('READONLY'); };
      const failStore = new AshRedisStore({ client: failRedis });
      await expect(failStore.store(makeCtx())).rejects.toThrow('READONLY');
    });

    it('propagates EVAL errors on consume()', async () => {
      const failRedis = createMockRedis();
      failRedis.eval = async () => { throw new Error('NOSCRIPT'); };
      const failStore = new AshRedisStore({ client: failRedis });
      await expect(failStore.consume('any')).rejects.toThrow('NOSCRIPT');
    });

    it('propagates DEL errors on get() for expired context', async () => {
      const failRedis = createMockRedis();
      const now = Math.floor(Date.now() / 1000);
      // Store an expired context manually
      const ctx = makeCtx({ expiresAt: now - 10 });
      const payload = JSON.stringify(ctx);
      failRedis._store.set(`ash:ctx:${ctx.id}`, { value: payload, ttl: -1 });
      failRedis.del = async () => { throw new Error('DEL_FAILED'); };
      const failStore = new AshRedisStore({ client: failRedis });
      await expect(failStore.get(ctx.id)).rejects.toThrow('DEL_FAILED');
    });
  });

  describe('PT-REDIS-002: Lua script response manipulation', () => {
    it('handles null return from eval (unexpected)', async () => {
      const badRedis = createMockRedis();
      badRedis.eval = async () => null;
      const badStore = new AshRedisStore({ client: badRedis });
      // null is not 'ERR:CTX_NOT_FOUND', so it falls through to JSON.parse(null)
      await expect(badStore.consume('x')).rejects.toThrow();
    });

    it('handles numeric return from eval (parses as valid JSON number)', async () => {
      const badRedis = createMockRedis();
      badRedis.eval = async () => 42;
      const badStore = new AshRedisStore({ client: badRedis });
      // JSON.parse("42") = 42, which is valid but not an AshContext
      // The store doesn't validate shape, so it returns the raw parsed value
      const result = await badStore.consume('x');
      expect(result).toBe(42);
    });

    it('handles empty string from eval', async () => {
      const badRedis = createMockRedis();
      badRedis.eval = async () => '';
      const badStore = new AshRedisStore({ client: badRedis });
      await expect(badStore.consume('x')).rejects.toThrow();
    });

    it('handles malformed JSON from eval', async () => {
      const badRedis = createMockRedis();
      badRedis.eval = async () => '{not valid json}';
      const badStore = new AshRedisStore({ client: badRedis });
      await expect(badStore.consume('x')).rejects.toThrow();
    });

    it('handles JSON with missing fields from eval', async () => {
      const badRedis = createMockRedis();
      badRedis.eval = async () => '{"id":"x"}';
      const badStore = new AshRedisStore({ client: badRedis });
      // No expiresAt means expiresAt is undefined — check > 0 is false for undefined
      const result = await badStore.consume('x');
      expect(result.id).toBe('x');
    });
  });

  describe('PT-REDIS-003: Key injection attacks', () => {
    it('context ID with newlines in Redis key', async () => {
      const ctx = makeCtx({ id: 'ctx\r\nSET injected key' });
      await store.store(ctx);
      // The key should be stored as-is (mock doesn't parse RESP protocol)
      const got = await store.get('ctx\r\nSET injected key');
      expect(got).not.toBeNull();
      expect(got!.id).toBe('ctx\r\nSET injected key');
    });

    it('context ID with null bytes', async () => {
      const ctx = makeCtx({ id: 'ctx\x00poison' });
      await store.store(ctx);
      const got = await store.get('ctx\x00poison');
      expect(got).not.toBeNull();
    });

    it('prefix injection via context ID', async () => {
      // Try to escape the prefix by using a key that looks like another prefix
      const ctx = makeCtx({ id: '../other-prefix:steal' });
      await store.store(ctx);
      // Should be stored under ash:ctx:../other-prefix:steal
      expect(redis._store.has('ash:ctx:../other-prefix:steal')).toBe(true);
      // Should NOT be stored under any other key
      expect(redis._store.has('other-prefix:steal')).toBe(false);
    });

    it('wildcard characters in context ID', async () => {
      const ctx = makeCtx({ id: 'ctx-*-glob-[test]' });
      await store.store(ctx);
      const got = await store.get('ctx-*-glob-[test]');
      expect(got).not.toBeNull();
    });
  });

  describe('PT-REDIS-004: JSON deserialization attacks', () => {
    it('handles __proto__ in stored JSON', async () => {
      const maliciousJson = '{"id":"x","nonce":"n","binding":"b","clientSecret":"s","used":false,"createdAt":0,"expiresAt":0,"__proto__":{"isAdmin":true}}';
      redis._store.set('ash:ctx:x', { value: maliciousJson, ttl: 300 });
      const got = await store.get('x');
      expect(got).not.toBeNull();
      // __proto__ should not pollute Object prototype
      expect(({} as any).isAdmin).toBeUndefined();
    });

    it('handles constructor pollution in stored JSON', async () => {
      const maliciousJson = '{"id":"x","nonce":"n","binding":"b","clientSecret":"s","used":false,"createdAt":0,"expiresAt":0,"constructor":{"prototype":{"pwned":true}}}';
      redis._store.set('ash:ctx:x', { value: maliciousJson, ttl: 300 });
      const got = await store.get('x');
      expect(got).not.toBeNull();
      expect(({} as any).pwned).toBeUndefined();
    });

    it('handles extremely deep nested JSON', async () => {
      let deep = '{"id":"x","nonce":"n","binding":"b","clientSecret":"s","used":false,"createdAt":0,"expiresAt":0,"deep":';
      for (let i = 0; i < 100; i++) deep += '{"a":';
      deep += '"leaf"';
      for (let i = 0; i < 100; i++) deep += '}';
      deep += '}';
      redis._store.set('ash:ctx:x', { value: deep, ttl: 300 });
      const got = await store.get('x');
      expect(got).not.toBeNull();
      expect(got!.id).toBe('x');
    });
  });

  // ── AQ: API Quality ───────────────────────────────────────────

  describe('AQ-REDIS-001: Constructor options validation', () => {
    it('uses default prefix when not specified', async () => {
      const s = new AshRedisStore({ client: redis });
      const ctx = makeCtx({ id: 'test-default' });
      await s.store(ctx);
      expect(redis._store.has('ash:ctx:test-default')).toBe(true);
    });

    it('uses empty string prefix', async () => {
      const s = new AshRedisStore({ client: redis, keyPrefix: '' });
      const ctx = makeCtx({ id: 'no-prefix' });
      await s.store(ctx);
      expect(redis._store.has('no-prefix')).toBe(true);
    });

    it('uses custom TTL of 1 second', async () => {
      const s = new AshRedisStore({ client: redis, ttlSeconds: 1 });
      const ctx = makeCtx({ expiresAt: 0 });
      await s.store(ctx);
      const entry = redis._store.get(`ash:ctx:${ctx.id}`);
      expect(entry!.ttl).toBe(1);
    });

    it('uses very large TTL', async () => {
      const s = new AshRedisStore({ client: redis, ttlSeconds: 86400 });
      const ctx = makeCtx({ expiresAt: 0 });
      await s.store(ctx);
      const entry = redis._store.get(`ash:ctx:${ctx.id}`);
      expect(entry!.ttl).toBe(86400);
    });
  });

  describe('AQ-REDIS-002: store() serialization correctness', () => {
    it('serializes all 7 AshContext fields', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx: AshContext = {
        id: 'ser-test',
        nonce: 'abcdef1234567890'.repeat(4),
        binding: 'POST|/api/users|name=test',
        clientSecret: 'secret_hash_value_here'.repeat(3),
        used: false,
        createdAt: now,
        expiresAt: now + 600,
      };
      await store.store(ctx);
      const raw = redis._store.get('ash:ctx:ser-test')!.value;
      const parsed = JSON.parse(raw);
      expect(parsed.id).toBe(ctx.id);
      expect(parsed.nonce).toBe(ctx.nonce);
      expect(parsed.binding).toBe(ctx.binding);
      expect(parsed.clientSecret).toBe(ctx.clientSecret);
      expect(parsed.used).toBe(false);
      expect(parsed.createdAt).toBe(now);
      expect(parsed.expiresAt).toBe(now + 600);
    });

    it('calculates expiresAt from createdAt + ttlSeconds when expiresAt is 0', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ createdAt: now, expiresAt: 0 });
      await store.store(ctx);
      const raw = redis._store.get(`ash:ctx:${ctx.id}`)!.value;
      const parsed = JSON.parse(raw);
      expect(parsed.expiresAt).toBe(now + 300);
    });

    it('preserves original expiresAt when > 0', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now + 999 });
      await store.store(ctx);
      const raw = redis._store.get(`ash:ctx:${ctx.id}`)!.value;
      const parsed = JSON.parse(raw);
      expect(parsed.expiresAt).toBe(now + 999);
    });

    it('passes EX argument to Redis SET', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const setCall = redis._callLog.find(c => c.method === 'set');
      expect(setCall).toBeDefined();
      expect(setCall!.args[2]).toBe('EX');
      expect(typeof setCall!.args[3]).toBe('number');
      expect(setCall!.args[3] as number).toBeGreaterThan(0);
    });
  });

  describe('AQ-REDIS-003: consume() atomicity guarantees', () => {
    it('uses eval (Lua) for atomic consume', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      redis._callLog.length = 0;
      await store.consume(ctx.id);
      const evalCall = redis._callLog.find(c => c.method === 'eval');
      expect(evalCall).toBeDefined();
    });

    it('passes correct key to Lua script', async () => {
      const ctx = makeCtx({ id: 'lua-key-test' });
      await store.store(ctx);
      redis._callLog.length = 0;
      await store.consume('lua-key-test');
      const evalCall = redis._callLog.find(c => c.method === 'eval');
      expect(evalCall!.args).toContain('ash:ctx:lua-key-test');
    });

    it('returns pre-consume state (used=false) from consume', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const consumed = await store.consume(ctx.id);
      expect(consumed.used).toBe(false);
    });

    it('post-consume state in Redis is used=true', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      await store.consume(ctx.id);
      const raw = redis._store.get(`ash:ctx:${ctx.id}`)!.value;
      const parsed = JSON.parse(raw);
      expect(parsed.used).toBe(true);
    });
  });

  describe('AQ-REDIS-004: expiry edge cases', () => {
    it('context at exact expiry boundary (expiresAt == now)', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now });
      await store.store(ctx);
      // now > ctx.expiresAt is false when equal, so context is still valid
      const got = await store.get(ctx.id);
      // Both null (just expired due to timing) and valid are acceptable
      // but the call itself must not crash
      expect(got === null || got.id === ctx.id).toBe(true);
    });

    it('context with expiresAt far in the future', async () => {
      const ctx = makeCtx({ expiresAt: 32503680000 }); // Year 3000
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
    });

    it('context with negative expiresAt', async () => {
      const ctx = makeCtx({ expiresAt: -1 });
      await store.store(ctx);
      // expiresAt > 0 is false, so the TTL = this._ttlSeconds (300)
      const entry = redis._store.get(`ash:ctx:${ctx.id}`);
      expect(entry!.ttl).toBe(300);
    });

    it('consume deletes expired context from Redis', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now - 100 });
      await store.store(ctx);
      await expect(store.consume(ctx.id)).rejects.toMatchObject({
        code: AshErrorCode.CTX_EXPIRED,
      });
      // After expiry check in consume, it should have called del
      const delCall = redis._callLog.find(c => c.method === 'del');
      expect(delCall).toBeDefined();
    });
  });

  // ── SA: Security Audit ────────────────────────────────────────

  describe('SA-REDIS-001: Error message safety', () => {
    it('CTX_NOT_FOUND does not reveal context ID', async () => {
      try {
        await store.consume('secret-ctx-id-12345');
        expect.unreachable('should have thrown');
      } catch (err: unknown) {
        const e = err as AshError;
        expect(e.message).not.toContain('secret-ctx-id-12345');
        expect(e.message).not.toContain('ash:ctx:');
      }
    });

    it('CTX_ALREADY_USED does not reveal nonce or secret', async () => {
      const ctx = makeCtx({ nonce: 'secret_nonce_value', clientSecret: 'secret_key_value' });
      await store.store(ctx);
      await store.consume(ctx.id);
      try {
        await store.consume(ctx.id);
        expect.unreachable('should have thrown');
      } catch (err: unknown) {
        const e = err as AshError;
        expect(e.message).not.toContain('secret_nonce_value');
        expect(e.message).not.toContain('secret_key_value');
        expect(e.message).not.toContain(ctx.id);
      }
    });

    it('CTX_EXPIRED does not reveal timing information', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now - 1 });
      await store.store(ctx);
      try {
        await store.consume(ctx.id);
        expect.unreachable('should have thrown');
      } catch (err: unknown) {
        const e = err as AshError;
        expect(e.message).not.toMatch(/\d{10}/); // No Unix timestamps
      }
    });
  });

  describe('SA-REDIS-002: HTTP status code mapping', () => {
    it('CTX_NOT_FOUND → 450', async () => {
      expect.assertions(1);
      try {
        await store.consume('missing');
      } catch (err: unknown) {
        expect((err as AshError).httpStatus).toBe(450);
      }
    });

    it('CTX_ALREADY_USED → 452', async () => {
      expect.assertions(1);
      const ctx = makeCtx();
      await store.store(ctx);
      await store.consume(ctx.id);
      try {
        await store.consume(ctx.id);
      } catch (err: unknown) {
        expect((err as AshError).httpStatus).toBe(452);
      }
    });

    it('CTX_EXPIRED → 451', async () => {
      expect.assertions(1);
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now - 10 });
      await store.store(ctx);
      try {
        await store.consume(ctx.id);
      } catch (err: unknown) {
        expect((err as AshError).httpStatus).toBe(451);
      }
    });
  });

  describe('SA-REDIS-003: Interface compliance', () => {
    it('AshRedisStore implements full AshContextStore interface', () => {
      const s: AshContextStore = new AshRedisStore({ client: redis });
      expect(typeof s.get).toBe('function');
      expect(typeof s.consume).toBe('function');
      expect(typeof s.store).toBe('function');
      expect(typeof s.cleanup).toBe('function');
    });

    it('cleanup always returns 0 (Redis-native TTL)', async () => {
      // Store many contexts, some expired
      for (let i = 0; i < 10; i++) {
        await store.store(makeCtx({ id: `cleanup-${i}` }));
      }
      const removed = await store.cleanup();
      expect(removed).toBe(0);
    });

    it('destroy resolves without error', async () => {
      await expect(store.destroy()).resolves.toBeUndefined();
    });
  });

  describe('SA-REDIS-004: Secret data in Redis storage', () => {
    it('clientSecret is stored in Redis (necessary for verification)', async () => {
      const ctx = makeCtx({ clientSecret: 'my_secret_value_here' });
      await store.store(ctx);
      const raw = redis._store.get(`ash:ctx:${ctx.id}`)!.value;
      // clientSecret must be in Redis for the verify flow
      expect(raw).toContain('my_secret_value_here');
    });

    it('nonce is stored in Redis (necessary for verification)', async () => {
      const ctx = makeCtx({ nonce: 'aabbccdd'.repeat(8) });
      await store.store(ctx);
      const raw = redis._store.get(`ash:ctx:${ctx.id}`)!.value;
      expect(raw).toContain('aabbccdd'.repeat(8));
    });
  });

  // ── FUZZ: Adversarial Inputs ──────────────────────────────────

  describe('FUZZ-REDIS-001: Random context IDs', () => {
    it('handles 100 random UUIDs', async () => {
      for (let i = 0; i < 100; i++) {
        const id = crypto.randomUUID();
        const ctx = makeCtx({ id });
        await store.store(ctx);
        const got = await store.get(id);
        expect(got).not.toBeNull();
        expect(got!.id).toBe(id);
      }
    });

    it('handles context IDs with all printable ASCII', async () => {
      let id = '';
      for (let c = 32; c < 127; c++) id += String.fromCharCode(c);
      const ctx = makeCtx({ id });
      await store.store(ctx);
      const got = await store.get(id);
      expect(got).not.toBeNull();
    });

    it('handles context IDs with Unicode', async () => {
      const ids = ['日本語', '🔒🔑🛡️', 'مرحبا', 'Ω≈ç√', 'ctx-\u200B-zwsp'];
      for (const id of ids) {
        const ctx = makeCtx({ id });
        await store.store(ctx);
        const got = await store.get(id);
        expect(got).not.toBeNull();
        expect(got!.id).toBe(id);
      }
    });
  });

  describe('FUZZ-REDIS-002: Concurrent consume simulation', () => {
    it('exactly one of N concurrent consumes succeeds', async () => {
      const ctx = makeCtx();
      await store.store(ctx);

      let successes = 0;
      let failures = 0;
      const promises = Array.from({ length: 10 }, async () => {
        try {
          await store.consume(ctx.id);
          successes++;
        } catch {
          failures++;
        }
      });
      await Promise.all(promises);

      // With our mock (sequential eval), exactly 1 succeeds
      expect(successes).toBe(1);
      expect(failures).toBe(9);
    });
  });

  describe('FUZZ-REDIS-003: Large payloads', () => {
    it('handles context with very large nonce (10KB)', async () => {
      const ctx = makeCtx({ nonce: 'a'.repeat(10000) });
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.nonce.length).toBe(10000);
    });

    it('handles context with very large binding (50KB)', async () => {
      const ctx = makeCtx({ binding: 'GET|/' + 'x'.repeat(50000) + '|' });
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.binding.length).toBeGreaterThan(50000);
    });
  });

  describe('FUZZ-REDIS-004: Malicious stored values', () => {
    it('handles stored value that is not JSON', async () => {
      redis._store.set('ash:ctx:bad', { value: 'not-json-at-all', ttl: 300 });
      await expect(store.get('bad')).rejects.toThrow();
    });

    it('handles stored value that is JSON array', async () => {
      redis._store.set('ash:ctx:arr', { value: '[1,2,3]', ttl: 300 });
      const got = await store.get('arr');
      // Arrays don't have expiresAt > 0, so they pass the check
      expect(got).not.toBeNull();
    });

    it('handles stored value with extra fields', async () => {
      const val = JSON.stringify({
        id: 'extra', nonce: 'n', binding: 'b', clientSecret: 's',
        used: false, createdAt: 0, expiresAt: 0, extraField: 'surprise',
      });
      redis._store.set('ash:ctx:extra', { value: val, ttl: 300 });
      const got = await store.get('extra');
      expect(got).not.toBeNull();
      expect((got as any).extraField).toBe('surprise');
    });
  });

  // ── PT: Redis vs Memory Store Parity ──────────────────────────

  describe('PT-REDIS-005: Parity with AshMemoryStore', () => {
    it('both stores reject double consume identically', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const ctx1 = makeCtx({ id: 'parity-1' });
      const ctx2 = { ...ctx1 }; // same data for both stores

      await store.store(ctx1);
      await memStore.store(ctx2);

      await store.consume(ctx1.id);
      await memStore.consume(ctx2.id);

      // Both should throw CTX_ALREADY_USED
      await expect(store.consume(ctx1.id)).rejects.toMatchObject({
        code: AshErrorCode.CTX_ALREADY_USED,
      });
      await expect(memStore.consume(ctx2.id)).rejects.toMatchObject({
        code: AshErrorCode.CTX_ALREADY_USED,
      });

      memStore.destroy();
    });

    it('both stores reject missing context identically', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });

      await expect(store.consume('ghost')).rejects.toMatchObject({
        code: AshErrorCode.CTX_NOT_FOUND,
      });
      await expect(memStore.consume('ghost')).rejects.toMatchObject({
        code: AshErrorCode.CTX_NOT_FOUND,
      });

      memStore.destroy();
    });
  });
});

// ══════════════════════════════════════════════════════════════════
// SECTION 2: E2E Integration — Full Client→Server Lifecycle
// ══════════════════════════════════════════════════════════════════

describe('Section 2: E2E Integration — Comprehensive', () => {

  // ── Helpers: Express mock ─────────────────────────────────────

  function createExpressReq(overrides: Record<string, unknown> = {}) {
    return {
      headers: {} as Record<string, string | string[] | undefined>,
      method: 'GET',
      path: '/api/test',
      originalUrl: '/api/test',
      url: '/api/test',
      body: undefined as unknown,
      ash: undefined as any,
      ...overrides,
    };
  }

  function createExpressRes() {
    let _status = 200;
    let _body: unknown = null;
    return {
      status(code: number) { _status = code; return this; },
      json(body: unknown) { _body = body; },
      get statusCode() { return _status; },
      get responseBody() { return _body; },
    };
  }

  // ── Helpers: Fastify mock ─────────────────────────────────────

  function createFastifyMock() {
    let _hookHandler: ((req: any, reply: any) => Promise<void>) | null = null;
    return {
      instance: {
        decorateRequest: vi.fn(),
        addHook: vi.fn((name: string, handler: any) => { _hookHandler = handler; }),
      },
      getHookHandler: () => _hookHandler,
    };
  }

  function createFastifyReply() {
    let _code = 200;
    let _body: unknown = null;
    return {
      code(c: number) { _code = c; return this; },
      send(b: unknown) { _body = b; },
      get statusCode() { return _code; },
      get responseBody() { return _body; },
    };
  }

  // ── E2E: Basic Mode ───────────────────────────────────────────

  describe('E2E-001: Basic mode — full lifecycle', () => {
    it('Express: context create → build → verify → success', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      // Server creates context
      const ctx = makeValidCtx('GET', '/api/users');
      await memStore.store(ctx);

      // Client builds proof
      const { headers } = buildValidHeaders(ctx, 'GET', '/api/users');

      // Client sends request through middleware
      const req = createExpressReq({
        headers,
        method: 'GET',
        path: '/api/users',
        originalUrl: '/api/users',
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.ash).toBeDefined();
      expect(req.ash.verified).toBe(true);
      expect(req.ash.mode).toBe('basic');
      expect(req.ash.contextId).toBe(ctx.id);

      memStore.destroy();
    });

    it('Fastify: context create → build → verify → success', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const { instance, getHookHandler } = createFastifyMock();

      await ashFastifyPlugin(instance as any, { store: memStore });
      const handler = getHookHandler()!;

      const ctx = makeValidCtx('GET', '/api/data');
      await memStore.store(ctx);

      const { headers } = buildValidHeaders(ctx, 'GET', '/api/data');

      const request: any = {
        headers,
        method: 'GET',
        url: '/api/data',
        body: undefined,
        ash: undefined,
      };
      const reply = createFastifyReply();

      await handler(request, reply);

      expect(request.ash).toBeDefined();
      expect(request.ash.verified).toBe(true);
      expect(request.ash.mode).toBe('basic');

      memStore.destroy();
    });
  });

  // ── E2E: POST with Body ───────────────────────────────────────

  describe('E2E-002: POST with JSON body', () => {
    it('Express: JSON body → build → verify → success', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('POST', '/api/users');
      await memStore.store(ctx);

      const body = JSON.stringify({ name: 'Alice', email: 'alice@test.com' });
      const { headers } = buildValidHeaders(ctx, 'POST', '/api/users', body);

      const req = createExpressReq({
        headers,
        method: 'POST',
        path: '/api/users',
        originalUrl: '/api/users',
        body: { name: 'Alice', email: 'alice@test.com' }, // Pre-parsed by express.json()
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.ash.verified).toBe(true);

      memStore.destroy();
    });

    it('Express: raw string body → build → verify → success', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('POST', '/api/raw');
      await memStore.store(ctx);

      const body = '{"data":"raw string"}';
      const { headers } = buildValidHeaders(ctx, 'POST', '/api/raw', body);

      const req = createExpressReq({
        headers,
        method: 'POST',
        path: '/api/raw',
        originalUrl: '/api/raw',
        body, // String body
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.ash.verified).toBe(true);

      memStore.destroy();
    });
  });

  // ── E2E: Replay Protection ────────────────────────────────────

  describe('E2E-003: Replay attack detection', () => {
    it('Express: second request with same context fails with 452', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('GET', '/api/secret');
      await memStore.store(ctx);

      const { headers } = buildValidHeaders(ctx, 'GET', '/api/secret');

      // First request succeeds
      const req1 = createExpressReq({ headers, method: 'GET', path: '/api/secret', originalUrl: '/api/secret' });
      const res1 = createExpressRes();
      await middleware(req1 as any, res1 as any, vi.fn());
      expect((req1 as any).ash.verified).toBe(true);

      // Second request (replay) fails
      const req2 = createExpressReq({ headers, method: 'GET', path: '/api/secret', originalUrl: '/api/secret' });
      const res2 = createExpressRes();
      await middleware(req2 as any, res2 as any, vi.fn());
      expect(res2.statusCode).toBe(452);
      expect((res2.responseBody as any).error).toBe('ASH_CTX_ALREADY_USED');

      memStore.destroy();
    });

    it('Fastify: replay detected on second request', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const { instance, getHookHandler } = createFastifyMock();
      await ashFastifyPlugin(instance as any, { store: memStore });
      const handler = getHookHandler()!;

      const ctx = makeValidCtx('GET', '/api/protected');
      await memStore.store(ctx);

      const { headers } = buildValidHeaders(ctx, 'GET', '/api/protected');

      // First request
      const req1: any = { headers, method: 'GET', url: '/api/protected', ash: undefined };
      await handler(req1, createFastifyReply());
      expect(req1.ash.verified).toBe(true);

      // Replay
      const req2: any = { headers, method: 'GET', url: '/api/protected', ash: undefined };
      const reply2 = createFastifyReply();
      await handler(req2, reply2);
      expect(reply2.statusCode).toBe(452);

      memStore.destroy();
    });
  });

  // ── E2E: Missing Headers ──────────────────────────────────────

  describe('E2E-004: Missing / invalid headers', () => {
    it('Express: no context ID header → 483', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const req = createExpressReq({ headers: {}, method: 'GET', path: '/api/test' });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      expect(res.statusCode).toBe(483);
      expect((res.responseBody as any).error).toBe('ASH_PROOF_MISSING');

      memStore.destroy();
    });

    it('Express: context ID but no other headers → 483', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('GET', '/api/test');
      await memStore.store(ctx);

      const req = createExpressReq({
        headers: { [X_ASH_CONTEXT_ID]: ctx.id },
        method: 'GET',
        path: '/api/test',
      });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      // After consuming, verify fails because other headers are missing → 483
      expect(res.statusCode).toBe(483);

      memStore.destroy();
    });

    it('Express: unknown context ID → 450', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const req = createExpressReq({
        headers: { [X_ASH_CONTEXT_ID]: 'nonexistent-ctx-id' },
        method: 'GET',
        path: '/api/test',
      });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      expect(res.statusCode).toBe(450);

      memStore.destroy();
    });
  });

  // ── E2E: Tampered Body ────────────────────────────────────────

  describe('E2E-005: Tampered request body', () => {
    it('Express: modified body after proof build → 460', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('POST', '/api/pay');
      await memStore.store(ctx);

      const originalBody = JSON.stringify({ amount: 100 });
      const { headers } = buildValidHeaders(ctx, 'POST', '/api/pay', originalBody);

      // Attacker modifies body
      const req = createExpressReq({
        headers,
        method: 'POST',
        path: '/api/pay',
        originalUrl: '/api/pay',
        body: { amount: 999999 }, // Tampered!
      });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      expect(res.statusCode).toBe(460);
      expect((res.responseBody as any).error).toBe('ASH_PROOF_INVALID');

      memStore.destroy();
    });
  });

  // ── E2E: Scoped Mode ─────────────────────────────────────────

  describe('E2E-006: Scoped mode with ScopePolicyRegistry', () => {
    it('Express: scoped proof matches registered policy', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const registry = new AshScopePolicyRegistry();
      registry.register({ pattern: 'POST /api/orders', fields: ['amount', 'currency'] });

      const middleware = ashExpressMiddleware({ store: memStore, scopeRegistry: registry });

      const ctx = makeValidCtx('POST', '/api/orders');
      await memStore.store(ctx);

      const body = JSON.stringify({ amount: 50, currency: 'USD', note: 'test' });
      const buildResult = ashBuildRequest({
        nonce: ctx.nonce,
        contextId: ctx.id,
        method: 'POST',
        path: '/api/orders',
        body,
        scope: ['amount', 'currency'],
      });

      const req = createExpressReq({
        headers: {
          [X_ASH_TIMESTAMP]: buildResult.timestamp,
          [X_ASH_NONCE]: buildResult.nonce,
          [X_ASH_BODY_HASH]: buildResult.bodyHash,
          [X_ASH_PROOF]: buildResult.proof,
          [X_ASH_CONTEXT_ID]: ctx.id,
        },
        method: 'POST',
        path: '/api/orders',
        originalUrl: '/api/orders',
        body: { amount: 50, currency: 'USD', note: 'test' },
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.ash.verified).toBe(true);
      expect(req.ash.mode).toBe('scoped');

      buildResult.destroy();
      memStore.destroy();
    });
  });

  // ── E2E: Custom Error Handler ─────────────────────────────────

  describe('E2E-007: Custom onError handler', () => {
    it('Express: onError receives AshError with correct code', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const onError = vi.fn();
      const middleware = ashExpressMiddleware({ store: memStore, onError });

      const req = createExpressReq({ headers: {}, method: 'GET', path: '/api/test' });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());

      expect(onError).toHaveBeenCalledOnce();
      const err = onError.mock.calls[0][0] as AshError;
      expect(err.code).toBe(AshErrorCode.PROOF_MISSING);
      expect(err.httpStatus).toBe(483);

      memStore.destroy();
    });

    it('Fastify: onError receives AshError', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const onError = vi.fn();
      const { instance, getHookHandler } = createFastifyMock();
      await ashFastifyPlugin(instance as any, { store: memStore, onError });
      const handler = getHookHandler()!;

      const request: any = { headers: {}, method: 'GET', url: '/api/test', ash: undefined };
      const reply = createFastifyReply();
      await handler(request, reply);

      expect(onError).toHaveBeenCalledOnce();
      expect((onError.mock.calls[0][0] as AshError).code).toBe(AshErrorCode.PROOF_MISSING);

      memStore.destroy();
    });
  });

  // ── E2E: Custom extractBody ───────────────────────────────────

  describe('E2E-008: Custom body extractor', () => {
    it('Express: custom extractBody is called', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const extractBody = vi.fn(() => '{"custom":"body"}');
      const middleware = ashExpressMiddleware({ store: memStore, extractBody });

      const ctx = makeValidCtx('POST', '/api/custom');
      await memStore.store(ctx);

      const body = '{"custom":"body"}';
      const { headers } = buildValidHeaders(ctx, 'POST', '/api/custom', body);

      const req = createExpressReq({
        headers,
        method: 'POST',
        path: '/api/custom',
        originalUrl: '/api/custom',
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(extractBody).toHaveBeenCalledOnce();
      expect(next).toHaveBeenCalledOnce();

      memStore.destroy();
    });
  });

  // ── E2E: Query String Handling ────────────────────────────────

  describe('E2E-009: Query string in URL', () => {
    it('Express: query parameters extracted from originalUrl', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('GET', '/api/search', 'q=test&page=1');
      await memStore.store(ctx);

      const buildResult = ashBuildRequest({
        nonce: ctx.nonce,
        contextId: ctx.id,
        method: 'GET',
        path: '/api/search',
        rawQuery: 'q=test&page=1',
        body: '',
      });

      const req = createExpressReq({
        headers: {
          [X_ASH_TIMESTAMP]: buildResult.timestamp,
          [X_ASH_NONCE]: buildResult.nonce,
          [X_ASH_BODY_HASH]: buildResult.bodyHash,
          [X_ASH_PROOF]: buildResult.proof,
          [X_ASH_CONTEXT_ID]: ctx.id,
        },
        method: 'GET',
        path: '/api/search',
        originalUrl: '/api/search?q=test&page=1',
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.ash.verified).toBe(true);

      buildResult.destroy();
      memStore.destroy();
    });

    it('Fastify: query and hash stripped from url', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const { instance, getHookHandler } = createFastifyMock();
      await ashFastifyPlugin(instance as any, { store: memStore });
      const handler = getHookHandler()!;

      const ctx = makeValidCtx('GET', '/api/items', 'sort=asc');
      await memStore.store(ctx);

      const buildResult = ashBuildRequest({
        nonce: ctx.nonce,
        contextId: ctx.id,
        method: 'GET',
        path: '/api/items',
        rawQuery: 'sort=asc',
        body: '',
      });

      const request: any = {
        headers: {
          [X_ASH_TIMESTAMP]: buildResult.timestamp,
          [X_ASH_NONCE]: buildResult.nonce,
          [X_ASH_BODY_HASH]: buildResult.bodyHash,
          [X_ASH_PROOF]: buildResult.proof,
          [X_ASH_CONTEXT_ID]: ctx.id,
        },
        method: 'GET',
        url: '/api/items?sort=asc#section',
        ash: undefined,
      };
      const reply = createFastifyReply();

      await handler(request, reply);

      expect(request.ash).toBeDefined();
      expect(request.ash.verified).toBe(true);

      buildResult.destroy();
      memStore.destroy();
    });
  });

  // ── E2E: Redis Store with Middleware ───────────────────────────

  describe('E2E-010: Redis store with Express middleware', () => {
    it('full flow: Redis store → Express middleware → success', async () => {
      const mockRedis = createMockRedis();
      const redisStore = new AshRedisStore({ client: mockRedis });
      const middleware = ashExpressMiddleware({ store: redisStore });

      const ctx = makeValidCtx('GET', '/api/redis-test');
      await redisStore.store(ctx);

      const { headers } = buildValidHeaders(ctx, 'GET', '/api/redis-test');

      const req = createExpressReq({
        headers,
        method: 'GET',
        path: '/api/redis-test',
        originalUrl: '/api/redis-test',
      });
      const res = createExpressRes();
      const next = vi.fn();

      await middleware(req as any, res as any, next);

      expect(next).toHaveBeenCalledOnce();
      expect(req.ash.verified).toBe(true);
      expect(req.ash.contextId).toBe(ctx.id);
    });

    it('Redis store: replay blocked after consume', async () => {
      const mockRedis = createMockRedis();
      const redisStore = new AshRedisStore({ client: mockRedis });
      const middleware = ashExpressMiddleware({ store: redisStore });

      const ctx = makeValidCtx('GET', '/api/once');
      await redisStore.store(ctx);
      const { headers } = buildValidHeaders(ctx, 'GET', '/api/once');

      // First request
      const req1 = createExpressReq({ headers, method: 'GET', path: '/api/once', originalUrl: '/api/once' });
      await middleware(req1 as any, createExpressRes() as any, vi.fn());
      expect((req1 as any).ash.verified).toBe(true);

      // Replay
      const req2 = createExpressReq({ headers, method: 'GET', path: '/api/once', originalUrl: '/api/once' });
      const res2 = createExpressRes();
      await middleware(req2 as any, res2 as any, vi.fn());
      expect(res2.statusCode).toBe(452);
    });
  });

  // ── E2E: Wrong Method/Path ────────────────────────────────────

  describe('E2E-011: Binding mismatch attacks', () => {
    it('Express: proof for GET /api/a used on GET /api/b → 460', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      // Context for /api/a
      const ctx = makeValidCtx('GET', '/api/a');
      await memStore.store(ctx);

      // Build proof for /api/a
      const { headers } = buildValidHeaders(ctx, 'GET', '/api/a');

      // Try to use it on /api/b
      const req = createExpressReq({
        headers,
        method: 'GET',
        path: '/api/b',
        originalUrl: '/api/b',
      });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      expect(res.statusCode).toBe(460);

      memStore.destroy();
    });

    it('Express: proof for GET used on POST → 460', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx = makeValidCtx('GET', '/api/test');
      await memStore.store(ctx);
      const { headers } = buildValidHeaders(ctx, 'GET', '/api/test');

      const req = createExpressReq({
        headers,
        method: 'POST', // Wrong method
        path: '/api/test',
        originalUrl: '/api/test',
      });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      expect(res.statusCode).toBe(460);

      memStore.destroy();
    });
  });

  // ── E2E: Multiple independent contexts ────────────────────────

  describe('E2E-012: Multiple concurrent contexts', () => {
    it('different contexts for different endpoints work independently', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const middleware = ashExpressMiddleware({ store: memStore });

      const ctx1 = makeValidCtx('GET', '/api/users');
      const ctx2 = makeValidCtx('POST', '/api/orders');
      await memStore.store(ctx1);
      await memStore.store(ctx2);

      const { headers: h1 } = buildValidHeaders(ctx1, 'GET', '/api/users');
      const { headers: h2 } = buildValidHeaders(ctx2, 'POST', '/api/orders');

      // Request 1
      const req1 = createExpressReq({ headers: h1, method: 'GET', path: '/api/users', originalUrl: '/api/users' });
      const next1 = vi.fn();
      await middleware(req1 as any, createExpressRes() as any, next1);
      expect(next1).toHaveBeenCalled();

      // Request 2
      const req2 = createExpressReq({ headers: h2, method: 'POST', path: '/api/orders', originalUrl: '/api/orders' });
      const next2 = vi.fn();
      await middleware(req2 as any, createExpressRes() as any, next2);
      expect(next2).toHaveBeenCalled();

      memStore.destroy();
    });
  });

  // ── E2E: Non-AshError from store ──────────────────────────────

  describe('E2E-013: Non-AshError thrown by store', () => {
    it('Express: non-AshError from consume is caught as 500', async () => {
      const badStore: AshContextStore = {
        async get() { return null; },
        async consume() { throw new TypeError('Something broke internally'); },
        async store() {},
        async cleanup() { return 0; },
      };
      const middleware = ashExpressMiddleware({ store: badStore });

      const req = createExpressReq({
        headers: { [X_ASH_CONTEXT_ID]: 'some-id' },
        method: 'GET',
        path: '/api/test',
      });
      const res = createExpressRes();
      await middleware(req as any, res as any, vi.fn());
      expect(res.statusCode).toBe(500);
      expect((res.responseBody as any).error).toBe('ASH_INTERNAL_ERROR');
    });
  });

  // ── E2E: Fastify URL parsing edge cases ───────────────────────

  describe('E2E-014: Fastify URL parsing', () => {
    it('Fastify: handles URL with only hash', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const { instance, getHookHandler } = createFastifyMock();
      await ashFastifyPlugin(instance as any, { store: memStore });
      const handler = getHookHandler()!;

      const ctx = makeValidCtx('GET', '/api/test');
      await memStore.store(ctx);
      const { headers } = buildValidHeaders(ctx, 'GET', '/api/test');

      const request: any = { headers, method: 'GET', url: '/api/test#fragment', ash: undefined };
      const reply = createFastifyReply();
      await handler(request, reply);
      expect(request.ash.verified).toBe(true);

      memStore.destroy();
    });

    it('Fastify: handles URL with query and hash', async () => {
      const memStore = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
      const { instance, getHookHandler } = createFastifyMock();
      await ashFastifyPlugin(instance as any, { store: memStore });
      const handler = getHookHandler()!;

      const ctx = makeValidCtx('GET', '/api/x', 'k=v');
      await memStore.store(ctx);

      const buildResult = ashBuildRequest({
        nonce: ctx.nonce,
        contextId: ctx.id,
        method: 'GET',
        path: '/api/x',
        rawQuery: 'k=v',
        body: '',
      });

      const request: any = {
        headers: {
          [X_ASH_TIMESTAMP]: buildResult.timestamp,
          [X_ASH_NONCE]: buildResult.nonce,
          [X_ASH_BODY_HASH]: buildResult.bodyHash,
          [X_ASH_PROOF]: buildResult.proof,
          [X_ASH_CONTEXT_ID]: ctx.id,
        },
        method: 'GET',
        url: '/api/x?k=v#hash',
        ash: undefined,
      };
      const reply = createFastifyReply();
      await handler(request, reply);
      expect(request.ash.verified).toBe(true);

      buildResult.destroy();
      memStore.destroy();
    });
  });
});

// ══════════════════════════════════════════════════════════════════
// SECTION 3: Barrel Export & Package Correctness
// ══════════════════════════════════════════════════════════════════

describe('Section 3: Barrel Export & Package Correctness', () => {
  // ── SA: Export Completeness ───────────────────────────────────

  describe('SA-PKG-001: All Layer 1 exports present', () => {
    it('exports all constants', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.ASH_SDK_VERSION).toBeDefined();
      expect(mod.ASH_SDK_VERSION).toBe('1.0.0');
      expect(mod.MAX_PAYLOAD_SIZE).toBeDefined();
      expect(mod.MAX_RECURSION_DEPTH).toBeDefined();
      expect(mod.MAX_SCOPE_FIELDS).toBeDefined();
      expect(mod.MAX_NONCE_LENGTH).toBeDefined();
      expect(mod.MIN_NONCE_HEX_CHARS).toBeDefined();
      expect(mod.MAX_BINDING_LENGTH).toBeDefined();
      expect(mod.MAX_CONTEXT_ID_LENGTH).toBeDefined();
      expect(mod.MAX_QUERY_PARAMS).toBeDefined();
      expect(mod.MAX_TIMESTAMP).toBeDefined();
      expect(mod.SHA256_HEX_LENGTH).toBeDefined();
      expect(mod.SCOPE_FIELD_DELIMITER).toBeDefined();
      expect(mod.PIPE_DELIMITER).toBeDefined();
      expect(mod.DEFAULT_MAX_TIMESTAMP_AGE_SECONDS).toBeDefined();
      expect(mod.DEFAULT_CLOCK_SKEW_SECONDS).toBeDefined();
    });

    it('exports AshError and AshErrorCode', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.AshError).toBeDefined();
      expect(mod.AshErrorCode).toBeDefined();
      expect(typeof mod.AshError).toBe('function');
      expect(mod.AshErrorCode.CTX_NOT_FOUND).toBe('ASH_CTX_NOT_FOUND');
    });

    it('exports all validation functions', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashValidateNonce).toBe('function');
      expect(typeof mod.ashValidateTimestampFormat).toBe('function');
      expect(typeof mod.ashValidateTimestamp).toBe('function');
      expect(typeof mod.ashValidateHash).toBe('function');
    });

    it('exports all canonicalization functions', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashCanonicalizeJson).toBe('function');
      expect(typeof mod.ashCanonicalizeJsonValue).toBe('function');
      expect(typeof mod.ashCanonicalizeQuery).toBe('function');
      expect(typeof mod.ashCanonicalizeUrlencoded).toBe('function');
    });

    it('exports comparison function', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashTimingSafeEqual).toBe('function');
    });

    it('exports all hashing functions', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashHashBody).toBe('function');
      expect(typeof mod.ashHashProof).toBe('function');
      expect(typeof mod.ashHashScope).toBe('function');
    });

    it('exports binding normalization', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashNormalizeBinding).toBe('function');
      expect(typeof mod.ashNormalizeBindingFromUrl).toBe('function');
    });

    it('exports basic proof functions', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashDeriveClientSecret).toBe('function');
      expect(typeof mod.ashBuildProof).toBe('function');
      expect(typeof mod.ashVerifyProof).toBe('function');
      expect(typeof mod.ashVerifyProofWithFreshness).toBe('function');
    });

    it('exports scoped proof functions', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashExtractScopedFields).toBe('function');
      expect(typeof mod.ashExtractScopedFieldsStrict).toBe('function');
      expect(typeof mod.ashBuildProofScoped).toBe('function');
      expect(typeof mod.ashVerifyProofScoped).toBe('function');
    });

    it('exports unified proof functions', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashBuildProofUnified).toBe('function');
      expect(typeof mod.ashVerifyProofUnified).toBe('function');
    });
  });

  describe('SA-PKG-002: All Layer 2 exports present', () => {
    it('exports header constants', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.X_ASH_TIMESTAMP).toBe('x-ash-ts');
      expect(mod.X_ASH_NONCE).toBe('x-ash-nonce');
      expect(mod.X_ASH_BODY_HASH).toBe('x-ash-body-hash');
      expect(mod.X_ASH_PROOF).toBe('x-ash-proof');
      expect(mod.X_ASH_CONTEXT_ID).toBe('x-ash-context-id');
    });

    it('exports ashExtractHeaders', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashExtractHeaders).toBe('function');
    });

    it('exports AshMemoryStore class', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.AshMemoryStore).toBe('function');
      const s = new mod.AshMemoryStore({ ttlSeconds: 1, cleanupIntervalSeconds: 0 });
      expect(typeof s.get).toBe('function');
      expect(typeof s.consume).toBe('function');
      expect(typeof s.store).toBe('function');
      expect(typeof s.cleanup).toBe('function');
      s.destroy();
    });

    it('exports AshRedisStore class', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.AshRedisStore).toBe('function');
    });

    it('exports AshScopePolicyRegistry class', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.AshScopePolicyRegistry).toBe('function');
      const r = new mod.AshScopePolicyRegistry();
      expect(typeof r.register).toBe('function');
      expect(typeof r.match).toBe('function');
      expect(typeof r.has).toBe('function');
      expect(typeof r.clear).toBe('function');
    });

    it('exports ashBuildRequest', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashBuildRequest).toBe('function');
    });

    it('exports ashVerifyRequest', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashVerifyRequest).toBe('function');
    });

    it('exports ashExpressMiddleware', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashExpressMiddleware).toBe('function');
    });

    it('exports ashFastifyPlugin', async () => {
      const mod = await import('../../../src/index.js');
      expect(typeof mod.ashFastifyPlugin).toBe('function');
    });
  });

  // ── AQ: Export Functional Correctness ─────────────────────────

  describe('AQ-PKG-001: Exported functions work correctly', () => {
    it('AshRedisStore can be instantiated from barrel export', async () => {
      const mod = await import('../../../src/index.js');
      const mockRedis = createMockRedis();
      const s = new mod.AshRedisStore({ client: mockRedis });
      expect(typeof s.get).toBe('function');
      expect(typeof s.consume).toBe('function');
      expect(typeof s.store).toBe('function');
      expect(typeof s.cleanup).toBe('function');
    });

    it('AshRedisStore store→get roundtrip via barrel export', async () => {
      const mod = await import('../../../src/index.js');
      const mockRedis = createMockRedis();
      const s = new mod.AshRedisStore({ client: mockRedis });
      const now = Math.floor(Date.now() / 1000);
      await s.store({
        id: 'barrel-test', nonce: 'a'.repeat(64), binding: 'GET|/|',
        clientSecret: 'b'.repeat(64), used: false, createdAt: now, expiresAt: now + 300,
      });
      const got = await s.get('barrel-test');
      expect(got).not.toBeNull();
      expect(got!.id).toBe('barrel-test');
    });

    it('AshMemoryStore and AshRedisStore share interface shape', async () => {
      const mod = await import('../../../src/index.js');
      const mockRedis = createMockRedis();
      const memStore: any = new mod.AshMemoryStore({ ttlSeconds: 1, cleanupIntervalSeconds: 0 });
      const redisStore: any = new mod.AshRedisStore({ client: mockRedis });

      // Both have same method signatures
      for (const method of ['get', 'consume', 'store', 'cleanup']) {
        expect(typeof memStore[method]).toBe('function');
        expect(typeof redisStore[method]).toBe('function');
      }

      memStore.destroy();
    });
  });

  describe('AQ-PKG-002: AshErrorCode completeness', () => {
    it('all 15 error codes are exported', async () => {
      const mod = await import('../../../src/index.js');
      const codes = Object.values(mod.AshErrorCode);
      expect(codes.length).toBe(15);
    });

    it('each error code has a unique HTTP status', async () => {
      const mod = await import('../../../src/index.js');
      const statuses = new Set<number>();
      for (const code of Object.values(mod.AshErrorCode)) {
        const err = new mod.AshError(code as any, 'test');
        statuses.add(err.httpStatus);
      }
      expect(statuses.size).toBe(15);
    });

    it('all error factory methods work', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.AshError.ctxNotFound().code).toBe('ASH_CTX_NOT_FOUND');
      expect(mod.AshError.ctxExpired().code).toBe('ASH_CTX_EXPIRED');
      expect(mod.AshError.ctxAlreadyUsed().code).toBe('ASH_CTX_ALREADY_USED');
      expect(mod.AshError.proofInvalid().code).toBe('ASH_PROOF_INVALID');
      expect(mod.AshError.proofMissing().code).toBe('ASH_PROOF_MISSING');
      expect(mod.AshError.bindingMismatch().code).toBe('ASH_BINDING_MISMATCH');
      expect(mod.AshError.canonicalizationError().code).toBe('ASH_CANONICALIZATION_ERROR');
      expect(mod.AshError.validationError('x').code).toBe('ASH_VALIDATION_ERROR');
      expect(mod.AshError.timestampInvalid('x').code).toBe('ASH_TIMESTAMP_INVALID');
      expect(mod.AshError.scopedFieldMissing('x').code).toBe('ASH_SCOPED_FIELD_MISSING');
      expect(mod.AshError.scopeMismatch('x').code).toBe('ASH_SCOPE_MISMATCH');
      expect(mod.AshError.chainBroken('x').code).toBe('ASH_CHAIN_BROKEN');
      expect(mod.AshError.internalError('x').code).toBe('ASH_INTERNAL_ERROR');
    });
  });

  describe('AQ-PKG-003: Constants correctness', () => {
    it('SHA256_HEX_LENGTH is 64', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.SHA256_HEX_LENGTH).toBe(64);
    });

    it('default timestamp age is 300 seconds', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.DEFAULT_MAX_TIMESTAMP_AGE_SECONDS).toBe(300);
    });

    it('default clock skew is 30 seconds', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.DEFAULT_CLOCK_SKEW_SECONDS).toBe(30);
    });

    it('MIN_NONCE_HEX_CHARS is 32', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.MIN_NONCE_HEX_CHARS).toBe(32);
    });

    it('MAX_NONCE_LENGTH is 512', async () => {
      const mod = await import('../../../src/index.js');
      expect(mod.MAX_NONCE_LENGTH).toBe(512);
    });

    it('header constant values match expected format', async () => {
      const mod = await import('../../../src/index.js');
      // All headers should be lowercase x-ash-*
      for (const h of [mod.X_ASH_TIMESTAMP, mod.X_ASH_NONCE, mod.X_ASH_BODY_HASH, mod.X_ASH_PROOF, mod.X_ASH_CONTEXT_ID]) {
        expect(h).toMatch(/^x-ash-[a-z-]+$/);
      }
    });
  });

  // ── FUZZ: Import from barrel ──────────────────────────────────

  describe('FUZZ-PKG-001: No unexpected exports', () => {
    it('barrel export does not leak internal modules', async () => {
      const mod = await import('../../../src/index.js');
      const keys = Object.keys(mod);
      // Should not contain internal helpers
      for (const key of keys) {
        expect(key).not.toMatch(/^_/); // No underscore-prefixed
        expect(key).not.toMatch(/hmacSha256/i); // No internal crypto
        expect(key).not.toMatch(/CONTROL_CHAR/i); // No internal regex
        expect(key).not.toMatch(/CONSUME_LUA/i); // No Lua scripts
      }
    });

    it('total export count is reasonable', async () => {
      const mod = await import('../../../src/index.js');
      const keys = Object.keys(mod);
      // Layer 1 (~30) + Layer 2 (~15) = ~45 exports
      expect(keys.length).toBeGreaterThan(30);
      expect(keys.length).toBeLessThan(80);
    });
  });

  // ── SA: Package.json Verification ─────────────────────────────

  describe('SA-PKG-003: package.json structure', () => {
    it('version is 1.2.0', async () => {
      const pkg = await import('../../../package.json');
      expect(pkg.version).toBe('1.2.0');
    });

    it('name is @3maem/ash-node-sdk', async () => {
      const pkg = await import('../../../package.json');
      expect(pkg.name).toBe('@3maem/ash-node-sdk');
    });

    it('license is Apache-2.0', async () => {
      const pkg = await import('../../../package.json');
      expect(pkg.license).toBe('Apache-2.0');
    });

    it('engines requires node >= 18', async () => {
      const pkg = await import('../../../package.json');
      expect(pkg.engines.node).toBe('>=18.0.0');
    });

    it('has no runtime dependencies', async () => {
      const pkg = await import('../../../package.json');
      expect(pkg.default?.dependencies ?? pkg.dependencies).toBeUndefined();
    });

    it('peerDependencies include express, fastify, ioredis', async () => {
      const pkg = await import('../../../package.json');
      const peers = pkg.default?.peerDependencies ?? pkg.peerDependencies;
      expect(peers.express).toBeDefined();
      expect(peers.fastify).toBeDefined();
      expect(peers.ioredis).toBeDefined();
    });

    it('all peerDependencies are optional', async () => {
      const pkg = await import('../../../package.json');
      const meta = pkg.default?.peerDependenciesMeta ?? pkg.peerDependenciesMeta;
      expect(meta.express.optional).toBe(true);
      expect(meta.fastify.optional).toBe(true);
      expect(meta.ioredis.optional).toBe(true);
    });

    it('files includes dist, LICENSE, README.md', async () => {
      const pkg = await import('../../../package.json');
      const files = pkg.default?.files ?? pkg.files;
      expect(files).toContain('dist');
      expect(files).toContain('LICENSE');
      expect(files).toContain('README.md');
    });

    it('has prepublishOnly script', async () => {
      const pkg = await import('../../../package.json');
      const scripts = pkg.default?.scripts ?? pkg.scripts;
      expect(scripts.prepublishOnly).toBeDefined();
      expect(scripts.prepublishOnly).toContain('build');
      expect(scripts.prepublishOnly).toContain('typecheck');
      expect(scripts.prepublishOnly).toContain('test');
    });

    it('exports map has import and require', async () => {
      const pkg = await import('../../../package.json');
      const exports = pkg.default?.exports ?? pkg.exports;
      expect(exports['.']).toBeDefined();
      expect(exports['.'].import).toBeDefined();
      expect(exports['.'].require).toBeDefined();
      expect(exports['.'].import.types).toContain('.d.ts');
      expect(exports['.'].require.types).toContain('.d.cts');
    });

    it('has keywords array', async () => {
      const pkg = await import('../../../package.json');
      const keywords = pkg.default?.keywords ?? pkg.keywords;
      expect(Array.isArray(keywords)).toBe(true);
      expect(keywords.length).toBeGreaterThan(5);
      expect(keywords).toContain('ash');
      expect(keywords).toContain('hmac');
      expect(keywords).toContain('express');
      expect(keywords).toContain('fastify');
    });
  });
});
