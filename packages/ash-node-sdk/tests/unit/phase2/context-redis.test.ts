import { describe, it, expect, beforeEach } from 'vitest';
import { AshRedisStore } from '../../../src/context-redis.js';
import type { RedisClient } from '../../../src/context-redis.js';
import type { AshContext } from '../../../src/context.js';
import { AshErrorCode } from '../../../src/errors.js';

// ── Mock Redis Client ──────────────────────────────────────────────

function createMockRedis(): RedisClient & {
  _store: Map<string, { value: string; ttl: number }>;
} {
  const store = new Map<string, { value: string; ttl: number }>();

  return {
    _store: store,

    async get(key: string) {
      const entry = store.get(key);
      if (!entry) return null;
      return entry.value;
    },

    async set(key: string, value: string, ...args: unknown[]) {
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
      const keys = Array.isArray(key) ? key : [key];
      let count = 0;
      for (const k of keys) {
        if (store.delete(k)) count++;
      }
      return count;
    },

    async eval(script: string, numkeys: number, ...args: (string | number)[]) {
      // Simulate the CONSUME_LUA script behavior
      const redisKey = args[0] as string;
      const entry = store.get(redisKey);
      if (!entry) return 'ERR:CTX_NOT_FOUND';

      const ctx = JSON.parse(entry.value);
      if (ctx.used) return 'ERR:CTX_ALREADY_USED';

      // Return original, then mark as used
      const original = entry.value;
      ctx.used = true;
      store.set(redisKey, { value: JSON.stringify(ctx), ttl: entry.ttl });
      return original;
    },
  };
}

// ── Helpers ────────────────────────────────────────────────────────

function makeCtx(overrides?: Partial<AshContext>): AshContext {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: 'ctx-test-001',
    nonce: 'a'.repeat(64),
    binding: 'GET|/api/test|',
    clientSecret: 'b'.repeat(64),
    used: false,
    createdAt: now,
    expiresAt: now + 300,
    ...overrides,
  };
}

// ── Tests ──────────────────────────────────────────────────────────

describe('AshRedisStore', () => {
  let redis: ReturnType<typeof createMockRedis>;
  let store: AshRedisStore;

  beforeEach(() => {
    redis = createMockRedis();
    store = new AshRedisStore({ client: redis });
  });

  // ── Basic Lifecycle ───────────────────────────────────────────

  describe('store + get lifecycle', () => {
    it('stores and retrieves a context', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.id).toBe(ctx.id);
      expect(got!.nonce).toBe(ctx.nonce);
      expect(got!.binding).toBe(ctx.binding);
      expect(got!.clientSecret).toBe(ctx.clientSecret);
    });

    it('returns null for nonexistent context', async () => {
      const got = await store.get('nonexistent');
      expect(got).toBeNull();
    });

    it('uses default key prefix ash:ctx:', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      expect(redis._store.has('ash:ctx:ctx-test-001')).toBe(true);
    });

    it('uses custom key prefix', async () => {
      const customStore = new AshRedisStore({ client: redis, keyPrefix: 'myapp:' });
      const ctx = makeCtx();
      await customStore.store(ctx);
      expect(redis._store.has('myapp:ctx-test-001')).toBe(true);
    });

    it('sets TTL from expiresAt when > 0', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now + 120 });
      await store.store(ctx);
      const entry = redis._store.get('ash:ctx:ctx-test-001');
      expect(entry!.ttl).toBeGreaterThan(0);
      expect(entry!.ttl).toBeLessThanOrEqual(120);
    });

    it('uses default TTL when expiresAt is 0', async () => {
      const ctx = makeCtx({ expiresAt: 0 });
      await store.store(ctx);
      const entry = redis._store.get('ash:ctx:ctx-test-001');
      expect(entry!.ttl).toBe(300); // default ttlSeconds
    });

    it('uses custom TTL', async () => {
      const customStore = new AshRedisStore({ client: redis, ttlSeconds: 60 });
      const ctx = makeCtx({ expiresAt: 0 });
      await customStore.store(ctx);
      const entry = redis._store.get('ash:ctx:ctx-test-001');
      expect(entry!.ttl).toBe(60);
    });
  });

  // ── Consume ───────────────────────────────────────────────────

  describe('consume', () => {
    it('consumes a stored context', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const consumed = await store.consume(ctx.id);
      expect(consumed.id).toBe(ctx.id);
      expect(consumed.nonce).toBe(ctx.nonce);
    });

    it('throws CTX_NOT_FOUND for missing context', async () => {
      await expect(store.consume('nonexistent')).rejects.toMatchObject({
        code: AshErrorCode.CTX_NOT_FOUND,
      });
    });

    it('throws CTX_ALREADY_USED on double consume', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      await store.consume(ctx.id);
      await expect(store.consume(ctx.id)).rejects.toMatchObject({
        code: AshErrorCode.CTX_ALREADY_USED,
      });
    });

    it('throws CTX_EXPIRED for expired context', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now - 10 });
      await store.store(ctx);
      await expect(store.consume(ctx.id)).rejects.toMatchObject({
        code: AshErrorCode.CTX_EXPIRED,
      });
    });

    it('marks context as used atomically (Lua script)', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      await store.consume(ctx.id);

      // Verify the stored value now has used=true
      const raw = await redis.get('ash:ctx:ctx-test-001');
      const parsed = JSON.parse(raw!);
      expect(parsed.used).toBe(true);
    });
  });

  // ── Cleanup and Destroy ───────────────────────────────────────

  describe('cleanup and destroy', () => {
    it('cleanup returns 0 (Redis handles expiry)', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const removed = await store.cleanup();
      expect(removed).toBe(0);
    });

    it('destroy is no-op (does not throw)', async () => {
      await expect(store.destroy()).resolves.toBeUndefined();
    });
  });

  // ── Get with expired context ──────────────────────────────────

  describe('get — expiry check', () => {
    it('returns null and deletes expired context on get()', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now - 10 });
      await store.store(ctx);

      const got = await store.get(ctx.id);
      expect(got).toBeNull();

      // Verify it was deleted from Redis
      expect(redis._store.has('ash:ctx:ctx-test-001')).toBe(false);
    });

    it('returns context when not yet expired', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx = makeCtx({ expiresAt: now + 600 });
      await store.store(ctx);

      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.id).toBe(ctx.id);
    });
  });

  // ── Penetration Tests ─────────────────────────────────────────

  describe('PT — penetration tests', () => {
    it('rejects consume on nonexistent ID (no information leak)', async () => {
      expect.assertions(2);
      try {
        await store.consume('does-not-exist-abc123');
      } catch (err: unknown) {
        const e = err as { code: string; message: string };
        expect(e.code).toBe(AshErrorCode.CTX_NOT_FOUND);
        // Ensure error message does not contain the ID
        expect(e.message).not.toContain('does-not-exist-abc123');
      }
    });

    it('cannot consume same context twice even with rapid calls', async () => {
      const ctx = makeCtx();
      await store.store(ctx);

      // First consume succeeds
      await store.consume(ctx.id);

      // All subsequent attempts fail
      for (let i = 0; i < 5; i++) {
        await expect(store.consume(ctx.id)).rejects.toMatchObject({
          code: AshErrorCode.CTX_ALREADY_USED,
        });
      }
    });

    it('handles context IDs with special characters in key prefix', async () => {
      const ctx = makeCtx({ id: 'ctx:with:colons' });
      await store.store(ctx);
      const got = await store.get('ctx:with:colons');
      expect(got).not.toBeNull();
      expect(got!.id).toBe('ctx:with:colons');
    });

    it('does not leak client secret in error messages', async () => {
      expect.assertions(1);
      const ctx = makeCtx({ clientSecret: 'supersecret123' });
      await store.store(ctx);
      await store.consume(ctx.id);

      try {
        await store.consume(ctx.id);
      } catch (err: unknown) {
        const e = err as { message: string };
        expect(e.message).not.toContain('supersecret123');
      }
    });
  });

  // ── Security Audit ────────────────────────────────────────────

  describe('SA — security audit', () => {
    it('stores all required AshContext fields', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).toHaveProperty('id');
      expect(got).toHaveProperty('nonce');
      expect(got).toHaveProperty('binding');
      expect(got).toHaveProperty('clientSecret');
      expect(got).toHaveProperty('used');
      expect(got).toHaveProperty('createdAt');
      expect(got).toHaveProperty('expiresAt');
    });

    it('implements AshContextStore interface (get, consume, store, cleanup)', () => {
      expect(typeof store.get).toBe('function');
      expect(typeof store.consume).toBe('function');
      expect(typeof store.store).toBe('function');
      expect(typeof store.cleanup).toBe('function');
    });

    it('TTL is always at least 1 second', async () => {
      const now = Math.floor(Date.now() / 1000);
      // expiresAt is 0.5s in the future — should clamp TTL to 1
      const ctx = makeCtx({ expiresAt: now });
      await store.store(ctx);
      const entry = redis._store.get('ash:ctx:ctx-test-001');
      expect(entry!.ttl).toBeGreaterThanOrEqual(1);
    });

    it('error codes match AshErrorCode enum', async () => {
      // CTX_NOT_FOUND
      await expect(store.consume('x')).rejects.toMatchObject({
        code: 'ASH_CTX_NOT_FOUND',
      });

      // CTX_ALREADY_USED
      const ctx = makeCtx();
      await store.store(ctx);
      await store.consume(ctx.id);
      await expect(store.consume(ctx.id)).rejects.toMatchObject({
        code: 'ASH_CTX_ALREADY_USED',
      });
    });
  });

  // ── FUZZ ──────────────────────────────────────────────────────

  describe('FUZZ — adversarial inputs', () => {
    it('handles empty string context ID', async () => {
      const ctx = makeCtx({ id: '' });
      await store.store(ctx);
      const got = await store.get('');
      expect(got).not.toBeNull();
    });

    it('handles very long context ID', async () => {
      const longId = 'x'.repeat(1000);
      const ctx = makeCtx({ id: longId });
      await store.store(ctx);
      const got = await store.get(longId);
      expect(got).not.toBeNull();
      expect(got!.id).toBe(longId);
    });

    it('handles Unicode context ID', async () => {
      const ctx = makeCtx({ id: 'ctx-مرحبا-🔑' });
      await store.store(ctx);
      const got = await store.get('ctx-مرحبا-🔑');
      expect(got).not.toBeNull();
    });

    it('handles many rapid store/get cycles', async () => {
      for (let i = 0; i < 100; i++) {
        const ctx = makeCtx({ id: `rapid-${i}` });
        await store.store(ctx);
      }
      for (let i = 0; i < 100; i++) {
        const got = await store.get(`rapid-${i}`);
        expect(got).not.toBeNull();
        expect(got!.id).toBe(`rapid-${i}`);
      }
    });

    it('handles context with empty nonce and binding', async () => {
      const ctx = makeCtx({ nonce: '', binding: '' });
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.nonce).toBe('');
      expect(got!.binding).toBe('');
    });

    it('handles context with special JSON characters in fields', async () => {
      const ctx = makeCtx({
        binding: 'GET|/api/"test"?foo=bar&baz=qux|',
        nonce: 'abc\ndef',
      });
      await store.store(ctx);
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.binding).toBe('GET|/api/"test"?foo=bar&baz=qux|');
    });

    it('handles consume after Redis client returns unexpected format', async () => {
      // Override eval to return garbage
      const badRedis = createMockRedis();
      const badStore = new AshRedisStore({ client: badRedis });
      // Monkey-patch eval to return something unexpected
      badRedis.eval = async () => '{"id":"x","nonce":"n","binding":"b","clientSecret":"s","used":false,"createdAt":0,"expiresAt":0}';
      // expiresAt=0 means no expiry check (the store checks > 0)
      const result = await badStore.consume('anything');
      expect(result.id).toBe('x');
    });
  });

  // ── QA ────────────────────────────────────────────────────────

  describe('QA — quality assurance', () => {
    it('multiple stores to same ID overwrites', async () => {
      const ctx1 = makeCtx({ nonce: 'first' });
      const ctx2 = makeCtx({ nonce: 'second' });
      await store.store(ctx1);
      await store.store(ctx2);
      const got = await store.get(ctx1.id);
      expect(got!.nonce).toBe('second');
    });

    it('preserves all context fields through serialize/deserialize', async () => {
      const now = Math.floor(Date.now() / 1000);
      const ctx: AshContext = {
        id: 'full-ctx',
        nonce: 'a1b2c3d4'.repeat(8),
        binding: 'POST|/api/users|name=John',
        clientSecret: 'secret'.repeat(10),
        used: false,
        createdAt: now,
        expiresAt: now + 600,
      };
      await store.store(ctx);
      const got = await store.get('full-ctx');
      expect(got).toEqual(ctx);
    });

    it('get does not modify context in store', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const got1 = await store.get(ctx.id);
      const got2 = await store.get(ctx.id);
      expect(got1).toEqual(got2);
    });

    it('consume returns context before it was marked used', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      const consumed = await store.consume(ctx.id);
      // The returned context should have used=false (original state)
      expect(consumed.used).toBe(false);
    });

    it('after consume, get still returns the context (but marked used)', async () => {
      const ctx = makeCtx();
      await store.store(ctx);
      await store.consume(ctx.id);

      // get() should still return it since Redis hasn't expired it
      const got = await store.get(ctx.id);
      expect(got).not.toBeNull();
      expect(got!.used).toBe(true);
    });
  });
});
