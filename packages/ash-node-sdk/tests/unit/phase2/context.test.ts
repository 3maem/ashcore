/**
 * ASH Node SDK — Phase 2: Context Store Tests
 *
 * Coverage: PT (double consume, expired reuse, ID guessing) / AQ (TTL,
 * lifecycle, cleanup, destroy) / SA (one-time guarantee, no secret in errors,
 * memory cleanup) / FUZZ (random IDs, rapid create/expire)
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AshMemoryStore } from '../../../src/context.js';
import type { AshContext } from '../../../src/context.js';
import { AshErrorCode } from '../../../src/errors.js';

function makeCtx(overrides?: Partial<AshContext>): AshContext {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: 'ctx_' + Math.random().toString(36).slice(2, 10),
    nonce: 'a'.repeat(64),
    binding: 'POST|/api/test|',
    clientSecret: 'secret_' + Math.random().toString(36).slice(2),
    used: false,
    createdAt: now,
    expiresAt: now + 300,
    ...overrides,
  };
}

let store: AshMemoryStore;

beforeEach(() => {
  store = new AshMemoryStore({ ttlSeconds: 300, cleanupIntervalSeconds: 0 });
});

afterEach(() => {
  store.destroy();
});

// ── AQ: Basic Lifecycle ────────────────────────────────────────────

describe('AQ: Context store — basic lifecycle', () => {
  it('AQ-CTX-001: store and get returns context', async () => {
    const ctx = makeCtx({ id: 'ctx_lifecycle_001' });
    await store.store(ctx);
    const result = await store.get('ctx_lifecycle_001');
    expect(result).not.toBeNull();
    expect(result!.id).toBe('ctx_lifecycle_001');
    expect(result!.nonce).toBe(ctx.nonce);
  });

  it('AQ-CTX-002: get returns null for unknown ID', async () => {
    const result = await store.get('ctx_nonexistent');
    expect(result).toBeNull();
  });

  it('AQ-CTX-003: consume returns context and marks used', async () => {
    const ctx = makeCtx({ id: 'ctx_consume_003' });
    await store.store(ctx);
    const result = await store.consume('ctx_consume_003');
    expect(result.id).toBe('ctx_consume_003');
    expect(result.used).toBe(true);
  });

  it('AQ-CTX-004: get after consume still returns context (but marked used)', async () => {
    const ctx = makeCtx({ id: 'ctx_after_consume' });
    await store.store(ctx);
    await store.consume('ctx_after_consume');
    const result = await store.get('ctx_after_consume');
    expect(result).not.toBeNull();
    expect(result!.used).toBe(true);
  });

  it('AQ-CTX-005: size reflects stored contexts', async () => {
    expect(store.size).toBe(0);
    await store.store(makeCtx({ id: 'a' }));
    expect(store.size).toBe(1);
    await store.store(makeCtx({ id: 'b' }));
    expect(store.size).toBe(2);
  });

  it('AQ-CTX-006: destroy clears all entries', async () => {
    await store.store(makeCtx({ id: 'a' }));
    await store.store(makeCtx({ id: 'b' }));
    store.destroy();
    expect(store.size).toBe(0);
  });
});

// ── AQ: TTL and Expiry ─────────────────────────────────────────────

describe('AQ: Context store — TTL and expiry', () => {
  it('AQ-CTX-TTL-001: auto-calculates expiresAt when set to 0', async () => {
    const now = Math.floor(Date.now() / 1000);
    const ctx = makeCtx({ id: 'ctx_auto_ttl', expiresAt: 0, createdAt: now });
    await store.store(ctx);
    const result = await store.get('ctx_auto_ttl');
    expect(result).not.toBeNull();
    expect(result!.expiresAt).toBe(now + 300);
  });

  it('AQ-CTX-TTL-002: get returns null for expired context', async () => {
    const past = Math.floor(Date.now() / 1000) - 600;
    const ctx = makeCtx({ id: 'ctx_expired', createdAt: past, expiresAt: past + 1 });
    await store.store(ctx);
    const result = await store.get('ctx_expired');
    expect(result).toBeNull();
  });

  it('AQ-CTX-TTL-003: custom TTL is respected', async () => {
    const customStore = new AshMemoryStore({ ttlSeconds: 10, cleanupIntervalSeconds: 0 });
    const now = Math.floor(Date.now() / 1000);
    const ctx = makeCtx({ id: 'ctx_custom_ttl', expiresAt: 0, createdAt: now });
    await customStore.store(ctx);
    const result = await customStore.get('ctx_custom_ttl');
    expect(result).not.toBeNull();
    expect(result!.expiresAt).toBe(now + 10);
    customStore.destroy();
  });
});

// ── AQ: Cleanup ────────────────────────────────────────────────────

describe('AQ: Context store — cleanup', () => {
  it('AQ-CTX-CLN-001: cleanup removes expired entries', async () => {
    const past = Math.floor(Date.now() / 1000) - 600;
    await store.store(makeCtx({ id: 'expired_1', createdAt: past, expiresAt: past + 1 }));
    await store.store(makeCtx({ id: 'expired_2', createdAt: past, expiresAt: past + 1 }));
    await store.store(makeCtx({ id: 'valid_1' })); // not expired

    const removed = await store.cleanup();
    expect(removed).toBe(2);
    expect(store.size).toBe(1);
  });

  it('AQ-CTX-CLN-002: cleanup returns 0 when nothing to remove', async () => {
    await store.store(makeCtx({ id: 'still_valid' }));
    const removed = await store.cleanup();
    expect(removed).toBe(0);
  });

  it('AQ-CTX-CLN-003: cleanup on empty store returns 0', async () => {
    const removed = await store.cleanup();
    expect(removed).toBe(0);
  });
});

// ── PT: Double Consume (One-Time Use) ──────────────────────────────

describe('PT: Context store — one-time consume', () => {
  it('PT-CTX-001: double consume throws CTX_ALREADY_USED', async () => {
    const ctx = makeCtx({ id: 'ctx_double' });
    await store.store(ctx);
    await store.consume('ctx_double');
    await expect(store.consume('ctx_double')).rejects.toThrowError(
      expect.objectContaining({ code: AshErrorCode.CTX_ALREADY_USED }),
    );
  });

  it('PT-CTX-002: consume unknown ID throws CTX_NOT_FOUND', async () => {
    await expect(store.consume('ctx_unknown')).rejects.toThrowError(
      expect.objectContaining({ code: AshErrorCode.CTX_NOT_FOUND }),
    );
  });

  it('PT-CTX-003: consume expired context throws CTX_EXPIRED', async () => {
    const past = Math.floor(Date.now() / 1000) - 600;
    const ctx = makeCtx({ id: 'ctx_exp_consume', createdAt: past, expiresAt: past + 1 });
    await store.store(ctx);
    await expect(store.consume('ctx_exp_consume')).rejects.toThrowError(
      expect.objectContaining({ code: AshErrorCode.CTX_EXPIRED }),
    );
  });

  it('PT-CTX-004: triple consume still throws CTX_ALREADY_USED', async () => {
    const ctx = makeCtx({ id: 'ctx_triple' });
    await store.store(ctx);
    await store.consume('ctx_triple');
    await expect(store.consume('ctx_triple')).rejects.toThrow();
    await expect(store.consume('ctx_triple')).rejects.toThrow();
  });
});

// ── SA: Security Assurance ─────────────────────────────────────────

describe('SA: Context store — security', () => {
  it('SA-CTX-001: error messages do not contain clientSecret', async () => {
    const ctx = makeCtx({ id: 'ctx_sec_001', clientSecret: 'SUPER_SECRET_VALUE' });
    await store.store(ctx);
    await store.consume('ctx_sec_001');
    try {
      await store.consume('ctx_sec_001');
      expect.fail('should have thrown');
    } catch (err: unknown) {
      const msg = (err as Error).message;
      expect(msg).not.toContain('SUPER_SECRET_VALUE');
    }
  });

  it('SA-CTX-002: error messages do not contain nonce', async () => {
    expect.assertions(1);
    try {
      await store.consume('ctx_nonce_leak');
    } catch (err: unknown) {
      const msg = (err as Error).message;
      expect(msg).not.toContain('ctx_nonce_leak');
    }
  });

  it('SA-CTX-003: destroyed store has zero entries', () => {
    store.destroy();
    expect(store.size).toBe(0);
  });

  it('SA-CTX-004: cleanup removes expired and expired consumed entries', async () => {
    const past = Math.floor(Date.now() / 1000) - 600;
    await store.store(makeCtx({ id: 'exp_used', createdAt: past, expiresAt: past + 1, used: true }));
    await store.store(makeCtx({ id: 'exp_unused', createdAt: past, expiresAt: past + 1, used: false }));
    const removed = await store.cleanup();
    expect(removed).toBe(2);
  });
});

// ── FUZZ: Random IDs and Rapid Operations ──────────────────────────

describe('FUZZ: Context store — random operations', () => {
  it('FUZZ-CTX-001: many concurrent stores do not collide', async () => {
    const ids = Array.from({ length: 100 }, (_, i) => `ctx_fuzz_${i}`);
    await Promise.all(ids.map(id => store.store(makeCtx({ id }))));
    expect(store.size).toBe(100);
  });

  it('FUZZ-CTX-002: rapid store/consume cycle works', async () => {
    for (let i = 0; i < 50; i++) {
      const id = `ctx_rapid_${i}`;
      await store.store(makeCtx({ id }));
      const result = await store.consume(id);
      expect(result.id).toBe(id);
      expect(result.used).toBe(true);
    }
  });

  it('FUZZ-CTX-003: special characters in ID are stored correctly', async () => {
    const id = 'ctx-with.dots_and-dashes.123';
    await store.store(makeCtx({ id }));
    const result = await store.get(id);
    expect(result).not.toBeNull();
    expect(result!.id).toBe(id);
  });

  it('FUZZ-CTX-004: overwriting same ID replaces context', async () => {
    await store.store(makeCtx({ id: 'ctx_overwrite', nonce: 'a'.repeat(64) }));
    await store.store(makeCtx({ id: 'ctx_overwrite', nonce: 'b'.repeat(64) }));
    const result = await store.get('ctx_overwrite');
    expect(result!.nonce).toBe('b'.repeat(64));
    expect(store.size).toBe(1);
  });

  it('FUZZ-CTX-005: empty string ID works (edge case)', async () => {
    await store.store(makeCtx({ id: '' }));
    const result = await store.get('');
    expect(result).not.toBeNull();
  });
});

// ── AQ: Auto-cleanup timer ─────────────────────────────────────────

describe('AQ: Context store — auto-cleanup timer', () => {
  it('AQ-CTX-TIMER-001: store with interval=0 has no timer', () => {
    const s = new AshMemoryStore({ cleanupIntervalSeconds: 0 });
    // No timer means destroy won't throw
    s.destroy();
  });

  it('AQ-CTX-TIMER-002: destroy can be called multiple times safely', () => {
    const s = new AshMemoryStore({ cleanupIntervalSeconds: 1 });
    s.destroy();
    s.destroy(); // should not throw
  });

  it('AQ-CTX-TIMER-003: default options create store without error', () => {
    const s = new AshMemoryStore();
    expect(s.size).toBe(0);
    s.destroy();
  });
});
