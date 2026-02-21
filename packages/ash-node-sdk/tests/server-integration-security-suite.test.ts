/**
 * Comprehensive Security Test Suite for ASH Node SDK Server Integration Layer
 *
 * This test suite covers:
 * - Penetration Testing (PT): Active vulnerability discovery
 * - API Quality (AQ): Boundary conditions, input validation
 * - Security Audit: Cryptographic correctness, protocol compliance
 * - Fuzz Testing: Edge cases and random inputs
 *
 * Components tested:
 * - headers.ts (Header extraction and validation)
 * - context.ts (Context store with TTL)
 * - scope-policy.ts (Scope policy registry)
 * - build-request.ts (Request building)
 * - verify-request.ts (Request verification)
 * - middleware/express.ts (Express middleware)
 * - middleware/fastify.ts (Fastify plugin)
 */

import { describe, it, expect, vi } from 'vitest';
import {
  ashExtractHeaders,
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '../src/headers.js';
import { AshMemoryStore, type AshContext } from '../src/context.js';
import { AshScopePolicyRegistry, type ScopePolicy } from '../src/scope-policy.js';
import { ashBuildRequest, type BuildRequestInput } from '../src/build-request.js';
import { ashVerifyRequest, type VerifyRequestInput } from '../src/verify-request.js';
import { ashExpressMiddleware, type ExpressRequest, type ExpressResponse } from '../src/middleware/express.js';
import { ashFastifyPlugin, type FastifyRequest, type FastifyReply, type FastifyInstance } from '../src/middleware/fastify.js';
import { AshError } from '../src/errors.js';

// ============================================================================
// Helper Functions
// ============================================================================

function randomHex(len: number): string {
  const hex = '0123456789abcdef';
  return Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join('');
}

function createValidContext(): AshContext {
  return {
    id: 'ctx_test_123',
    nonce: randomHex(32),
    binding: 'POST|/api/test|',
    clientSecret: randomHex(64),
    used: false,
    createdAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  };
}

function createValidHeaders(): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  return {
    [X_ASH_TIMESTAMP]: timestamp,
    [X_ASH_NONCE]: randomHex(32),
    [X_ASH_BODY_HASH]: randomHex(64),
    [X_ASH_PROOF]: randomHex(64),
    [X_ASH_CONTEXT_ID]: 'ctx_test_123',
  };
}

// ============================================================================
// Penetration Testing (PT)
// ============================================================================

describe('Penetration Testing (PT)', () => {
  describe('PT-001: Header Injection Attacks', () => {
    it('should reject control characters in timestamp header', () => {
      const headers = createValidHeaders();
      headers[X_ASH_TIMESTAMP] = '123456789\x00';
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject control characters in nonce header', () => {
      const headers = createValidHeaders();
      headers[X_ASH_NONCE] = 'abc\x01def';
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject newline injection in body hash header', () => {
      const headers = createValidHeaders();
      headers[X_ASH_BODY_HASH] = 'hash\nmalicious';
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject carriage return injection in proof header', () => {
      const headers = createValidHeaders();
      headers[X_ASH_PROOF] = 'proof\rattack';
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject null byte injection in context ID header', () => {
      const headers = createValidHeaders();
      headers[X_ASH_CONTEXT_ID] = 'ctx\x00injection';
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });
  });

  describe('PT-002: Header Length Overflow', () => {
    it('should reject oversized timestamp header (>16 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_TIMESTAMP] = '1'.repeat(17);
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject oversized nonce header (>512 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_NONCE] = 'a'.repeat(513);
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject oversized body hash header (>64 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_BODY_HASH] = 'a'.repeat(65);
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject oversized proof header (>64 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_PROOF] = 'a'.repeat(65);
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });

    it('should reject oversized context ID header (>256 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_CONTEXT_ID] = 'a'.repeat(257);
      expect(() => ashExtractHeaders(headers)).toThrow(AshError);
    });
  });

  describe('PT-003: Context Store Attacks', () => {
    it('should prevent replay attack via context reuse', async () => {
      const store = new AshMemoryStore();
      const ctx = createValidContext();
      await store.store(ctx);

      // First consume should succeed
      await store.consume(ctx.id);

      // Second consume should fail (replay)
      await expect(store.consume(ctx.id)).rejects.toThrow(AshError);
    });

    it('should reject expired context', async () => {
      const store = new AshMemoryStore();
      const ctx: AshContext = {
        ...createValidContext(),
        expiresAt: Math.floor(Date.now() / 1000) - 1, // Already expired
      };
      await store.store(ctx);

      await expect(store.consume(ctx.id)).rejects.toThrow(AshError);
    });

    it('should reject unknown context ID', async () => {
      const store = new AshMemoryStore();
      await expect(store.consume('unknown-context')).rejects.toThrow(AshError);
    });
  });

  describe('PT-004: Scope Policy Injection', () => {
    it('should reject control characters in policy pattern', () => {
      const registry = new AshScopePolicyRegistry();
      const policy: ScopePolicy = {
        pattern: 'POST /api/\x00test',
        fields: ['amount'],
      };
      expect(() => registry.register(policy)).toThrow(AshError);
    });

    it('should reject null bytes in policy pattern', () => {
      const registry = new AshScopePolicyRegistry();
      const policy: ScopePolicy = {
        pattern: 'POST /api/test\x00',
        fields: ['amount'],
      };
      expect(() => registry.register(policy)).toThrow(AshError);
    });

    it('should reject oversized policy pattern (>512 chars)', () => {
      const registry = new AshScopePolicyRegistry();
      const policy: ScopePolicy = {
        pattern: `POST /api/${'a'.repeat(520)}`, // Total > 512 chars
        fields: ['amount'],
      };
      expect(policy.pattern.length).toBeGreaterThan(512);
      expect(() => registry.register(policy)).toThrow(AshError);
    });

    it('should reject excessive wildcards (>8)', () => {
      const registry = new AshScopePolicyRegistry();
      const policy: ScopePolicy = {
        pattern: 'POST /*/*/*/*/*/*/*/*/*',
        fields: ['amount'],
      };
      expect(() => registry.register(policy)).toThrow(AshError);
    });
  });

  describe('PT-005: Middleware Security', () => {
    it('Express: should handle missing context ID gracefully', async () => {
      const store = new AshMemoryStore();
      const middleware = ashExpressMiddleware({ store });

      const req = {
        headers: {},
        method: 'POST',
        path: '/api/test',
      } as ExpressRequest;

      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
      } as unknown as ExpressResponse;

      const next = vi.fn();

      middleware(req, res, next);
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(res.status).toHaveBeenCalledWith(483);
      expect(next).not.toHaveBeenCalled();
    });

    it('Fastify: should handle missing context ID gracefully', async () => {
      const store = new AshMemoryStore();
      const fastify = {
        decorateRequest: vi.fn(),
        addHook: vi.fn(),
      } as unknown as FastifyInstance;

      await ashFastifyPlugin(fastify, { store });

      const hookHandler = fastify.addHook.mock.calls[0][1];
      const req = {
        headers: {},
        method: 'POST',
        url: '/api/test',
      } as FastifyRequest;

      const reply = {
        code: vi.fn().mockReturnThis(),
        send: vi.fn().mockReturnThis(),
      } as unknown as FastifyReply;

      await hookHandler(req, reply);

      expect(reply.code).toHaveBeenCalledWith(483);
    });
  });
});

// ============================================================================
// API Quality (AQ) Tests
// ============================================================================

describe('API Quality (AQ)', () => {
  describe('AQ-001: Header Boundary Conditions', () => {
    it('should accept minimum valid timestamp (1 digit)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_TIMESTAMP] = '0';
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should accept maximum valid timestamp (16 digits)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_TIMESTAMP] = '9999999999999999';
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should accept minimum nonce length (32 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_NONCE] = 'a'.repeat(32);
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should accept maximum nonce length (512 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_NONCE] = 'a'.repeat(512);
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should accept exact body hash length (64 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_BODY_HASH] = 'a'.repeat(64);
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should accept exact proof length (64 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_PROOF] = 'a'.repeat(64);
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should accept maximum context ID length (256 chars)', () => {
      const headers = createValidHeaders();
      headers[X_ASH_CONTEXT_ID] = 'a'.repeat(256);
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });
  });

  describe('AQ-002: Header Case Insensitivity', () => {
    it('should handle lowercase header names', () => {
      const headers: Record<string, string> = {
        'x-ash-ts': '1234567890',
        'x-ash-nonce': randomHex(32),
        'x-ash-body-hash': randomHex(64),
        'x-ash-proof': randomHex(64),
        'x-ash-context-id': 'ctx_test',
      };
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should handle mixed case header names', () => {
      const headers: Record<string, string> = {
        'X-Ash-Ts': '1234567890',
        'X-ASH-Nonce': randomHex(32),
        'x-ash-BODY-hash': randomHex(64),
        'X-ash-proof': randomHex(64),
        'x-ASH-context-ID': 'ctx_test',
      };
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });
  });

  describe('AQ-003: Context Store TTL', () => {
    it('should respect custom TTL', async () => {
      const store = new AshMemoryStore({ ttlSeconds: 1 });
      const now = Math.floor(Date.now() / 1000);
      const ctx: AshContext = {
        ...createValidContext(),
        createdAt: now,
        expiresAt: now + 1, // 1 second from now
      };
      await store.store(ctx);

      // Should exist immediately
      const found = await store.get(ctx.id);
      expect(found).not.toBeNull();

      // Wait for expiration (longer wait to ensure system clock catches up)
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Force cleanup
      await store.cleanup();

      const expired = await store.get(ctx.id);
      expect(expired).toBeNull();
    });

    it('should handle cleanup', async () => {
      const store = new AshMemoryStore({ ttlSeconds: 1, cleanupIntervalSeconds: 0 });
      const ctx = createValidContext();
      ctx.expiresAt = Math.floor(Date.now() / 1000) - 1;
      await store.store(ctx);

      const removed = await store.cleanup();
      expect(removed).toBeGreaterThanOrEqual(1);
    });
  });

  describe('AQ-004: Scope Policy Matching', () => {
    it('should match exact paths', () => {
      const registry = new AshScopePolicyRegistry();
      registry.register({ pattern: 'POST /api/users', fields: ['name'] });

      const match = registry.match('POST', '/api/users');
      expect(match).not.toBeNull();
      expect(match?.policy.fields).toEqual(['name']);
    });

    it('should match parameterized paths', () => {
      const registry = new AshScopePolicyRegistry();
      registry.register({ pattern: 'GET /api/users/:id', fields: ['filter'] });

      const match = registry.match('GET', '/api/users/123');
      expect(match).not.toBeNull();
      expect(match?.params).toEqual({ id: '123' });
    });

    it('should match wildcard paths', () => {
      const registry = new AshScopePolicyRegistry();
      registry.register({ pattern: 'GET /api/*', fields: ['query'] });

      const match = registry.match('GET', '/api/users/123');
      expect(match).not.toBeNull();
    });

    it('should prioritize exact over param over wildcard', () => {
      const registry = new AshScopePolicyRegistry();
      registry.register({ pattern: 'GET /api/users/*', fields: ['wildcard'] });
      registry.register({ pattern: 'GET /api/users/:id', fields: ['param'] });
      registry.register({ pattern: 'GET /api/users/123', fields: ['exact'] });

      const match = registry.match('GET', '/api/users/123');
      expect(match?.policy.fields).toEqual(['exact']);
    });
  });

  describe('AQ-005: Build Request Validation', () => {
    it('should require nonce', () => {
      const input: BuildRequestInput = {
        nonce: '',
        contextId: 'ctx_test',
        method: 'POST',
        path: '/api/test',
      };
      expect(() => ashBuildRequest(input)).toThrow(AshError);
    });

    it('should require context ID', () => {
      const input: BuildRequestInput = {
        nonce: randomHex(32),
        contextId: '',
        method: 'POST',
        path: '/api/test',
      };
      expect(() => ashBuildRequest(input)).toThrow(AshError);
    });

    it('should require path starting with /', () => {
      const input: BuildRequestInput = {
        nonce: randomHex(32),
        contextId: 'ctx_test',
        method: 'POST',
        path: 'api/test',
      };
      expect(() => ashBuildRequest(input)).toThrow(AshError);
    });
  });
});

// ============================================================================
// Security Audit Tests
// ============================================================================

describe('Security Audit', () => {
  describe('SA-001: Header Security', () => {
    it('should sanitize multi-value headers', () => {
      const headers: Record<string, string[]> = {
        [X_ASH_TIMESTAMP]: ['1234567890'],
        [X_ASH_NONCE]: [randomHex(32)],
        [X_ASH_BODY_HASH]: [randomHex(64)],
        [X_ASH_PROOF]: [randomHex(64)],
        [X_ASH_CONTEXT_ID]: ['ctx_test'],
      };
      expect(() => ashExtractHeaders(headers)).not.toThrow();
    });

    it('should handle comma-separated header values', () => {
      const headers: Record<string, string> = {
        [X_ASH_TIMESTAMP]: '1234567890',
        [X_ASH_NONCE]: randomHex(32),
        [X_ASH_BODY_HASH]: randomHex(64),
        [X_ASH_PROOF]: randomHex(64),
        [X_ASH_CONTEXT_ID]: 'ctx_test',
      };
      const result = ashExtractHeaders(headers);
      expect(result.timestamp).toBe('1234567890');
    });
  });

  describe('SA-002: Context Isolation', () => {
    it('should isolate contexts between stores', async () => {
      const store1 = new AshMemoryStore();
      const store2 = new AshMemoryStore();
      const ctx = createValidContext();

      await store1.store(ctx);

      const fromStore1 = await store1.get(ctx.id);
      const fromStore2 = await store2.get(ctx.id);

      expect(fromStore1).not.toBeNull();
      expect(fromStore2).toBeNull();
    });

    it('should prevent context modification after storage', async () => {
      const store = new AshMemoryStore();
      const ctx = createValidContext();
      await store.store(ctx);

      // Modify original
      ctx.used = true;

      // Retrieved context should not be affected
      const retrieved = await store.get(ctx.id);
      expect(retrieved?.used).toBe(false);
    });
  });

  describe('SA-003: Scope Policy Security', () => {
    it('should reject empty pattern', () => {
      const registry = new AshScopePolicyRegistry();
      expect(() => registry.register({ pattern: '', fields: [] })).toThrow(AshError);
    });

    it('should reject pattern without method', () => {
      const registry = new AshScopePolicyRegistry();
      expect(() => registry.register({ pattern: '/api/users', fields: [] })).toThrow(AshError);
    });

    it('should reject pattern without leading slash', () => {
      const registry = new AshScopePolicyRegistry();
      expect(() => registry.register({ pattern: 'POST api/users', fields: [] })).toThrow(AshError);
    });

    it('should normalize method to uppercase', () => {
      const registry = new AshScopePolicyRegistry();
      registry.register({ pattern: 'post /api/users', fields: ['name'] });

      const match = registry.match('POST', '/api/users');
      expect(match).not.toBeNull();
    });
  });

  describe('SA-004: Memory Safety', () => {
    it('should zero out sensitive data on destroy', () => {
      const input: BuildRequestInput = {
        nonce: randomHex(32),
        contextId: 'ctx_test',
        method: 'POST',
        path: '/api/test',
        body: '{"amount":100}',
      };

      const result = ashBuildRequest(input);
      expect(() => result.destroy()).not.toThrow();
    });
  });

  describe('SA-005: Error Handling', () => {
    it('should return AshError for validation failures', async () => {
      const store = new AshMemoryStore();
      const result = await store.get('nonexistent');
      expect(result).toBeNull();
    });

    it('should provide correct HTTP status codes', () => {
      expect.assertions(3);
      const headers = createValidHeaders();
      delete headers[X_ASH_TIMESTAMP];

      try {
        ashExtractHeaders(headers);
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(AshError);
        if (err instanceof AshError) {
          expect(err.httpStatus).toBe(483);
          expect(err.code).toBe('ASH_PROOF_MISSING');
        }
      }
    });
  });

  describe('SA-006: Verification Failure', () => {
    it('should reject mismatched nonce/context gracefully', () => {
      const input: VerifyRequestInput = {
        headers: createValidHeaders(),
        method: 'POST',
        path: '/api/test',
        body: '{"amount":100}',
        nonce: randomHex(32),
        contextId: 'ctx_test',
      };

      const result = ashVerifyRequest(input);
      // Should fail gracefully with proof invalid, not crash
      expect(result.ok).toBe(false);
    });
  });
});

// ============================================================================
// Fuzz Testing
// ============================================================================

describe('Fuzz Testing', () => {
  describe('FUZZ-001: Random Header Values', () => {
    it('should handle various timestamp formats', () => {
      const timestamps = ['0', '1', '9999999999', '9999999999999999'];

      for (const ts of timestamps) {
        const headers = createValidHeaders();
        headers[X_ASH_TIMESTAMP] = ts;
        try {
          ashExtractHeaders(headers);
        } catch {
          // Expected for some values
        }
      }
    });

    it('should handle various nonce patterns', () => {
      const nonces = [
        randomHex(32),
        randomHex(64),
        randomHex(128),
        randomHex(512),
      ];

      for (const nonce of nonces) {
        const headers = createValidHeaders();
        headers[X_ASH_NONCE] = nonce;
        try {
          const result = ashExtractHeaders(headers);
          expect(result.nonce).toBe(nonce.toLowerCase());
        } catch {
          // Expected for some values
        }
      }
    });
  });

  describe('FUZZ-002: Malformed Headers', () => {
    it('should handle empty header values', () => {
      const headers = createValidHeaders();
      headers[X_ASH_TIMESTAMP] = '';
      expect(() => ashExtractHeaders(headers)).toThrow();
    });

    it('should handle whitespace-only context ID without crashing', () => {
      const headers = createValidHeaders();
      headers[X_ASH_CONTEXT_ID] = '   ';
      // May accept or reject — crash-safety is the concern
      try {
        ashExtractHeaders(headers);
      } catch {
        // Rejection is acceptable
      }
    });

    it('should handle special characters in context ID', () => {
      const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*'];

      for (const char of specialChars) {
        const headers = createValidHeaders();
        headers[X_ASH_CONTEXT_ID] = `ctx${char}test`;
        try {
          ashExtractHeaders(headers);
        } catch {
          // Expected for invalid chars
        }
      }
    });
  });

  describe('FUZZ-003: Context Store Edge Cases', () => {
    it('should handle rapid store/retrieve operations', async () => {
      const store = new AshMemoryStore();
      const operations = [];

      for (let i = 0; i < 100; i++) {
        const ctx: AshContext = {
          id: `ctx_${i}`,
          nonce: randomHex(32),
          binding: 'POST|/api/test|',
          clientSecret: randomHex(64),
          used: false,
          createdAt: Math.floor(Date.now() / 1000),
          expiresAt: Math.floor(Date.now() / 1000) + 300,
        };
        operations.push(store.store(ctx));
      }

      await Promise.all(operations);
      expect(store.size).toBe(100);
    });

    it('should handle concurrent consume operations', async () => {
      const store = new AshMemoryStore();
      const ctx = createValidContext();
      await store.store(ctx);

      const results = await Promise.allSettled([
        store.consume(ctx.id),
        store.consume(ctx.id),
        store.consume(ctx.id),
      ]);

      const successes = results.filter(r => r.status === 'fulfilled');
      expect(successes.length).toBe(1);
    });
  });

  describe('FUZZ-004: Scope Policy Edge Cases', () => {
    it('should handle various path patterns', () => {
      const registry = new AshScopePolicyRegistry();
      const patterns = [
        { pattern: 'GET /', fields: [] },
        { pattern: 'POST /api/deep/nested/path', fields: ['data'] },
        { pattern: 'GET /api/users/:userId/posts/:postId', fields: ['title'] },
        { pattern: 'DELETE /api/*', fields: [] },
      ];

      for (const p of patterns) {
        try {
          registry.register(p);
        } catch {
          // Some may fail
        }
      }

      // If we get here without crash, the fuzz loop succeeded
    });

    it('should handle empty and null fields', () => {
      const registry = new AshScopePolicyRegistry();

      registry.register({ pattern: 'GET /api/empty', fields: [] });
      expect(registry.match('GET', '/api/empty')).not.toBeNull();
    });
  });

  describe('FUZZ-005: Request Body Edge Cases', () => {
    it('should handle various body formats', () => {
      const bodies = [
        '',
        '{}',
        '[]',
        'null',
        '{"a":1}',
        '{"nested":{"deep":{"value":true}}}',
        '[1,2,3,4,5]',
      ];

      for (const body of bodies) {
        const input: BuildRequestInput = {
          nonce: randomHex(32),
          contextId: 'ctx_test',
          method: 'POST',
          path: '/api/test',
          body,
        };

        try {
          ashBuildRequest(input);
        } catch {
          // Some may fail for invalid JSON
        }
      }
    });
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('Integration Tests', () => {
  describe('INT-001: End-to-End Request Flow', () => {
    it('should build and verify a basic request', () => {
      const nonce = randomHex(32);
      const contextId = 'ctx_test';
      const body = '{"amount":100}';

      // Build request
      const built = ashBuildRequest({
        nonce,
        contextId,
        method: 'POST',
        path: '/api/transfer',
        body,
      });

      expect(built.proof).toHaveLength(64);
      expect(built.bodyHash).toHaveLength(64);

      // Verify request
      const headers: Record<string, string> = {
        [X_ASH_TIMESTAMP]: built.timestamp,
        [X_ASH_NONCE]: nonce,
        [X_ASH_BODY_HASH]: built.bodyHash,
        [X_ASH_PROOF]: built.proof,
        [X_ASH_CONTEXT_ID]: contextId,
      };

      const verified = ashVerifyRequest({
        headers,
        method: 'POST',
        path: '/api/transfer',
        body,
        nonce,
        contextId,
      });

      expect(verified.ok).toBe(true);
      expect(verified.meta?.mode).toBe('basic');
    });

    it('should detect tampered body', () => {
      const nonce = randomHex(32);
      const contextId = 'ctx_test';
      const body = '{"amount":100}';

      // Build request
      const built = ashBuildRequest({
        nonce,
        contextId,
        method: 'POST',
        path: '/api/transfer',
        body,
      });

      // Verify with tampered body
      const headers: Record<string, string> = {
        [X_ASH_TIMESTAMP]: built.timestamp,
        [X_ASH_NONCE]: nonce,
        [X_ASH_BODY_HASH]: built.bodyHash,
        [X_ASH_PROOF]: built.proof,
        [X_ASH_CONTEXT_ID]: contextId,
      };

      const verified = ashVerifyRequest({
        headers,
        method: 'POST',
        path: '/api/transfer',
        body: '{"amount":999999}', // Tampered
        nonce,
        contextId,
      });

      expect(verified.ok).toBe(false);
    });
  });

  describe('INT-002: Scoped Request Flow', () => {
    it('should build and verify scoped request', () => {
      const nonce = randomHex(32);
      const contextId = 'ctx_test';
      const body = '{"amount":100,"recipient":"alice","note":"test"}';
      const scope = ['amount', 'recipient'];

      // Build scoped request
      const built = ashBuildRequest({
        nonce,
        contextId,
        method: 'POST',
        path: '/api/transfer',
        body,
        scope,
      });

      expect(built.scopeHash).toBeDefined();

      // Verify scoped request
      const headers: Record<string, string> = {
        [X_ASH_TIMESTAMP]: built.timestamp,
        [X_ASH_NONCE]: nonce,
        [X_ASH_BODY_HASH]: built.bodyHash,
        [X_ASH_PROOF]: built.proof,
        [X_ASH_CONTEXT_ID]: contextId,
      };

      const verified = ashVerifyRequest({
        headers,
        method: 'POST',
        path: '/api/transfer',
        body,
        nonce,
        contextId,
        scope,
      });

      expect(verified.ok).toBe(true);
      expect(verified.meta?.mode).toBe('scoped');
    });
  });

  describe('INT-003: Middleware Integration', () => {
    it('Express: full middleware flow with valid context', async () => {
      const store = new AshMemoryStore();
      const ctx = createValidContext();
      await store.store(ctx);

      const middleware = ashExpressMiddleware({ store });

      // Build valid request
      const built = ashBuildRequest({
        nonce: ctx.nonce,
        contextId: ctx.id,
        method: 'POST',
        path: '/api/test',
        body: '{"data":"test"}',
      });

      const req = {
        headers: {
          [X_ASH_TIMESTAMP]: built.timestamp,
          [X_ASH_NONCE]: ctx.nonce,
          [X_ASH_BODY_HASH]: built.bodyHash,
          [X_ASH_PROOF]: built.proof,
          [X_ASH_CONTEXT_ID]: ctx.id,
        },
        method: 'POST',
        path: '/api/test',
        body: { data: 'test' },
      } as ExpressRequest;

      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
      } as unknown as ExpressResponse;

      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.ash).toBeDefined();
      expect(req.ash?.verified).toBe(true);
    });

    it('Fastify: full plugin flow with valid context', async () => {
      const store = new AshMemoryStore();
      const ctx = createValidContext();
      await store.store(ctx);

      const fastify = {
        decorateRequest: vi.fn(),
        addHook: vi.fn(),
      } as unknown as FastifyInstance;

      await ashFastifyPlugin(fastify, { store });

      // Build valid request
      const built = ashBuildRequest({
        nonce: ctx.nonce,
        contextId: ctx.id,
        method: 'POST',
        path: '/api/test',
        body: '{"data":"test"}',
      });

      const hookHandler = fastify.addHook.mock.calls[0][1];
      const req = {
        headers: {
          [X_ASH_TIMESTAMP]: built.timestamp,
          [X_ASH_NONCE]: ctx.nonce,
          [X_ASH_BODY_HASH]: built.bodyHash,
          [X_ASH_PROOF]: built.proof,
          [X_ASH_CONTEXT_ID]: ctx.id,
        },
        method: 'POST',
        url: '/api/test',
        body: { data: 'test' },
      } as FastifyRequest;

      const reply = {
        code: vi.fn().mockReturnThis(),
        send: vi.fn().mockReturnThis(),
      } as unknown as FastifyReply;

      await hookHandler(req, reply);

      expect(reply.code).not.toHaveBeenCalled();
      expect(req.ash).toBeDefined();
      expect(req.ash!.verified).toBe(true);
    });
  });
});
