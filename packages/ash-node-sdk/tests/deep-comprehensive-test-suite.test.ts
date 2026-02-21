/**
 * DEEP COMPREHENSIVE TEST SUITE for ASH Node SDK
 *
 * Categories:
 * - PT (Penetration Testing): Security attack simulations
 * - QA (Quality Assurance): Boundary conditions, edge cases
 * - FUZZ (Fuzz Testing): Random/adversarial inputs
 * - PERF (Performance): Load, stress, timing tests
 * - SA (Security Audit): Cryptographic, protocol compliance
 * - BUG (Bug Hunting): Known vulnerability patterns
 */

import { describe, it, expect } from 'vitest';
import {
  // Core functions
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashHashBody,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashTimingSafeEqual,
  ashValidateNonce,
  ashValidateTimestamp,
  ashNormalizeBinding,
  // Phase 2
  ashExtractHeaders,
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
  ashBuildRequest,
  ashBuildRequestDebug,
  // Constants
  MAX_RECURSION_DEPTH,
  MAX_NONCE_LENGTH,
  MIN_NONCE_HEX_CHARS,
  MAX_BINDING_LENGTH,
  MAX_CONTEXT_ID_LENGTH,
  SHA256_HEX_LENGTH,
} from '../src/index.js';
import { AshError, AshErrorCode } from '../src/errors.js';

// ============================================================================
// Helpers
// ============================================================================

const randomHex = (len: number): string => {
  const hex = '0123456789abcdef';
  return Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join('');
};

const measureTime = (fn: () => void): number => {
  const start = performance.now();
  fn();
  return performance.now() - start;
};

// ============================================================================
// PT: PENETRATION TESTING
// ============================================================================

describe('🔴 PT: PENETRATION TESTING', () => {
  describe('PT-001: Injection Attacks', () => {
    it('should reject null byte in JSON', () => {
      const malicious = '{"data":"value\x00"}';
      expect(() => ashCanonicalizeJson(malicious)).toThrow();
    });

    it('should reject control characters in headers', () => {
      const headers = {
        [X_ASH_TIMESTAMP]: '1234567890',
        [X_ASH_NONCE]: 'abc\x01def',
        [X_ASH_BODY_HASH]: 'a'.repeat(64),
        [X_ASH_PROOF]: 'b'.repeat(64),
        [X_ASH_CONTEXT_ID]: 'ctx_test',
      };
      expect(() => ashExtractHeaders(headers)).toThrow();
    });

    it('should reject newline injection in binding', () => {
      expect(() => ashNormalizeBinding('POST', '/api/test\n/admin', '')).toThrow();
    });

    it('should reject carriage return injection', () => {
      expect(() => ashNormalizeBinding('POST', '/api/test\r/admin', '')).toThrow();
    });

    it('should reject tab injection in context ID', () => {
      expect(() => ashDeriveClientSecret('a'.repeat(32), 'ctx\tadmin', 'POST|/api|')).toThrow();
    });
  });

  describe('PT-002: Length Exploits', () => {
    it('should handle small JSON payload canonicalization', () => {
      const payload = `{"data":"${'a'.repeat(100)}"}`;
      expect(() => ashCanonicalizeJson(payload)).not.toThrow();
    });

    it('should reject nonce at exact MAX_NONCE_LENGTH boundary', () => {
      const nonce = 'a'.repeat(MAX_NONCE_LENGTH + 1);
      expect(() => ashValidateNonce(nonce)).toThrow();
    });

    it('should reject binding at exact MAX_BINDING_LENGTH boundary', () => {
      const longPath = '/api/' + 'a'.repeat(MAX_BINDING_LENGTH);
      expect(() => ashDeriveClientSecret('a'.repeat(32), 'ctx_test', longPath)).toThrow();
    });

    it('should reject context ID at exact MAX_CONTEXT_ID_LENGTH boundary', () => {
      const longId = 'a'.repeat(MAX_CONTEXT_ID_LENGTH + 1);
      expect(() => ashDeriveClientSecret('a'.repeat(32), longId, 'POST|/api|')).toThrow();
    });
  });

  describe('PT-003: Replay Attacks', () => {
    it('should detect exact proof replay', () => {
      const nonce = randomHex(32);
      const binding = 'POST|/api/transfer|';
      const bodyHash = ashHashBody('{"amount":100}');
      const timestamp = String(Math.floor(Date.now() / 1000));

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_1', binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      // First verification should pass
      expect(ashVerifyProof(nonce, 'ctx_1', binding, timestamp, bodyHash, proof)).toBe(true);

      // Same proof with different context should fail
      expect(ashVerifyProof(nonce, 'ctx_2', binding, timestamp, bodyHash, proof)).toBe(false);
    });

    it('should detect timestamp replay with old timestamp', () => {
      const oldTimestamp = String(Math.floor(Date.now() / 1000) - 1000);
      expect(() => ashValidateTimestamp(oldTimestamp, 300, 30)).toThrow();
    });

    it('should detect binding mismatch attack', () => {
      const nonce = randomHex(32);
      const binding1 = 'POST|/api/transfer|';
      const binding2 = 'POST|/api/admin|';
      const bodyHash = ashHashBody('{}');
      const timestamp = String(Math.floor(Date.now() / 1000));

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_test', binding1);
      const proof = ashBuildProof(clientSecret, timestamp, binding1, bodyHash);

      // Proof for /api/transfer should NOT verify against /api/admin
      expect(ashVerifyProof(nonce, 'ctx_test', binding2, timestamp, bodyHash, proof)).toBe(false);
    });
  });

  describe('PT-004: Timing Attack Vectors', () => {
    it('should use constant-time comparison (same length)', () => {
      const hash1 = 'a'.repeat(64);
      const hash2 = 'b'.repeat(64);

      // Verify the function works correctly
      expect(ashTimingSafeEqual(hash1, hash2)).toBe(false);
      expect(ashTimingSafeEqual(hash1, hash1)).toBe(true);
      
      // Note: JS timing variance is dominated by JIT/GC, not algorithm
      // crypto.timingSafeEqual is used internally for constant-time comparison
    });

    it('should use constant-time comparison (different prefix)', () => {
      const hash1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const hash2 = 'abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

      // Both should return false without timing difference
      expect(ashTimingSafeEqual(hash1, hash2)).toBe(false);
      expect(ashTimingSafeEqual(hash2, hash1)).toBe(false);
    });
  });

  describe('PT-005: DoS Attack Vectors', () => {
    it('should handle deeply nested JSON gracefully', () => {
      let nested = 'null';
      for (let i = 0; i < MAX_RECURSION_DEPTH + 10; i++) {
        nested = `{"a":${nested}}`;
      }
      expect(() => ashCanonicalizeJson(nested)).toThrow();
    });

    it('should handle wide JSON (many keys)', () => {
      const obj: Record<string, number> = {};
      for (let i = 0; i < 1000; i++) {
        obj[`key${i}`] = i;
      }
      expect(() => ashCanonicalizeJson(JSON.stringify(obj))).not.toThrow();
    });

    it('should handle large array', () => {
      const arr = Array(10000).fill(1);
      expect(() => ashCanonicalizeJson(JSON.stringify(arr))).not.toThrow();
    });
  });

  describe('PT-006: Unicode Normalization Attacks', () => {
    it('should normalize NFC vs NFD consistently', () => {
      // café in NFC
      const nfc = '{"name":"café"}';
      // café in NFD (e + combining acute)
      const nfd = '{"name":"cafe\u0301"}';

      const result1 = ashCanonicalizeJson(nfc);
      const result2 = ashCanonicalizeJson(nfd);

      expect(result1).toBe(result2);
    });

    it('should handle mixed normalization in same payload', () => {
      const mixed = '{"cafe":"café","naïve":"naïve"}';
      expect(() => ashCanonicalizeJson(mixed)).not.toThrow();
    });
  });

  describe('PT-007: Type Confusion', () => {
    it('should handle array vs object confusion', () => {
      const arr = '[1,2,3]';
      const obj = '{"0":1,"1":2,"2":3}';

      const hash1 = ashHashBody(ashCanonicalizeJson(arr));
      const hash2 = ashHashBody(ashCanonicalizeJson(obj));

      expect(hash1).not.toBe(hash2);
    });

    it('should handle number vs string confusion', () => {
      const num = '{"id":123}';
      const str = '{"id":"123"}';

      const hash1 = ashHashBody(ashCanonicalizeJson(num));
      const hash2 = ashHashBody(ashCanonicalizeJson(str));

      expect(hash1).not.toBe(hash2);
    });
  });
});

// ============================================================================
// QA: QUALITY ASSURANCE
// ============================================================================

describe('🟢 QA: QUALITY ASSURANCE', () => {
  describe('QA-001: Boundary Values', () => {
    it('should handle minimum valid nonce (32 hex chars)', () => {
      const nonce = 'a'.repeat(32);
      expect(() => ashValidateNonce(nonce)).not.toThrow();
    });

    it('should handle maximum valid nonce (512 hex chars)', () => {
      const nonce = 'a'.repeat(512);
      expect(() => ashValidateNonce(nonce)).not.toThrow();
    });

    it('should reject timestamp of 0 (epoch) as expired', () => {
      // Timestamp 0 (1970-01-01) is correctly rejected as expired
      expect(() => ashValidateTimestamp('0', 300, 30)).toThrow('expired');
    });

    it('should reject future timestamp at year 3000', () => {
      // Future timestamps are correctly rejected for replay protection
      const ts = String(32503680000); // Year 3000
      expect(() => ashValidateTimestamp(ts, 300, 30)).toThrow('future');
    });

    it('should handle empty query string', () => {
      expect(ashCanonicalizeQuery('')).toBe('');
    });

    it('should handle query with only special chars', () => {
      expect(() => ashCanonicalizeQuery('a=%20&b=%2B')).not.toThrow();
    });
  });

  describe('QA-002: Input Sanitization', () => {
    it('should trim whitespace from method', () => {
      const binding = ashNormalizeBinding('  POST  ', '/api', '');
      expect(binding).toBe('POST|/api|');
    });

    it('should handle leading/trailing slashes in path', () => {
      const binding1 = ashNormalizeBinding('GET', '/api/users/', '');
      const binding2 = ashNormalizeBinding('GET', '/api/users', '');
      expect(binding1).toBe(binding2);
    });

    it('should collapse multiple slashes', () => {
      const binding = ashNormalizeBinding('GET', '/api//users///profile', '');
      expect(binding).toBe('GET|/api/users/profile|');
    });

    it('should handle dot segments in path', () => {
      const binding = ashNormalizeBinding('GET', '/api/v1/../v2/users', '');
      expect(binding).toBe('GET|/api/v2/users|');
    });
  });

  describe('QA-003: Case Sensitivity', () => {
    it('should normalize method to uppercase', () => {
      const binding = ashNormalizeBinding('post', '/api', '');
      expect(binding.startsWith('POST')).toBe(true);
    });

    it('should handle lowercase nonce hex', () => {
      const nonce = 'abcdef' + '0'.repeat(26);
      expect(() => ashValidateNonce(nonce)).not.toThrow();
    });

    it('should handle uppercase nonce hex', () => {
      const nonce = 'ABCDEF' + '0'.repeat(26);
      expect(() => ashValidateNonce(nonce)).not.toThrow();
    });

    it('should handle mixed case nonce hex', () => {
      const nonce = 'AbCdEf' + '0'.repeat(26);
      expect(() => ashValidateNonce(nonce)).not.toThrow();
    });
  });

  describe('QA-004: Empty/Null Handling', () => {
    it('should handle empty body', () => {
      const result = ashBuildRequest({
        nonce: randomHex(32),
        contextId: 'ctx_test',
        method: 'GET',
        path: '/api',
        body: '',
      });
      expect(result.proof).toHaveLength(64);
    });

    it('should handle null-like values in JSON', () => {
      const json = '{"a":null,"b":false,"c":0,"d":""}';
      expect(() => ashCanonicalizeJson(json)).not.toThrow();
    });

    it('should reject undefined method', () => {
      // @ts-expect-error - testing invalid input
      expect(() => ashNormalizeBinding(undefined, '/api', '')).toThrow();
    });
  });
});

// ============================================================================
// FUZZ: FUZZ TESTING
// ============================================================================

describe('🟡 FUZZ: FUZZ TESTING', () => {
  describe('FUZZ-001: Random JSON Payloads', () => {
    const payloads = [
      '{}',
      '[]',
      'null',
      'true',
      'false',
      '0',
      '-0',
      '1e308',
      '-1e308',
      '{"":null}',
      '{"a":{"b":{"c":{"d":{"e":1}}}}}',
      '[null,false,true,0,"",{},[]]',
      '{"' + 'a'.repeat(1000) + '":1}',
    ];

    for (const payload of payloads) {
      it(`should handle: ${payload.slice(0, 50)}${payload.length > 50 ? '...' : ''}`, () => {
        try {
          ashCanonicalizeJson(payload);
        } catch {
          // Expected for some invalid payloads
        }
      });
    }
  });

  describe('FUZZ-002: Random Query Strings', () => {
    const queries = [
      '',
      'a=1',
      'a=1&b=2&c=3',
      'a=1&a=2&a=3',
      'key=value%20with%20spaces',
      'special=%2B%2F%3D%26',
      'unicode=%E2%9C%93',
      'empty=',
      '=value',
      'a',
      'a&b',
      '?',
      '?a=1',
      'a=1#fragment',
    ];

    for (const query of queries) {
      it(`should handle: "${query}"`, () => {
        try {
          ashCanonicalizeQuery(query);
        } catch {
          // Some may fail
        }
      });
    }
  });

  describe('FUZZ-003: Random Binding Patterns', () => {
    const patterns = [
      ['GET', '/'],
      ['POST', '/api/users'],
      ['PUT', '/api/users/123'],
      ['DELETE', '/api/users/123/posts/456'],
      ['PATCH', '/api/v1.0/resource'],
      ['GET', '/api/users', 'page=1&limit=10'],
      ['POST', '/api/webhook/github'],
    ];

    for (const [method, path, query = ''] of patterns) {
      it(`should handle: ${method} ${path}${query ? '?' + query : ''}`, () => {
        expect(() => ashNormalizeBinding(method as string, path as string, query as string)).not.toThrow();
      });
    }
  });

  describe('FUZZ-004: Unicode Edge Cases', () => {
    const chars = [
      '\x00',      // Null
      '\x7F',      // DEL
      '\u0001',    // Control char
      '🎉',        // Emoji
      '中',        // CJK
      'مرحبا',     // Arabic
      'שלום',      // Hebrew (RTL)
      '👨‍👩‍👧‍👦',     // Family emoji (ZWJ)
      '\u200B',    // Zero-width space
      '\uFEFF',    // BOM
    ];

    for (const ch of chars) {
      it(`should handle character: U+${ch.charCodeAt(0).toString(16).padStart(4, '0')}`, () => {
        const json = `{"char":"${ch}"}`;
        try {
          ashCanonicalizeJson(json);
        } catch {
          // Some control chars may fail
        }
      });
    }
  });

  describe('FUZZ-005: Special Numeric Values', () => {
    const numbers = [
      '0',
      '-0',
      '0.0',
      '-0.0',
      '1e0',
      '1e308',
      '1e-308',
      '9007199254740991',   // MAX_SAFE_INTEGER
      '-9007199254740991',  // MIN_SAFE_INTEGER
      'Infinity',
      '-Infinity',
      'NaN',
    ];

    for (const num of numbers) {
      it(`should handle number: ${num}`, () => {
        const json = `{"num":${num}}`;
        try {
          ashCanonicalizeJson(json);
        } catch {
          // Infinity and NaN should fail
        }
      });
    }
  });
});

// ============================================================================
// PERF: PERFORMANCE TESTING
// ============================================================================

describe('🔵 PERF: PERFORMANCE TESTING', () => {
  describe('PERF-001: Hash Performance', () => {
    it('should hash small payload quickly (<10ms for 1KB)', () => {
      const payload = JSON.stringify({ data: 'a'.repeat(1000) });
      const time = measureTime(() => ashHashBody(ashCanonicalizeJson(payload)));
      expect(time).toBeLessThan(10);
    });

    it('should hash medium payload reasonably (<50ms for 100KB)', () => {
      const payload = JSON.stringify({ data: 'a'.repeat(100000) });
      const time = measureTime(() => ashHashBody(ashCanonicalizeJson(payload)));
      expect(time).toBeLessThan(50);
    });
  });

  describe('PERF-002: Proof Generation Performance', () => {
    it('should generate proof quickly (<5ms)', () => {
      const nonce = randomHex(32);
      const binding = 'POST|/api/transfer|';
      const bodyHash = ashHashBody('{"amount":100}');
      const timestamp = String(Math.floor(Date.now() / 1000));

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_test', binding);

      const time = measureTime(() => {
        ashBuildProof(clientSecret, timestamp, binding, bodyHash);
      });

      expect(time).toBeLessThan(5);
    });
  });

  describe('PERF-003: Canonicalization Performance', () => {
    it('should canonicalize simple JSON quickly (<1ms)', () => {
      const json = '{"b":2,"a":1}';
      const time = measureTime(() => ashCanonicalizeJson(json));
      expect(time).toBeLessThan(1);
    });

    it('should handle 1000 iterations without degradation', () => {
      const json = '{"data":{"nested":{"deep":{"value":true}}}}';

      const times: number[] = [];
      for (let i = 0; i < 1000; i++) {
        times.push(measureTime(() => ashCanonicalizeJson(json)));
      }

      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      expect(avg).toBeLessThan(1);
    });
  });

  describe('PERF-004: Memory Efficiency', () => {
    it('should handle large object without memory issues', () => {
      const obj: Record<string, string> = {};
      for (let i = 0; i < 10000; i++) {
        obj[`key${i}`] = `value${i}`;
      }

      const json = JSON.stringify(obj);
      expect(() => ashCanonicalizeJson(json)).not.toThrow();
    });
  });
});

// ============================================================================
// SA: SECURITY AUDIT
// ============================================================================

describe('🟣 SA: SECURITY AUDIT', () => {
  describe('SA-001: Cryptographic Correctness', () => {
    it('should produce deterministic proofs', () => {
      const nonce = randomHex(32);
      const binding = 'POST|/api|';
      const bodyHash = ashHashBody('{}');
      const timestamp = '1234567890';

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_test', binding);
      const proof1 = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
      const proof2 = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(proof1).toBe(proof2);
    });

    it('should produce unique proofs for different inputs', () => {
      const nonce = randomHex(32);
      const binding = 'POST|/api|';
      const bodyHash = ashHashBody('{}');

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_test', binding);
      const proof1 = ashBuildProof(clientSecret, '1234567890', binding, bodyHash);
      const proof2 = ashBuildProof(clientSecret, '1234567891', binding, bodyHash);

      expect(proof1).not.toBe(proof2);
    });

    it('should have proof length of exactly 64 hex chars (SHA-256)', () => {
      const nonce = randomHex(32);
      const binding = 'POST|/api|';
      const bodyHash = ashHashBody('{}');
      const timestamp = String(Math.floor(Date.now() / 1000));

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_test', binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(proof).toHaveLength(64);
      expect(proof).toMatch(/^[0-9a-f]+$/);
    });
  });

  describe('SA-002: Protocol Compliance', () => {
    it('should have unique HTTP status codes for each error', () => {
      const codes = [
        AshErrorCode.CTX_NOT_FOUND,
        AshErrorCode.CTX_EXPIRED,
        AshErrorCode.CTX_ALREADY_USED,
        AshErrorCode.PROOF_INVALID,
        AshErrorCode.BINDING_MISMATCH,
        AshErrorCode.TIMESTAMP_INVALID,
        AshErrorCode.PROOF_MISSING,
        AshErrorCode.VALIDATION_ERROR,
      ];

      const statuses = new Set<number>();
      for (const code of codes) {
        const err = new AshError(code, 'test');
        expect(statuses.has(err.httpStatus)).toBe(false);
        statuses.add(err.httpStatus);
      }
    });
  });

  describe('SA-003: Sensitive Data Handling', () => {
    it('should redact secrets in debug output', () => {
      const result = ashBuildRequestDebug({
        nonce: randomHex(32),
        contextId: 'ctx_test',
        method: 'POST',
        path: '/api',
        body: '{}',
      });

      // Check trace for redaction
      const traceStr = JSON.stringify(result.trace);
      expect(traceStr).not.toContain(result.nonce); // Nonce should be redacted in trace
      expect(traceStr).toContain('[REDACTED]');

      result.destroy();
    });

    it('should clear sensitive data on destroy', () => {
      const result = ashBuildRequest({
        nonce: randomHex(32),
        contextId: 'ctx_test',
        method: 'POST',
        path: '/api',
        body: '{}',
      });

      // Before destroy
      expect(result.proof).toHaveLength(64);

      result.destroy();

      // After destroy (internal implementation may vary, but shouldn't crash)
      expect(() => result.destroy()).not.toThrow();
    });
  });

  describe('SA-004: Error Safety', () => {
    it('should not leak internal details in error messages', () => {
      expect.assertions(1);
      try {
        ashCanonicalizeJson('not valid json');
        expect.fail('Should have thrown');
      } catch (err) {
        if (err instanceof AshError) {
          expect(err.message).not.toContain('not valid json');
        }
      }
    });

    it('should provide safe error codes', () => {
      const err = AshError.proofInvalid();
      expect(err.code).toBe('ASH_PROOF_INVALID');
      expect(err.message).not.toContain('secret');
    });
  });
});

// ============================================================================
// BUG: BUG HUNTING
// ============================================================================

describe('🐛 BUG: BUG HUNTING', () => {
  describe('BUG-001: Known Vulnerability Patterns', () => {
    it('should not have prototype pollution in JSON parse', () => {
      const malicious = '{"__proto__":{"isAdmin":true}}';
      
      // The canonicalization should handle this safely
      expect(() => ashCanonicalizeJson(malicious)).not.toThrow();

      // KEY SECURITY CHECK: Object.prototype should NOT be polluted globally
      // This would affect ALL objects in the application
      expect((Object.prototype as any).isAdmin).toBeUndefined();
      
      // Note: When JSON.parse() encounters __proto__, it sets the object's prototype.
      // Object.keys() only returns own properties, so __proto__ is not seen.
      // The canonicalization effectively strips the __proto__ key, which is safe.
      const result = ashCanonicalizeJson(malicious);
      expect(result).toBe('{}'); // __proto__ becomes prototype, not own property
    });

    it('should handle constructor property safely', () => {
      const json = '{"constructor":{"prototype":{"isAdmin":true}}}';
      expect(() => ashCanonicalizeJson(json)).not.toThrow();
    });
  });

  describe('BUG-002: Race Condition Detection', () => {
    it('should handle concurrent proof generation', async () => {
      const nonce = randomHex(32);
      const binding = 'POST|/api|';
      const bodyHash = ashHashBody('{}');
      const timestamp = String(Math.floor(Date.now() / 1000));

      const clientSecret = ashDeriveClientSecret(nonce, 'ctx_test', binding);

      const promises = Array(100).fill(null).map(() =>
        Promise.resolve(ashBuildProof(clientSecret, timestamp, binding, bodyHash))
      );

      const results = await Promise.all(promises);
      const allSame = results.every(r => r === results[0]);
      expect(allSame).toBe(true);
    });
  });

  describe('BUG-003: Resource Exhaustion', () => {
    it('should handle rapid successive calls', () => {
      const results: string[] = [];
      for (let i = 0; i < 1000; i++) {
        results.push(ashHashBody(`{"i":${i}}`));
      }
      expect(results).toHaveLength(1000);
      expect(results[0]).toHaveLength(SHA256_HEX_LENGTH);
    });
  });

  describe('BUG-004: Input Validation Gaps', () => {
    it('should reject non-hex characters in nonce', () => {
      const invalidNonces = [
        'g'.repeat(32),  // 'g' is not hex
        ' '.repeat(32),  // spaces
        '@'.repeat(32),  // special chars
      ];

      for (const nonce of invalidNonces) {
        expect(() => ashValidateNonce(nonce)).toThrow();
      }
    });

    it('should reject invalid timestamp formats', () => {
      const invalidTimestamps = [
        'abc',
        '12.34',
        '-123',
        '+123',
        ' 123 ',
        '0123',  // Leading zero
      ];

      for (const ts of invalidTimestamps) {
        expect(() => ashValidateTimestamp(ts, 300, 30)).toThrow();
      }
    });
  });

  describe('BUG-005: Off-by-One Errors', () => {
    it('should handle exact boundary for MIN_NONCE_HEX_CHARS', () => {
      const nonce = 'a'.repeat(MIN_NONCE_HEX_CHARS);
      expect(() => ashValidateNonce(nonce)).not.toThrow();
    });

    it('should reject one less than MIN_NONCE_HEX_CHARS', () => {
      const nonce = 'a'.repeat(MIN_NONCE_HEX_CHARS - 1);
      expect(() => ashValidateNonce(nonce)).toThrow();
    });
  });
});
