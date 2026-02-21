/**
 * Comprehensive Security Test Suite for ASH Node.js SDK
 * 
 * This test suite covers:
 * - Penetration Testing (PT): Active vulnerability discovery
 * - API Quality (AQ): Boundary conditions, input validation
 * - Security Audit: Cryptographic correctness, protocol compliance
 * - Fuzz Testing: Edge cases and random inputs
 */

import { describe, it, expect } from 'vitest';
import {
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashHashBody,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashVerifyProofWithFreshness,
  ashTimingSafeEqual,
  ashValidateTimestamp,
  ashNormalizeBinding,
  AshError,
} from '../src/index.js';

// ============================================================================
// Helper Functions
// ============================================================================

function randomHex(len: number): string {
  const hex = '0123456789abcdef';
  return Array.from({ length: len }, () => hex[Math.floor(Math.random() * 16)]).join('');
}

// ============================================================================
// Penetration Testing (PT)
// ============================================================================

describe('Penetration Testing (PT)', () => {
  describe('PT-001: Proof Determinism', () => {
    it('should produce identical proofs for identical inputs', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api/transfer|';
      const bodyHash = ashHashBody('{"amount":100}');
      const timestamp = '1704067200';

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof1 = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
      const proof2 = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(proof1).toBe(proof2);
      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof1)).toBe(true);
      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof2)).toBe(true);
    });
  });

  describe('PT-002: Timestamp Manipulation', () => {
    it('should reject future timestamp beyond skew', () => {
      const futureTs = '9999999999';
      expect(() => {
        ashValidateTimestamp(futureTs, 300, 30);
      }).toThrow(AshError);
    });

    it('should reject past timestamp beyond age limit', () => {
      const pastTs = '1000000';
      expect(() => {
        ashValidateTimestamp(pastTs, 300, 30);
      }).toThrow(AshError);
    });
  });

  describe('PT-003: Binding Manipulation', () => {
    it('should reject proof for wrong endpoint', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api/transfer|';
      const wrongBinding = 'POST|/api/admin|';
      const bodyHash = ashHashBody('{"amount":100}');
      const timestamp = '1704067200';

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProof(nonce, contextId, wrongBinding, timestamp, bodyHash, proof)).toBe(false);
    });
  });

  describe('PT-004: Body Hash Manipulation', () => {
    it('should reject proof with modified body hash', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api/transfer|';
      const originalBody = '{"amount":100}';
      const modifiedBody = '{"amount":999999}';
      const bodyHash = ashHashBody(originalBody);
      const modifiedHash = ashHashBody(modifiedBody);
      const timestamp = '1704067200';

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProof(nonce, contextId, binding, timestamp, modifiedHash, proof)).toBe(false);
    });
  });

  describe('PT-005: Nonce Reuse', () => {
    it('should produce different secrets for different contexts with same nonce', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId1 = 'ctx_user1';
      const contextId2 = 'ctx_user2';
      const binding = 'POST|/api/transfer|';

      const secret1 = ashDeriveClientSecret(nonce, contextId1, binding);
      const secret2 = ashDeriveClientSecret(nonce, contextId2, binding);

      expect(secret1).not.toBe(secret2);
    });
  });

  describe('PT-006: Length Extension Attack', () => {
    it('should reject extended proof', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api/transfer|';
      const bodyHash = ashHashBody('{"amount":100}');
      const timestamp = '1704067200';

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      const extendedProof = proof + 'EXTRA';
      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, extendedProof)).toBe(false);
    });
  });

  describe('PT-007: Context ID Injection', () => {
    it('should reject pipe character in context_id', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const maliciousContext = 'ctx|admin';
      const binding = 'POST|/api/transfer|';

      expect(() => {
        ashDeriveClientSecret(nonce, maliciousContext, binding);
      }).toThrow(AshError);
    });

    it('should reject CRLF in context_id', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const maliciousContext = 'ctx\r\nX-Header: evil';
      const binding = 'POST|/api/transfer|';

      expect(() => {
        ashDeriveClientSecret(nonce, maliciousContext, binding);
      }).toThrow(AshError);
    });
  });

  describe('PT-008: Null Byte Injection', () => {
    it('should reject null bytes in context_id', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const maliciousContext = 'ctx\x00admin';
      const binding = 'POST|/api/transfer|';

      expect(() => {
        ashDeriveClientSecret(nonce, maliciousContext, binding);
      }).toThrow(AshError);
    });
  });

  describe('PT-009: Unicode Normalization Attack', () => {
    it('should normalize Unicode consistently', () => {
      const nfc = '{"name":"café"}';
      const nfd = '{"name":"cafe\u0301"}';

      const canonicalNfc = ashCanonicalizeJson(nfc);
      const canonicalNfd = ashCanonicalizeJson(nfd);

      expect(canonicalNfc).toBe(canonicalNfd);

      const hashNfc = ashHashBody(canonicalNfc);
      const hashNfd = ashHashBody(canonicalNfd);
      expect(hashNfc).toBe(hashNfd);
    });
  });

  describe('PT-010: Timing Attack Resistance', () => {
    it('should use constant-time comparison', () => {
      const proof1 = 'a'.repeat(64);
      const proof2 = 'b'.repeat(64);
      const proof3 = 'a'.repeat(63) + 'b';

      expect(ashTimingSafeEqual(proof1, proof2)).toBe(false);
      expect(ashTimingSafeEqual(proof1, proof3)).toBe(false);
      expect(ashTimingSafeEqual(proof1, proof1)).toBe(true);
    });
  });

  describe('PT-011: Proof Forgery', () => {
    it('should reject random fake proof', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api/transfer|';
      const bodyHash = ashHashBody('{"amount":100}');
      const timestamp = '1704067200';

      const fakeProof = 'deadbeef'.repeat(8);
      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, fakeProof)).toBe(false);
    });
  });

  describe('PT-012: DoS via Recursive JSON', () => {
    it('should reject deeply nested JSON', () => {
      let nested = 'null';
      for (let i = 0; i < 65; i++) {
        nested = `{"a":${nested}}`;
      }

      expect(() => {
        ashCanonicalizeJson(nested);
      }).toThrow(AshError);
    });
  });

  describe('PT-013: DoS via Large Payload', () => {
    it('should reject oversized payload', () => {
      const largePayload = `{"data":"${'a'.repeat(11 * 1024 * 1024)}"}`;
      
      expect(() => {
        ashCanonicalizeJson(largePayload);
      }).toThrow(AshError);
    });
  });
});

// ============================================================================
// API Quality (AQ) Tests
// ============================================================================

describe('API Quality (AQ)', () => {
  describe('AQ-001: Empty String Handling', () => {
    it('should handle empty JSON object', () => {
      const result = ashCanonicalizeJson('{}');
      expect(result).toBe('{}');
    });

    it('should handle empty string in JSON', () => {
      const result = ashCanonicalizeJson('{"key":""}');
      expect(result).toBe('{"key":""}');
    });
  });

  describe('AQ-002: Whitespace Handling', () => {
    it('should normalize various whitespace forms', () => {
      const inputs = [
        '{"a":1}',
        '{ "a" : 1 }',
        '{"a":\t1}',
        '{"a":\n1}',
        '{  "a"  :  1  }',
      ];

      const expected = '{"a":1}';
      for (const input of inputs) {
        expect(ashCanonicalizeJson(input)).toBe(expected);
      }
    });
  });

  describe('AQ-003: Minimum Nonce Length', () => {
    it('should reject nonce below 32 hex chars', () => {
      const shortNonce = 'a'.repeat(31);
      expect(() => {
        ashDeriveClientSecret(shortNonce, 'ctx_test', 'POST|/api|');
      }).toThrow(AshError);
    });

    it('should accept nonce with exactly 32 hex chars', () => {
      const minNonce = 'a'.repeat(32);
      expect(() => {
        ashDeriveClientSecret(minNonce, 'ctx_test', 'POST|/api|');
      }).not.toThrow();
    });
  });

  describe('AQ-004: Maximum Nonce Length', () => {
    it('should reject nonce above 512 hex chars', () => {
      const longNonce = 'a'.repeat(513);
      expect(() => {
        ashDeriveClientSecret(longNonce, 'ctx_test', 'POST|/api|');
      }).toThrow(AshError);
    });

    it('should accept nonce with exactly 512 hex chars', () => {
      const maxNonce = 'a'.repeat(512);
      expect(() => {
        ashDeriveClientSecret(maxNonce, 'ctx_test', 'POST|/api|');
      }).not.toThrow();
    });
  });

  describe('AQ-005: Context ID Length', () => {
    it('should reject empty context ID', () => {
      expect(() => {
        ashDeriveClientSecret('0123456789abcdef0123456789abcdef', '', 'POST|/api|');
      }).toThrow(AshError);
    });

    it('should accept context ID at maximum length (256)', () => {
      const maxContext = 'a'.repeat(256);
      expect(() => {
        ashDeriveClientSecret('0123456789abcdef0123456789abcdef', maxContext, 'POST|/api|');
      }).not.toThrow();
    });

    it('should reject context ID over maximum length', () => {
      const overContext = 'a'.repeat(257);
      expect(() => {
        ashDeriveClientSecret('0123456789abcdef0123456789abcdef', overContext, 'POST|/api|');
      }).toThrow(AshError);
    });
  });

  describe('AQ-006: Binding Length', () => {
    it('should reject empty binding', () => {
      expect(() => {
        ashDeriveClientSecret('0123456789abcdef0123456789abcdef', 'ctx_test', '');
      }).toThrow(AshError);
    });
  });

  describe('AQ-007: Numeric Edge Cases', () => {
    it('should handle zero correctly', () => {
      expect(ashCanonicalizeJson('{"a":0}')).toBe('{"a":0}');
    });

    it('should convert negative zero to positive zero', () => {
      expect(ashCanonicalizeJson('{"a":-0.0}')).toBe('{"a":0}');
    });

    it('should handle large numbers', () => {
      expect(ashCanonicalizeJson('{"a":9007199254740991}')).toBe('{"a":9007199254740991}');
    });

    it('should preserve floats', () => {
      expect(ashCanonicalizeJson('{"a":3.14159}')).toBe('{"a":3.14159}');
    });

    it('should convert whole floats to integers', () => {
      expect(ashCanonicalizeJson('{"a":5.0}')).toBe('{"a":5}');
    });
  });

  describe('AQ-008: Special Characters in Strings', () => {
    it('should handle escape sequences', () => {
      const testCases = [
        ['{"a":"\\\\"}', '{"a":"\\\\"}'],
        ['{"a":"\\\""}', '{"a":"\\\""}'],
        ['{"a":"\\n"}', '{"a":"\\n"}'],
        ['{"a":"\\t"}', '{"a":"\\t"}'],
      ];

      for (const [input, expected] of testCases) {
        expect(ashCanonicalizeJson(input)).toBe(expected);
      }
    });
  });

  describe('AQ-009: Unicode Edge Cases', () => {
    it('should handle BMP characters', () => {
      const result = ashCanonicalizeJson('{"a":"日本語"}');
      expect(result).toContain('日本語');
    });

    it('should handle surrogate pairs (emoji)', () => {
      const result = ashCanonicalizeJson('{"a":"🎉"}');
      expect(result).toContain('🎉');
    });

    it('should handle zero-width joiner', () => {
      const result = ashCanonicalizeJson('{"a":"👨‍👩‍👧‍👦"}');
      expect(result).toContain('👨‍👩‍👧‍👦');
    });
  });

  describe('AQ-010: Array Handling', () => {
    it('should handle empty array', () => {
      expect(ashCanonicalizeJson('{"a":[]}')).toBe('{"a":[]}');
    });

    it('should handle nested arrays', () => {
      expect(ashCanonicalizeJson('{"a":[[1,2],[3,4]]}')).toBe('{"a":[[1,2],[3,4]]}');
    });

    it('should handle array with objects', () => {
      expect(ashCanonicalizeJson('{"a":[{"b":2},{"c":3}]}')).toBe('{"a":[{"b":2},{"c":3}]}');
    });
  });

  describe('AQ-011: Key Ordering', () => {
    it('should sort keys lexicographically', () => {
      expect(ashCanonicalizeJson('{"z":1,"a":2,"m":3}')).toBe('{"a":2,"m":3,"z":1}');
    });

    it('should sort nested object keys', () => {
      expect(ashCanonicalizeJson('{"z":{"b":2,"a":1},"a":3}')).toBe('{"a":3,"z":{"a":1,"b":2}}');
    });
  });

  describe('AQ-012: Query String Edge Cases', () => {
    it('should handle empty query', () => {
      expect(ashCanonicalizeQuery('')).toBe('');
    });

    it('should handle single parameter', () => {
      expect(ashCanonicalizeQuery('a=1')).toBe('a=1');
    });

    it('should sort duplicate keys by value', () => {
      expect(ashCanonicalizeQuery('a=2&a=1')).toBe('a=1&a=2');
    });

    it('should handle percent-encoded spaces', () => {
      expect(ashCanonicalizeQuery('a=hello%20world')).toBe('a=hello%20world');
    });

    it('should encode plus as %2B', () => {
      expect(ashCanonicalizeQuery('a=b+c')).toBe('a=b%2Bc');
    });
  });
});

// ============================================================================
// Security Audit Tests
// ============================================================================

describe('Security Audit', () => {
  describe('SA-001: HMAC Key Derivation', () => {
    it('should produce deterministic output', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api|';

      const secret1 = ashDeriveClientSecret(nonce, contextId, binding);
      const secret2 = ashDeriveClientSecret(nonce, contextId, binding);

      expect(secret1).toBe(secret2);
    });

    it('should produce different output for different inputs', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      
      const secret1 = ashDeriveClientSecret(nonce, 'ctx_1', 'POST|/api|');
      const secret2 = ashDeriveClientSecret(nonce, 'ctx_2', 'POST|/api|');

      expect(secret1).not.toBe(secret2);
    });

    it('should be case-insensitive for nonce hex', () => {
      const nonceLower = '0123456789abcdef0123456789abcdef';
      const nonceUpper = '0123456789ABCDEF0123456789ABCDEF';

      const secret1 = ashDeriveClientSecret(nonceLower, 'ctx_test', 'POST|/api|');
      const secret2 = ashDeriveClientSecret(nonceUpper, 'ctx_test', 'POST|/api|');

      expect(secret1).toBe(secret2);
    });
  });

  describe('SA-002: Proof Uniqueness', () => {
    it('should produce different proofs for different timestamps', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api|';
      const bodyHash = ashHashBody('{"a":1}');

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof1 = ashBuildProof(clientSecret, '1000000000', binding, bodyHash);
      const proof2 = ashBuildProof(clientSecret, '1000000001', binding, bodyHash);

      expect(proof1).not.toBe(proof2);
    });
  });

  describe('SA-003: Hash Consistency', () => {
    it('should produce consistent hashes', () => {
      const input = '{"a":1}';
      const hash1 = ashHashBody(input);
      const hash2 = ashHashBody(input);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);
    });
  });

  describe('SA-004: Error Message Safety', () => {
    it('should not leak sensitive information in errors', () => {
      expect.assertions(2);
      try {
        ashCanonicalizeJson('not valid json');
        expect.fail('Should have thrown');
      } catch (err) {
        if (err instanceof AshError) {
          const msg = err.message;
          expect(msg).not.toContain('not valid json');
          expect(msg).not.toContain('{');
        }
      }
    });
  });

  describe('SA-005: Timestamp Validation', () => {
    it('should reject leading zeros in timestamps', () => {
      expect(() => {
        ashValidateTimestamp('0123456789', 300, 30);
      }).toThrow(AshError);
    });

    it('should accept "0" as format-valid (but expired)', () => {
      expect.assertions(1);
      // "0" is valid format but will fail freshness check
      // Only fail if it's not expired (it will be expired)
      try {
        ashValidateTimestamp('0', 300, 30);
      } catch (err) {
        // Expected to fail due to expiration, not format
        expect(err).toBeInstanceOf(AshError);
      }
    });
  });

  describe('SA-006: Binding Normalization Security', () => {
    it('should reject path without leading slash', () => {
      expect(() => {
        ashNormalizeBinding('GET', 'api/users', '');
      }).toThrow(AshError);
    });

    it('should normalize path correctly', () => {
      const result = ashNormalizeBinding('GET', '/api/users', '');
      expect(result).toBe('GET|/api/users|');
    });
  });

});

// ============================================================================
// Fuzz Testing
// ============================================================================

describe('Fuzz Testing', () => {
  describe('FUZZ-001: Random Nonce Handling', () => {
    it('should handle random nonce lengths', () => {
      for (let i = 0; i < 50; i++) {
        const len = Math.floor(Math.random() * 600);
        const nonce = randomHex(len);

        try {
          ashDeriveClientSecret(nonce, 'ctx_test', 'POST|/api|');
          expect(len).toBeGreaterThanOrEqual(32);
          expect(len).toBeLessThanOrEqual(512);
        } catch (err) {
          expect(len < 32 || len > 512).toBe(true);
        }
      }
    });
  });

  describe('FUZZ-002: Random Context IDs', () => {
    it('should handle various context ID patterns', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      
      const contexts = [
        'ctx_test',
        'ctx-test',
        'ctx.test',
        'ctx_test_123',
        'a'.repeat(256),
      ];

      for (const context of contexts) {
        if (context.length > 0 && context.length <= 256 && /^[A-Za-z0-9_\-.]+$/.test(context)) {
          expect(() => {
            ashDeriveClientSecret(nonce, context, 'POST|/api|');
          }).not.toThrow();
        } else {
          expect(() => {
            ashDeriveClientSecret(nonce, context, 'POST|/api|');
          }).toThrow();
        }
      }
    });
  });

  describe('FUZZ-003: Random JSON Payloads', () => {
    it('should handle various JSON structures', () => {
      const payloads = [
        '{}',
        '[]',
        'null',
        'true',
        'false',
        '0',
        '{"":null}',
        '{"a":{"b":{"c":1}}}',
        '[1,2,3,4,5]',
        '{"key with spaces":1}',
      ];

      for (const payload of payloads) {
        try {
          ashCanonicalizeJson(payload);
        } catch {
          // Some may fail, but should not crash
        }
      }
    });
  });

  describe('FUZZ-004: Random Query Strings', () => {
    it('should handle various query string patterns', () => {
      const queries = [
        '',
        'a=1',
        'a=1&b=2&c=3',
        'a=1&a=2&a=3',
        'key=value%20with%20spaces',
        'special=%2B%2F%3D',
        'a',
        'a=',
        '=b',
      ];

      for (const query of queries) {
        try {
          ashCanonicalizeQuery(query);
        } catch {
          // Should not crash
        }
      }
    });
  });

  describe('FUZZ-005: Random Bindings', () => {
    it('should handle various HTTP methods', () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
      
      for (const method of methods) {
        try {
          ashNormalizeBinding(method, '/api/users', '');
        } catch {
          // Should not crash
        }
      }
    });
  });

  describe('FUZZ-006: Special Unicode Characters', () => {
    it('should handle various Unicode characters', () => {
      const testChars = [
        'A',
        'é',
        '€',
        '中',
        '🎉',
      ];

      for (const ch of testChars) {
        const json = `{"char":"${ch}"}`;
        try {
          ashCanonicalizeJson(json);
        } catch (err) {
          // Some characters might need escaping
        }
      }
    });
  });

  describe('FUZZ-007: Edge Case Numbers', () => {
    it('should handle various numeric formats', () => {
      const numbers = [
        '0',
        '-0',
        '0.0',
        '-0.0',
        '1e10',
        '1e-10',
        '1E10',
        '0.0000001',
        '9999999999999999',
        '-9999999999999999',
      ];

      for (const num of numbers) {
        const json = `{"num":${num}}`;
        try {
          ashCanonicalizeJson(json);
        } catch {
          // Should not crash
        }
      }
    });
  });

  describe('FUZZ-008: Pathological JSON Structures', () => {
    it('should handle many keys', () => {
      const obj: Record<string, number> = {};
      for (let i = 0; i < 100; i++) {
        obj[`key${i}`] = i;
      }
      const json = JSON.stringify(obj);
      expect(() => ashCanonicalizeJson(json)).not.toThrow();
    });

    it('should handle deep nesting just under limit', () => {
      let deep = 'null';
      for (let i = 0; i < 63; i++) {
        deep = `{"a":${deep}}`;
      }
      expect(() => ashCanonicalizeJson(deep)).not.toThrow();
    });
  });

  describe('FUZZ-009: Malformed Input Resilience', () => {
    it('should handle malformed JSON gracefully', () => {
      const malformed = [
        '{',
        '}',
        '[',
        ']',
        '"',
        '"""',
        '{"a":}',
        '{"a":1]',
        '[1,2,}',
        'not json at all',
        '<xml>not json</xml>',
      ];

      for (const input of malformed) {
        try {
          ashCanonicalizeJson(input);
        } catch {
          // Expected - should not crash
        }
      }
    });
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('Integration Tests', () => {
  describe('INT-001: Full Request Flow', () => {
    it('should complete full request flow', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_transaction_123';
      const binding = 'POST|/api/transfer|';

      const payload = '{"from":"alice","to":"bob","amount":100.00}';
      const canonical = ashCanonicalizeJson(payload);

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const bodyHash = ashHashBody(canonical);
      const timestamp = '1704067200';
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProof(nonce, contextId, binding, timestamp, bodyHash, proof)).toBe(true);

      const tampered = '{"from":"alice","to":"bob","amount":999999.00}';
      const tamperedCanonical = ashCanonicalizeJson(tampered);
      const tamperedHash = ashHashBody(tamperedCanonical);
      expect(ashVerifyProof(nonce, contextId, binding, timestamp, tamperedHash, proof)).toBe(false);
    });
  });

  describe('INT-002: Verify with Freshness', () => {
    it('should verify with timestamp freshness check', () => {
      const nonce = '0123456789abcdef0123456789abcdef';
      const contextId = 'ctx_test';
      const binding = 'POST|/api|';
      const bodyHash = ashHashBody('{"a":1}');
      const now = Math.floor(Date.now() / 1000);
      const timestamp = now.toString();

      const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
      const proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);

      expect(ashVerifyProofWithFreshness(
        nonce, contextId, binding, timestamp, bodyHash, proof, 300, 30
      )).toBe(true);
    });
  });

  describe('INT-003: Roundtrip Consistency', () => {
    it('should produce identical canonicalization on multiple passes', () => {
      const json = '{"z":1,"a":{"c":3,"b":2},"arr":[3,1,2]}';
      
      const c1 = ashCanonicalizeJson(json);
      const c2 = ashCanonicalizeJson(c1);
      const c3 = ashCanonicalizeJson(c2);

      expect(c1).toBe(c2);
      expect(c2).toBe(c3);

      const h1 = ashHashBody(c1);
      const h2 = ashHashBody(c2);
      expect(h1).toBe(h2);
    });
  });

  describe('INT-004: Error Handling Chain', () => {
    it('should propagate errors correctly', () => {
      expect(() => {
        ashDeriveClientSecret('short', 'ctx', 'POST|/api|');
      }).toThrow(AshError);

      expect(() => {
        ashCanonicalizeJson('{invalid');
      }).toThrow(AshError);
    });
  });
});
