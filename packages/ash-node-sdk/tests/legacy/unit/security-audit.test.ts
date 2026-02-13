/**
 * Security Audit Tests
 *
 * Tests for OWASP-style vulnerabilities, injection attacks, timing attacks,
 * cryptographic misuse, and information disclosure.
 */
import { describe, it, expect } from 'vitest';
import {
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashDeriveClientSecret,
  ashBuildProof,
  ashHashBody,
  ashHashProof,
  ashTimingSafeEqual,
  ashValidateNonce,
  ashValidateTimestampFormat,
  ashExtractScopedFieldsStrict,
  AshError,
} from '../../src/index.js';

const VALID_NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const VALID_BODY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('SEC: Input injection prevention', () => {
  it('SEC-INJ-001: Null byte injection in nonce', () => {
    expect(() => ashValidateNonce('0123456789abcdef0123456789ab\x00ef')).toThrow(AshError);
  });

  it('SEC-INJ-002: Pipe injection in method', () => {
    expect(() => ashNormalizeBinding('GET|EXTRA', '/api', '')).toThrow(AshError);
  });

  it('SEC-INJ-003: Control character injection in method', () => {
    expect(() => ashNormalizeBinding('GET\r\nX-Injected: true', '/api', '')).toThrow(AshError);
  });

  it('SEC-INJ-004: Null byte injection in path', () => {
    expect(() => ashNormalizeBinding('GET', '/api/%00/admin', '')).toThrow(AshError);
  });

  it('SEC-INJ-005: Path traversal after decode', () => {
    // %2e%2e = ".." after decode — should be resolved, not leak to parent
    const result = ashNormalizeBinding('GET', '/api/%2e%2e/admin', '');
    expect(result).toBe('GET|/admin|');
  });

  it('SEC-INJ-006: Query fragment injection', () => {
    const result = ashCanonicalizeQuery('a=1#<script>alert(1)</script>');
    expect(result).toBe('a=1');
    expect(result).not.toContain('<script>');
  });

  it('SEC-INJ-007: Unicode homograph in context_id', () => {
    // Cyrillic 'а' looks like Latin 'a' but is different bytes
    expect(() => ashDeriveClientSecret(VALID_NONCE, 'ctx_\u0430bc', 'POST|/api|')).toThrow(AshError);
  });

  it('SEC-INJ-008: Delimiter collision in context_id', () => {
    expect(() => ashDeriveClientSecret(VALID_NONCE, 'ctx|injected', 'POST|/api|')).toThrow(AshError);
  });
});

describe('SEC: Cryptographic correctness', () => {
  it('SEC-CRYPTO-001: Different nonces produce different secrets', () => {
    const s1 = ashDeriveClientSecret(
      '0123456789abcdef0123456789abcdef',
      'ctx_test',
      'POST|/api|',
    );
    const s2 = ashDeriveClientSecret(
      'fedcba9876543210fedcba9876543210',
      'ctx_test',
      'POST|/api|',
    );
    expect(s1).not.toBe(s2);
  });

  it('SEC-CRYPTO-002: Different bindings produce different secrets', () => {
    const s1 = ashDeriveClientSecret(VALID_NONCE, 'ctx_test', 'GET|/api/a|');
    const s2 = ashDeriveClientSecret(VALID_NONCE, 'ctx_test', 'GET|/api/b|');
    expect(s1).not.toBe(s2);
  });

  it('SEC-CRYPTO-003: Different timestamps produce different proofs', () => {
    const secret = ashDeriveClientSecret(VALID_NONCE, 'ctx_test', 'POST|/api|');
    const p1 = ashBuildProof(secret, '1700000000', 'POST|/api|', VALID_BODY_HASH);
    const p2 = ashBuildProof(secret, '1700000001', 'POST|/api|', VALID_BODY_HASH);
    expect(p1).not.toBe(p2);
  });

  it('SEC-CRYPTO-004: Different payloads produce different body hashes', () => {
    const h1 = ashHashBody('{"a":1}');
    const h2 = ashHashBody('{"a":2}');
    expect(h1).not.toBe(h2);
  });

  it('SEC-CRYPTO-005: Chain hash is not reversible to proof', () => {
    const proof = 'fb9010d5e1f7e61f3a26417e0eb18081ae1f01ab9da3439f54956daa1fb07159';
    const chainHash = ashHashProof(proof);
    expect(chainHash).not.toBe(proof);
    expect(chainHash.length).toBe(64);
  });

  it('SEC-CRYPTO-006: Nonce case normalization (uppercase vs lowercase)', () => {
    const s1 = ashDeriveClientSecret(
      '0123456789ABCDEF0123456789ABCDEF',
      'ctx_test',
      'POST|/api|',
    );
    const s2 = ashDeriveClientSecret(
      '0123456789abcdef0123456789abcdef',
      'ctx_test',
      'POST|/api|',
    );
    expect(s1).toBe(s2);
  });

  it('SEC-CRYPTO-007: Proof output is always 64 lowercase hex chars', () => {
    const secret = ashDeriveClientSecret(VALID_NONCE, 'ctx_test', 'POST|/api|');
    const proof = ashBuildProof(secret, '1700000000', 'POST|/api|', VALID_BODY_HASH);
    expect(proof.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(proof)).toBe(true);
  });
});

describe('SEC: Timing-safe comparison', () => {
  it('SEC-TIMING-001: Equal strings return true', () => {
    expect(ashTimingSafeEqual('secret123', 'secret123')).toBe(true);
  });

  it('SEC-TIMING-002: Different strings return false', () => {
    expect(ashTimingSafeEqual('secret123', 'secret124')).toBe(false);
  });

  it('SEC-TIMING-003: Different lengths return false', () => {
    expect(ashTimingSafeEqual('short', 'much longer string')).toBe(false);
  });

  it('SEC-TIMING-004: Empty vs non-empty returns false', () => {
    expect(ashTimingSafeEqual('', 'something')).toBe(false);
  });

  it('SEC-TIMING-005: Both empty returns true', () => {
    expect(ashTimingSafeEqual('', '')).toBe(true);
  });
});

describe('SEC: Information disclosure prevention', () => {
  it('SEC-DISC-001: Invalid JSON error does not leak input', () => {
    try {
      ashCanonicalizeJson('{"secret":"password123"broken}');
    } catch (e: unknown) {
      const err = e as AshError;
      expect(err.message).not.toContain('password123');
      expect(err.message).not.toContain('secret');
    }
  });

  it('SEC-DISC-002: Error codes are stable ASH_ prefixed strings', () => {
    try {
      ashDeriveClientSecret('short', 'ctx', 'POST|/api|');
    } catch (e: unknown) {
      const err = e as AshError;
      expect(err.code).toMatch(/^ASH_/);
    }
  });
});

describe('SEC: DoS prevention', () => {
  it('SEC-DOS-001: Rejects oversized JSON', () => {
    const huge = '{"d":"' + 'x'.repeat(11 * 1024 * 1024) + '"}';
    expect(() => ashCanonicalizeJson(huge)).toThrow(AshError);
  });

  it('SEC-DOS-002: Rejects deeply nested JSON', () => {
    const nested = '{"a":'.repeat(70) + '1' + '}'.repeat(70);
    expect(() => ashCanonicalizeJson(nested)).toThrow(AshError);
  });

  it('SEC-DOS-003: Rejects oversized query string', () => {
    const huge = 'a=' + 'x'.repeat(11 * 1024 * 1024);
    expect(() => ashCanonicalizeQuery(huge)).toThrow(AshError);
  });

  it('SEC-DOS-004: Rejects oversized binding', () => {
    const longPath = '/api/' + 'a'.repeat(8190);
    expect(() => ashNormalizeBinding('GET', longPath, '')).toThrow(AshError);
  });

  it('SEC-DOS-005: Rejects oversized nonce', () => {
    const longNonce = '0'.repeat(513);
    expect(() => ashValidateNonce(longNonce)).toThrow(AshError);
  });
});
