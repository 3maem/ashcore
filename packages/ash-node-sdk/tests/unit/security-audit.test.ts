/**
 * ASH Node SDK v1.0.0 — Security Audit Tests
 *
 * Tests for OWASP-style vulnerabilities, injection attacks, timing attacks,
 * cryptographic misuse, information disclosure, and DoS prevention.
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import {
  ASH_SDK_VERSION,
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashDeriveClientSecret,
  ashBuildProof,
  ashHashBody,
  ashHashProof,
  ashHashScope,
  ashTimingSafeEqual,
  ashValidateNonce,
  ashValidateTimestampFormat,
  ashValidateHash,
  AshError,
  AshErrorCode,
} from '../../src/index.js';

const VALID_NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const VALID_BODY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('SEC: SDK version gate', () => {
  it('confirms SDK v1.0.0', () => {
    expect(ASH_SDK_VERSION).toBe('1.0.0');
  });
});

// ── Input Injection Prevention ──────────────────────────────────────

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
    const result = ashNormalizeBinding('GET', '/api/%2e%2e/admin', '');
    expect(result).toBe('GET|/admin|');
  });

  it('SEC-INJ-006: Query fragment injection', () => {
    const result = ashCanonicalizeQuery('a=1#<script>alert(1)</script>');
    expect(result).toBe('a=1');
    expect(result).not.toContain('<script>');
  });

  it('SEC-INJ-007: Unicode homograph in context_id', () => {
    expect(() => ashDeriveClientSecret(VALID_NONCE, 'ctx_\u0430bc', 'POST|/api|')).toThrow(AshError);
  });

  it('SEC-INJ-008: Delimiter collision in context_id', () => {
    expect(() => ashDeriveClientSecret(VALID_NONCE, 'ctx|injected', 'POST|/api|')).toThrow(AshError);
  });

  it('SEC-INJ-009: SQL injection in query key', () => {
    const result = ashCanonicalizeQuery("'; DROP TABLE users;--=1");
    expect(result).toContain('%27');
  });

  it('SEC-INJ-010: XSS in JSON value canonicalized safely', () => {
    const result = ashCanonicalizeJson('{"xss":"<script>alert(1)</script>"}');
    expect(result).toBe('{"xss":"<script>alert(1)</script>"}');
  });

  it('SEC-INJ-011: Unicode null in context_id rejected', () => {
    expect(() => ashDeriveClientSecret(VALID_NONCE, 'ctx\u0000test', 'POST|/api|')).toThrow(AshError);
  });

  it('SEC-INJ-012: Tab character in method rejected', () => {
    expect(() => ashNormalizeBinding('GET\tExtra', '/api', '')).toThrow(AshError);
  });

  it('SEC-INJ-013: Non-ASCII character in method rejected', () => {
    expect(() => ashNormalizeBinding('G\u00c9T', '/api', '')).toThrow(AshError);
  });

  it('SEC-INJ-014: Empty method rejected', () => {
    expect(() => ashNormalizeBinding('', '/api', '')).toThrow(AshError);
  });

  it('SEC-INJ-015: Nonce with spaces rejected', () => {
    expect(() => ashValidateNonce('0123456789 abcdef0123456789abcdef')).toThrow(AshError);
  });
});

// ── Cryptographic Correctness ───────────────────────────────────────

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

  it('SEC-CRYPTO-008: Client secret is always 64 lowercase hex chars', () => {
    const secret = ashDeriveClientSecret(VALID_NONCE, 'ctx_test', 'POST|/api|');
    expect(secret.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(secret)).toBe(true);
  });

  it('SEC-CRYPTO-009: Body hash is always 64 lowercase hex chars', () => {
    const hash = ashHashBody('test');
    expect(hash.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
  });

  it('SEC-CRYPTO-010: Scope hash is always 64 lowercase hex chars (non-empty scope)', () => {
    const hash = ashHashScope(['field1']);
    expect(hash.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
  });

  it('SEC-CRYPTO-011: Empty scope produces empty hash string', () => {
    expect(ashHashScope([])).toBe('');
  });

  it('SEC-CRYPTO-012: Same input always produces same output (determinism)', () => {
    const runs = Array.from({ length: 10 }, () =>
      ashDeriveClientSecret(VALID_NONCE, 'ctx_test', 'POST|/api|'),
    );
    expect(new Set(runs).size).toBe(1);
  });

  it('SEC-CRYPTO-013: Hash avalanche — one bit change cascades', () => {
    const h1 = ashHashBody('test1');
    const h2 = ashHashBody('test2');
    // Count differing hex digits — should be significant
    let diffs = 0;
    for (let i = 0; i < 64; i++) {
      if (h1[i] !== h2[i]) diffs++;
    }
    expect(diffs).toBeGreaterThan(20); // SHA-256 avalanche effect
  });
});

// ── Timing-safe Comparison ──────────────────────────────────────────

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

  it('SEC-TIMING-006: Very long equal strings return true', () => {
    const long = 'a'.repeat(10000);
    expect(ashTimingSafeEqual(long, long)).toBe(true);
  });

  it('SEC-TIMING-007: Strings differing in last char return false', () => {
    const base = 'a'.repeat(1000);
    expect(ashTimingSafeEqual(base + 'x', base + 'y')).toBe(false);
  });

  it('SEC-TIMING-008: Unicode strings compared correctly', () => {
    expect(ashTimingSafeEqual('hello\u00e9', 'hello\u00e9')).toBe(true);
    expect(ashTimingSafeEqual('hello\u00e9', 'hello\u00e8')).toBe(false);
  });
});

// ── Information Disclosure Prevention ───────────────────────────────

describe('SEC: Information disclosure prevention', () => {
  it('SEC-DISC-001: Invalid JSON error does not leak input', () => {
    expect.assertions(2);
    try {
      ashCanonicalizeJson('{"secret":"password123"broken}');
    } catch (e: unknown) {
      const err = e as AshError;
      expect(err.message).not.toContain('password123');
      expect(err.message).not.toContain('secret');
    }
  });

  it('SEC-DISC-002: Error codes are stable ASH_ prefixed strings', () => {
    expect.assertions(1);
    try {
      ashDeriveClientSecret('short', 'ctx', 'POST|/api|');
    } catch (e: unknown) {
      const err = e as AshError;
      expect(err.code).toMatch(/^ASH_/);
    }
  });

  it('SEC-DISC-003: Nonce validation error does not echo back nonce', () => {
    expect.assertions(1);
    const sensitiveNonce = 'xyz';
    try {
      ashValidateNonce(sensitiveNonce);
    } catch (e: unknown) {
      const err = e as AshError;
      expect(err.message).not.toContain(sensitiveNonce);
    }
  });

  it('SEC-DISC-004: Error objects have consistent structure', () => {
    expect.assertions(1);
    try {
      ashValidateTimestampFormat('');
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(AshError);
    }
  });

  it('SEC-DISC-005: AshError name property is always "AshError"', () => {
    const err = new AshError(AshErrorCode.VALIDATION_ERROR, 'test');
    expect(err.name).toBe('AshError');
  });
});

// ── DoS Prevention ──────────────────────────────────────────────────

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

  it('SEC-DOS-006: Rejects oversized urlencoded input', () => {
    const huge = 'a=' + 'x'.repeat(11 * 1024 * 1024);
    expect(() => ashCanonicalizeUrlencoded(huge)).toThrow(AshError);
  });

  it('SEC-DOS-007: Exactly at nesting limit (64) works', () => {
    const nested = '{"a":'.repeat(63) + '1' + '}'.repeat(63);
    expect(() => ashCanonicalizeJson(nested)).not.toThrow();
  });

  it('SEC-DOS-008: One above nesting limit (65) throws', () => {
    const nested = '{"a":'.repeat(65) + '1' + '}'.repeat(65);
    expect(() => ashCanonicalizeJson(nested)).toThrow(AshError);
  });

  it('SEC-DOS-009: Rejects context_id longer than 256 chars', () => {
    const longCtx = 'a'.repeat(257);
    expect(() => ashDeriveClientSecret(VALID_NONCE, longCtx, 'POST|/api|')).toThrow(AshError);
  });

  it('SEC-DOS-010: Minimum nonce length enforced (32 hex chars)', () => {
    expect(() => ashValidateNonce('0'.repeat(31))).toThrow(AshError);
    expect(() => ashValidateNonce('0'.repeat(32))).not.toThrow();
  });
});

// ── Hash Validation ─────────────────────────────────────────────────

describe('SEC: Hash validation', () => {
  it('SEC-HASH-001: Valid hash passes validation', () => {
    expect(() => ashValidateHash(VALID_BODY_HASH, 'body_hash')).not.toThrow();
  });

  it('SEC-HASH-002: Short hash rejected', () => {
    expect(() => ashValidateHash('abc', 'body_hash')).toThrow(AshError);
  });

  it('SEC-HASH-003: Non-hex hash rejected', () => {
    expect(() => ashValidateHash('g'.repeat(64), 'body_hash')).toThrow(AshError);
  });

  it('SEC-HASH-004: Hash with spaces rejected', () => {
    expect(() => ashValidateHash(' '.repeat(64), 'body_hash')).toThrow(AshError);
  });

  it('SEC-HASH-005: Empty proof hash rejected', () => {
    expect(() => ashHashProof('')).toThrow(AshError);
  });
});
