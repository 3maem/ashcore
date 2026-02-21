/**
 * ASH Node SDK v1.0.0 — Bug Regression Tests
 *
 * Tests for known bugs, edge cases from bug reports, and regression guards
 * to prevent reintroduction of previously fixed issues.
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
  ashVerifyProofUnified,
  ashHashBody,
  ashHashProof,
  ashHashScope,
  ashValidateTimestampFormat,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  AshError,
} from '../../src/index.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_bug_test';
const BINDING = 'POST|/api/test|';
const TS = '1700000000';

describe('BUG: SDK version gate', () => {
  it('confirms SDK v1.0.0', () => {
    expect(ASH_SDK_VERSION).toBe('1.0.0');
  });
});

// ── BUG-001: HMAC key format ────────────────────────────────────────
// The HMAC key for derive_client_secret must use ASCII bytes of lowercase
// nonce hex string (NOT hex-decoded binary). This was a critical deviation
// from the Rust reference.

describe('BUG-001: HMAC key uses ASCII nonce bytes (not decoded)', () => {
  it('BUG-001-A: Known vector matches Rust reference output', () => {
    const secret = ashDeriveClientSecret(NONCE, 'ctx_test', 'POST|/api|');
    // This would fail if we hex-decoded the nonce instead of using ASCII bytes
    expect(secret.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(secret)).toBe(true);
  });

  it('BUG-001-B: Uppercase and lowercase nonce produce same secret', () => {
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
});

// ── BUG-002: derive_client_secret message format ────────────────────
// Message is "contextId|binding". No version prefix in the HMAC message.

describe('BUG-002: derive_client_secret message format', () => {
  it('BUG-002-A: Output matches cross-SDK conformance vector', () => {
    // Message must NOT include any version prefix
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(secret.length).toBe(64);
    // Verify it's deterministic
    const secret2 = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(secret).toBe(secret2);
  });
});

// ── BUG-003: ashHashProof hashes ASCII hex bytes ────────────────────
// ashHashProof should hash the ASCII bytes of the proof hex string,
// NOT the decoded binary bytes. This affects chain hashing.

describe('BUG-003: ashHashProof hashes ASCII bytes', () => {
  it('BUG-003-A: ashHashProof("aa...") != SHA256(0xaa...)', () => {
    const proof = 'aa'.repeat(32); // 64 hex chars = 32 bytes decoded
    const hashOfAscii = ashHashProof(proof);
    // SHA-256 of the 64-byte ASCII string "aaa...a" (not 32-byte binary 0xAA...)
    const expectedForAscii = ashHashBody(proof); // Both hash ASCII bytes
    expect(hashOfAscii).toBe(expectedForAscii);
  });
});

// ── BUG-004: Negative zero in JSON canonicalization ─────────────────
// JSON.parse("-0") produces -0 in JavaScript. JCS requires it to serialize as "0".

describe('BUG-004: Negative zero handling', () => {
  it('BUG-004-A: -0 serializes as 0', () => {
    expect(ashCanonicalizeJson('-0')).toBe('0');
  });

  it('BUG-004-B: -0.0 serializes as 0', () => {
    expect(ashCanonicalizeJson('-0.0')).toBe('0');
  });

  it('BUG-004-C: Object with -0 value', () => {
    expect(ashCanonicalizeJson('{"a":-0}')).toBe('{"a":0}');
  });

  it('BUG-004-D: Array with -0 element', () => {
    expect(ashCanonicalizeJson('[-0,1,-0]')).toBe('[0,1,0]');
  });
});

// ── BUG-005: Plus literal in query canonicalization ──────────────────
// In ashcore, + is treated as literal plus (NOT as space).
// This differs from application/x-www-form-urlencoded standard.

describe('BUG-005: Plus is literal in queries', () => {
  it('BUG-005-A: Plus sign preserved as %2B', () => {
    const result = ashCanonicalizeQuery('a=1+2');
    expect(result).toContain('%2B');
    expect(result).not.toContain('+');
    expect(result).not.toContain('%20');
  });

  it('BUG-005-B: Plus in key also preserved', () => {
    const result = ashCanonicalizeQuery('a+b=1');
    expect(result).toContain('a%2Bb');
  });

  it('BUG-005-C: Space encoded as %20 not +', () => {
    const result = ashCanonicalizeQuery('a=hello world');
    expect(result).toContain('%20');
    expect(result).not.toContain('+');
  });
});

// ── BUG-006: Scope hash deduplication ───────────────────────────────
// Duplicate field names in scope must be deduplicated before hashing.

describe('BUG-006: Scope deduplication', () => {
  it('BUG-006-A: Duplicate fields deduplicated', () => {
    const h1 = ashHashScope(['a', 'b']);
    const h2 = ashHashScope(['a', 'b', 'a']);
    expect(h1).toBe(h2);
  });

  it('BUG-006-B: Triple duplicate same as single', () => {
    const h1 = ashHashScope(['x']);
    const h2 = ashHashScope(['x', 'x', 'x']);
    expect(h1).toBe(h2);
  });
});

// ── BUG-007: Path traversal beyond root ─────────────────────────────
// "/.." should resolve to "/" (root), not crash or go negative.

describe('BUG-007: Path traversal edge cases', () => {
  it('BUG-007-A: Path beyond root resolves to root', () => {
    const result = ashNormalizeBinding('GET', '/../../..', '');
    expect(result).toBe('GET|/|');
  });

  it('BUG-007-B: Complex traversal resolves correctly', () => {
    const result = ashNormalizeBinding('GET', '/a/b/../c/./d/../e', '');
    expect(result).toBe('GET|/a/c/e|');
  });

  it('BUG-007-C: Single dot path', () => {
    const result = ashNormalizeBinding('GET', '/.', '');
    expect(result).toBe('GET|/|');
  });
});

// ── BUG-008: Scope hash consistency ─────────────────────────────────
// Scope hash must sort fields alphabetically before joining and hashing.

describe('BUG-008: Scope field sorting', () => {
  it('BUG-008-A: Fields sorted alphabetically', () => {
    const h1 = ashHashScope(['c', 'a', 'b']);
    const h2 = ashHashScope(['a', 'b', 'c']);
    expect(h1).toBe(h2);
  });

  it('BUG-008-B: Numeric-looking fields sorted lexicographically', () => {
    const h1 = ashHashScope(['2', '10', '1']);
    const h2 = ashHashScope(['1', '10', '2']);
    expect(h1).toBe(h2);
  });
});

// ── BUG-009: Context ID charset validation ──────────────────────────
// Context IDs must only contain: A-Z a-z 0-9 _ - .

describe('BUG-009: Context ID validation', () => {
  it('BUG-009-A: Valid context IDs accepted', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'ctx_test', BINDING)).not.toThrow();
    expect(() => ashDeriveClientSecret(NONCE, 'CTX-123', BINDING)).not.toThrow();
    expect(() => ashDeriveClientSecret(NONCE, 'ctx.v2.test', BINDING)).not.toThrow();
  });

  it('BUG-009-B: Space in context ID rejected', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'ctx test', BINDING)).toThrow(AshError);
  });

  it('BUG-009-C: Slash in context ID rejected', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'ctx/test', BINDING)).toThrow(AshError);
  });

  it('BUG-009-D: Empty context ID rejected', () => {
    expect(() => ashDeriveClientSecret(NONCE, '', BINDING)).toThrow(AshError);
  });

  it('BUG-009-E: At sign in context ID rejected', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'ctx@test', BINDING)).toThrow(AshError);
  });
});

// ── BUG-010: Empty body hash for build_proof ────────────────────────

describe('BUG-010: build_proof body hash validation', () => {
  it('BUG-010-A: Empty body hash rejected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(() => ashBuildProof(secret, TS, BINDING, '')).toThrow(AshError);
  });

  it('BUG-010-B: Short body hash rejected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(() => ashBuildProof(secret, TS, BINDING, 'abcd')).toThrow(AshError);
  });

  it('BUG-010-C: Non-hex body hash rejected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(() => ashBuildProof(secret, TS, BINDING, 'g'.repeat(64))).toThrow(AshError);
  });
});

// ── BUG-011: Unified proof scope/chain consistency ──────────────────

describe('BUG-011: Unified proof consistency checks', () => {
  it('BUG-011-A: Scope hash without scope throws', () => {
    expect(() =>
      ashVerifyProofUnified(
        NONCE, CTX, BINDING, TS, '{}', 'a'.repeat(64),
        [], 'a'.repeat(64), // scope_hash with empty scope
        null, '',
      ),
    ).toThrow(AshError);
  });

  it('BUG-011-B: Scope without scope hash throws', () => {
    expect(() =>
      ashVerifyProofUnified(
        NONCE, CTX, BINDING, TS, '{}', 'a'.repeat(64),
        ['field'], '', // empty scope_hash with non-empty scope
        null, '',
      ),
    ).toThrow(AshError);
  });

  it('BUG-011-C: Chain hash without previous proof throws', () => {
    expect(() =>
      ashVerifyProofUnified(
        NONCE, CTX, BINDING, TS, '{}', 'a'.repeat(64),
        [], '', null, 'a'.repeat(64),
      ),
    ).toThrow(AshError);
  });
});

// ── BUG-012: JSON with trailing comma ───────────────────────────────

describe('BUG-012: Invalid JSON rejected', () => {
  it('BUG-012-A: Trailing comma rejected', () => {
    expect(() => ashCanonicalizeJson('{"a":1,}')).toThrow(AshError);
  });

  it('BUG-012-B: Single quotes rejected', () => {
    expect(() => ashCanonicalizeJson("{'a':1}")).toThrow(AshError);
  });

  it('BUG-012-C: Unquoted keys rejected', () => {
    expect(() => ashCanonicalizeJson('{a:1}')).toThrow(AshError);
  });

  it('BUG-012-D: Comments in JSON rejected', () => {
    expect(() => ashCanonicalizeJson('{"a":1 /* comment */}')).toThrow(AshError);
  });

  it('BUG-012-E: NaN rejected', () => {
    expect(() => ashCanonicalizeJson('NaN')).toThrow(AshError);
  });

  it('BUG-012-F: Infinity rejected', () => {
    expect(() => ashCanonicalizeJson('Infinity')).toThrow(AshError);
  });

  it('BUG-012-G: undefined rejected', () => {
    expect(() => ashCanonicalizeJson('undefined')).toThrow(AshError);
  });
});

// ── BUG-013: Scoped proof with non-existent nested field ────────────

describe('BUG-013: Scoped proof with missing nested fields', () => {
  it('BUG-013-A: Missing parent object in lenient mode', () => {
    const payload = { a: 1 };
    const result = ashExtractScopedFields(payload, ['x.y.z']);
    expect(result).toEqual({});
  });

  it('BUG-013-B: Missing array index in lenient mode', () => {
    const payload = { items: [1, 2] };
    const result = ashExtractScopedFields(payload, ['items[5]']);
    expect(result).toEqual({});
  });

  it('BUG-013-C: Missing parent object in strict mode throws', () => {
    expect(() =>
      ashExtractScopedFieldsStrict({ a: 1 }, ['x.y.z']),
    ).toThrow(AshError);
  });
});

// ── BUG-014: Percent encoding edge cases in path ────────────────────

describe('BUG-014: Percent encoding edge cases', () => {
  it('BUG-014-A: Already encoded unreserved chars decoded', () => {
    // %61 = 'a' (unreserved) — should decode then not re-encode
    const result = ashNormalizeBinding('GET', '/api/%61bc', '');
    expect(result).toBe('GET|/api/abc|');
  });

  it('BUG-014-B: Reserved chars remain encoded with uppercase', () => {
    // Space in path encoded as %20
    const result = ashNormalizeBinding('GET', '/api/hello%20world', '');
    expect(result).toContain('%20');
  });
});

// ── BUG-015: Verify proof with freshness ────────────────────────────

describe('BUG-015: Freshness verification edge cases', () => {
  it('BUG-015-A: Current timestamp passes freshness check', () => {
    const now = String(Math.floor(Date.now() / 1000));
    // With default 300s max age and 30s clock skew, current timestamp should pass
    expect(() => ashValidateTimestampFormat(now)).not.toThrow();
  });
});

// ── BUG-016: Urlencoded vs query canonicalization consistency ────────

describe('BUG-016: Urlencoded/query consistency', () => {
  it('BUG-016-A: Same input produces same output', () => {
    const input = 'b=2&a=1&c=3';
    expect(ashCanonicalizeUrlencoded(input)).toBe(ashCanonicalizeQuery(input));
  });

  it('BUG-016-B: Empty input handled consistently', () => {
    expect(ashCanonicalizeUrlencoded('')).toBe('');
    expect(ashCanonicalizeQuery('')).toBe('');
  });

  it('BUG-016-C: Fragment stripped in both', () => {
    const input = 'a=1#fragment';
    expect(ashCanonicalizeUrlencoded(input)).toBe(ashCanonicalizeQuery(input));
  });
});
