/**
 * ASH Node SDK v1.0.0 — Logical Error Tests
 *
 * Tests for logic errors, state consistency, argument validation,
 * idempotency, commutativity, and invariant checks.
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import {
  ASH_SDK_VERSION,
  ashCanonicalizeJson,
  ashCanonicalizeJsonValue,
  ashCanonicalizeQuery,
  ashNormalizeBinding,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashHashBody,
  ashHashProof,
  ashHashScope,
  ashTimingSafeEqual,
  ashValidateNonce,
  ashValidateTimestampFormat,
  ashExtractScopedFields,
  AshError,
  MAX_TIMESTAMP,
} from '../../src/index.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_logic_test';
const BINDING = 'POST|/api/test|';
const TS = '1700000000';
const PAYLOAD = '{"amount":100,"recipient":"alice"}';

describe('LOGIC: SDK version gate', () => {
  it('confirms SDK v1.0.0', () => {
    expect(ASH_SDK_VERSION).toBe('1.0.0');
  });
});

// ── Idempotency Tests ───────────────────────────────────────────────

describe('LOGIC: Idempotency', () => {
  it('LOGIC-IDEM-001: Canonicalize JSON twice produces same result', () => {
    const first = ashCanonicalizeJson('{"b":1,"a":2}');
    const second = ashCanonicalizeJson(first);
    expect(first).toBe(second);
  });

  it('LOGIC-IDEM-002: Hash body is idempotent on same input', () => {
    const h1 = ashHashBody('test');
    const h2 = ashHashBody('test');
    expect(h1).toBe(h2);
  });

  it('LOGIC-IDEM-003: Derive secret is idempotent', () => {
    const s1 = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const s2 = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(s1).toBe(s2);
  });

  it('LOGIC-IDEM-004: Build proof is idempotent', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const bodyHash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    const p1 = ashBuildProof(secret, TS, BINDING, bodyHash);
    const p2 = ashBuildProof(secret, TS, BINDING, bodyHash);
    expect(p1).toBe(p2);
  });

  it('LOGIC-IDEM-005: Normalize binding is idempotent', () => {
    const b1 = ashNormalizeBinding('GET', '/api/users', 'b=2&a=1');
    // Parsing a normalized binding: extract parts and re-normalize
    const parts = b1.split('|');
    const b2 = ashNormalizeBinding(parts[0], parts[1], parts[2]);
    expect(b1).toBe(b2);
  });

  it('LOGIC-IDEM-006: Hash scope is idempotent', () => {
    const h1 = ashHashScope(['c', 'a', 'b']);
    const h2 = ashHashScope(['c', 'a', 'b']);
    expect(h1).toBe(h2);
  });

  it('LOGIC-IDEM-007: Canonicalize query twice produces same result', () => {
    const first = ashCanonicalizeQuery('c=3&a=1&b=2');
    const second = ashCanonicalizeQuery(first);
    expect(first).toBe(second);
  });
});

// ── Commutativity / Order Independence ──────────────────────────────

describe('LOGIC: Commutativity and order independence', () => {
  it('LOGIC-COMM-001: JSON key order does not affect canonicalization', () => {
    const a = ashCanonicalizeJson('{"x":1,"y":2,"z":3}');
    const b = ashCanonicalizeJson('{"z":3,"x":1,"y":2}');
    const c = ashCanonicalizeJson('{"y":2,"z":3,"x":1}');
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('LOGIC-COMM-002: Query parameter order does not affect canonicalization', () => {
    const a = ashCanonicalizeQuery('x=1&y=2&z=3');
    const b = ashCanonicalizeQuery('z=3&x=1&y=2');
    expect(a).toBe(b);
  });

  it('LOGIC-COMM-003: Scope field order does not affect scope hash', () => {
    const a = ashHashScope(['x', 'y', 'z']);
    const b = ashHashScope(['z', 'x', 'y']);
    const c = ashHashScope(['y', 'z', 'x']);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('LOGIC-COMM-004: Scope field order does not affect proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount', 'recipient']);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['recipient', 'amount']);
    expect(r1.proof).toBe(r2.proof);
    expect(r1.scopeHash).toBe(r2.scopeHash);
  });

  it('LOGIC-COMM-005: JSON array order IS significant', () => {
    const a = ashCanonicalizeJson('[1,2,3]');
    const b = ashCanonicalizeJson('[3,2,1]');
    expect(a).not.toBe(b);
  });
});

// ── Symmetry Tests (build <-> verify) ───────────────────────────────

describe('LOGIC: Build/verify symmetry', () => {
  it('LOGIC-SYM-001: build → verify roundtrip succeeds', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const bodyHash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);
    expect(ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, proof)).toBe(true);
  });

  it('LOGIC-SYM-002: Scoped build → verify roundtrip succeeds', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    const valid = ashVerifyProofScoped(
      NONCE, CTX, BINDING, TS, PAYLOAD,
      ['amount'], r.scopeHash, r.proof,
    );
    expect(valid).toBe(true);
  });

  it('LOGIC-SYM-003: Unified build → verify roundtrip succeeds', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, ['amount'], null);
    const valid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, TS, PAYLOAD, r.proof,
      ['amount'], r.scopeHash, null, '',
    );
    expect(valid).toBe(true);
  });

  it('LOGIC-SYM-004: Unified build → verify with chain roundtrip', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, '1700000000', BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);

    const valid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000100', PAYLOAD, r2.proof,
      [], '', r1.proof, r2.chainHash,
    );
    expect(valid).toBe(true);
  });

  it('LOGIC-SYM-005: Timing-safe equal is symmetric', () => {
    expect(ashTimingSafeEqual('abc', 'abc')).toBe(true);
    expect(ashTimingSafeEqual('abc', 'def')).toBe(false);
    expect(ashTimingSafeEqual('def', 'abc')).toBe(false);
  });
});

// ── Input Sensitivity Tests ─────────────────────────────────────────

describe('LOGIC: Input sensitivity (every parameter matters)', () => {
  it('LOGIC-SENS-001: Changing nonce changes secret', () => {
    const n1 = '0'.repeat(64);
    const n2 = '1'.repeat(64);
    const s1 = ashDeriveClientSecret(n1, CTX, BINDING);
    const s2 = ashDeriveClientSecret(n2, CTX, BINDING);
    expect(s1).not.toBe(s2);
  });

  it('LOGIC-SENS-002: Changing context_id changes secret', () => {
    const s1 = ashDeriveClientSecret(NONCE, 'ctx_a', BINDING);
    const s2 = ashDeriveClientSecret(NONCE, 'ctx_b', BINDING);
    expect(s1).not.toBe(s2);
  });

  it('LOGIC-SENS-003: Changing binding changes secret', () => {
    const s1 = ashDeriveClientSecret(NONCE, CTX, 'GET|/a|');
    const s2 = ashDeriveClientSecret(NONCE, CTX, 'GET|/b|');
    expect(s1).not.toBe(s2);
  });

  it('LOGIC-SENS-004: Changing timestamp changes proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const bodyHash = ashHashBody('{}');
    const p1 = ashBuildProof(secret, '1700000000', BINDING, bodyHash);
    const p2 = ashBuildProof(secret, '1700000001', BINDING, bodyHash);
    expect(p1).not.toBe(p2);
  });

  it('LOGIC-SENS-005: Changing body hash changes proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const h1 = ashHashBody('{"a":1}');
    const h2 = ashHashBody('{"a":2}');
    const p1 = ashBuildProof(secret, TS, BINDING, h1);
    const p2 = ashBuildProof(secret, TS, BINDING, h2);
    expect(p1).not.toBe(p2);
  });

  it('LOGIC-SENS-006: Changing scope changes scoped proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['recipient']);
    expect(r1.proof).not.toBe(r2.proof);
  });

  it('LOGIC-SENS-007: Adding chain changes unified proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, [], 'a'.repeat(64));
    expect(r1.proof).not.toBe(r2.proof);
  });

  it('LOGIC-SENS-008: Different payloads produce different scoped proofs', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, '{"amount":100}', ['amount']);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, '{"amount":200}', ['amount']);
    expect(r1.proof).not.toBe(r2.proof);
  });
});

// ── Type Invariant Tests ────────────────────────────────────────────

describe('LOGIC: Type invariants', () => {
  it('LOGIC-TYPE-001: All hash outputs are 64 lowercase hex chars', () => {
    const hexRe = /^[0-9a-f]{64}$/;
    expect(hexRe.test(ashHashBody('test'))).toBe(true);
    expect(hexRe.test(ashHashProof('a'.repeat(64)))).toBe(true);
    expect(hexRe.test(ashHashScope(['field1']))).toBe(true);
    expect(hexRe.test(ashDeriveClientSecret(NONCE, CTX, BINDING))).toBe(true);
    const bodyHash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    expect(hexRe.test(ashBuildProof(
      ashDeriveClientSecret(NONCE, CTX, BINDING), TS, BINDING, bodyHash,
    ))).toBe(true);
  });

  it('LOGIC-TYPE-002: Canonicalized JSON is valid JSON', () => {
    const canonical = ashCanonicalizeJson('{"b":1,"a":2}');
    expect(() => JSON.parse(canonical)).not.toThrow();
    const parsed = JSON.parse(canonical);
    expect(parsed.a).toBe(2);
    expect(parsed.b).toBe(1);
  });

  it('LOGIC-TYPE-003: ashVerifyProof always returns boolean', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const bodyHash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const valid = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, proof);
    const invalid = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, 'a'.repeat(64));
    expect(valid).toBe(true);
    expect(invalid).toBe(false);
  });

  it('LOGIC-TYPE-004: ScopedProofResult has correct shape', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    expect(r.proof.length).toBe(64);
    expect(r.scopeHash.length).toBe(64);
  });

  it('LOGIC-TYPE-005: UnifiedProofResult has correct shape', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, ['amount'], null);
    expect(r.proof.length).toBe(64);
    expect(r.scopeHash.length).toBe(64);
    expect(r.chainHash).toBe(''); // no previous proof
  });

  it('LOGIC-TYPE-006: UnifiedProofResult with chain has all fields populated', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, ['amount'], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, ['amount'], r1.proof);
    expect(r2.proof.length).toBe(64);
    expect(r2.scopeHash.length).toBe(64);
    expect(r2.chainHash.length).toBe(64);
  });

  it('LOGIC-TYPE-007: Validate timestamp returns number', () => {
    const ts = ashValidateTimestampFormat('1700000000');
    expect(ts).toBe(1700000000);
  });
});

// ── Invalid State Prevention ────────────────────────────────────────

describe('LOGIC: Invalid state prevention', () => {
  it('LOGIC-STATE-001: Cannot build proof with empty client_secret', () => {
    expect(() => ashBuildProof('', TS, BINDING, 'a'.repeat(64))).toThrow(AshError);
  });

  it('LOGIC-STATE-002: Cannot build proof with empty binding', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(() => ashBuildProof(secret, TS, '', 'a'.repeat(64))).toThrow(AshError);
  });

  it('LOGIC-STATE-003: Cannot derive secret with empty nonce', () => {
    expect(() => ashDeriveClientSecret('', CTX, BINDING)).toThrow(AshError);
  });

  it('LOGIC-STATE-004: Cannot derive secret with empty binding', () => {
    expect(() => ashDeriveClientSecret(NONCE, CTX, '')).toThrow(AshError);
  });

  it('LOGIC-STATE-005: Cannot build unified proof with empty client_secret', () => {
    expect(() => ashBuildProofUnified('', TS, BINDING, PAYLOAD, [], null)).toThrow(AshError);
  });

  it('LOGIC-STATE-006: Cannot build unified proof with empty binding', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    expect(() => ashBuildProofUnified(secret, TS, '', PAYLOAD, [], null)).toThrow(AshError);
  });

  it('LOGIC-STATE-007: Cannot build scoped proof with empty client_secret', () => {
    expect(() => ashBuildProofScoped('', TS, BINDING, PAYLOAD, [])).toThrow(AshError);
  });
});

// ── Transitivity and Consistency ────────────────────────────────────

describe('LOGIC: Transitivity and consistency', () => {
  it('LOGIC-TRANS-001: Chain hash of proof matches ashHashProof output', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);
    expect(r2.chainHash).toBe(ashHashProof(r1.proof));
  });

  it('LOGIC-TRANS-002: Scope hash in scoped proof matches ashHashScope output', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const scope = ['amount', 'recipient'];
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, scope);
    expect(r.scopeHash).toBe(ashHashScope(scope));
  });

  it('LOGIC-TRANS-003: Full-body proof matches zero-scope proof body hash', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const basicProof = ashBuildProof(secret, TS, BINDING, bodyHash);

    // Scoped with empty scope should use full payload
    const scopedResult = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, []);
    // Different HMAC messages but both use full payload body hash
    // basic: timestamp|binding|bodyHash
    // scoped: timestamp|binding|bodyHash|scopeHash (scopeHash is "")
    // These have different messages, so proofs will differ. That's correct.
    expect(basicProof).not.toBe(scopedResult.proof);
    expect(scopedResult.scopeHash).toBe('');
  });

  it('LOGIC-TRANS-004: Empty body hashes to SHA-256 of empty string', () => {
    expect(ashHashBody('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('LOGIC-TRANS-005: ashCanonicalizeJsonValue and ashCanonicalizeJson agree', () => {
    const input = '{"b":2,"a":1}';
    const fromString = ashCanonicalizeJson(input);
    const fromParsed = ashCanonicalizeJsonValue(JSON.parse(input));
    expect(fromString).toBe(fromParsed);
  });
});

// ── Boundary Value Tests ────────────────────────────────────────────

describe('LOGIC: Boundary values', () => {
  it('LOGIC-BOUND-001: Timestamp 0 is valid', () => {
    expect(ashValidateTimestampFormat('0')).toBe(0);
  });

  it('LOGIC-BOUND-002: Timestamp at MAX_TIMESTAMP boundary', () => {
    expect(ashValidateTimestampFormat(String(MAX_TIMESTAMP))).toBe(MAX_TIMESTAMP);
  });

  it('LOGIC-BOUND-003: Timestamp above MAX_TIMESTAMP rejected', () => {
    expect(() => ashValidateTimestampFormat(String(MAX_TIMESTAMP + 1))).toThrow(AshError);
  });

  it('LOGIC-BOUND-004: Nonce at exactly 32 hex chars valid', () => {
    expect(() => ashValidateNonce('0'.repeat(32))).not.toThrow();
  });

  it('LOGIC-BOUND-005: Nonce at exactly 512 hex chars valid', () => {
    expect(() => ashValidateNonce('0'.repeat(512))).not.toThrow();
  });

  it('LOGIC-BOUND-006: Single-element array in JSON', () => {
    expect(ashCanonicalizeJson('[42]')).toBe('[42]');
  });

  it('LOGIC-BOUND-007: Single-key object in JSON', () => {
    expect(ashCanonicalizeJson('{"a":1}')).toBe('{"a":1}');
  });

  it('LOGIC-BOUND-008: Empty query string canonicalizes to empty', () => {
    expect(ashCanonicalizeQuery('')).toBe('');
  });
});

// ── Non-interference Tests ──────────────────────────────────────────

describe('LOGIC: Non-interference (independent operations do not affect each other)', () => {
  it('LOGIC-NONINT-001: Multiple derive_secret calls do not interfere', () => {
    const s1 = ashDeriveClientSecret(NONCE, 'ctx_a', BINDING);
    const s2 = ashDeriveClientSecret(NONCE, 'ctx_b', BINDING);
    const s3 = ashDeriveClientSecret(NONCE, 'ctx_a', BINDING);
    expect(s1).toBe(s3); // Same inputs = same output
    expect(s1).not.toBe(s2); // Different inputs = different output
  });

  it('LOGIC-NONINT-002: Canonicalization does not mutate input', () => {
    const input = '{"b":1,"a":2}';
    ashCanonicalizeJson(input);
    expect(input).toBe('{"b":1,"a":2}');
  });

  it('LOGIC-NONINT-003: Extract scoped fields does not mutate payload', () => {
    const payload = { a: 1, b: { c: 3 } };
    const copy = JSON.parse(JSON.stringify(payload));
    ashExtractScopedFields(payload, ['a']);
    expect(payload).toEqual(copy);
  });

  it('LOGIC-NONINT-004: Multiple hash calls do not interfere', () => {
    const h1 = ashHashBody('test1');
    const h2 = ashHashBody('test2');
    const h3 = ashHashBody('test1');
    expect(h1).toBe(h3);
    expect(h1).not.toBe(h2);
  });
});
