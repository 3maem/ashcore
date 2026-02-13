/**
 * ASH Node SDK v1.0.0 — Penetration Tests (PT)
 *
 * Simulates real attacker scenarios: proof forgery, replay attacks,
 * parameter tampering, binding bypass, scope manipulation, and chain poisoning.
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import {
  ASH_SDK_VERSION,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashHashBody,
  ashCanonicalizeJson,
  ashNormalizeBinding,
  ashHashScope,
  ashHashProof,
  AshError,
} from '../../src/index.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_test_conformance_v1';
const BINDING = 'POST|/api/transfer|';
const TS = '1700000000';
const PAYLOAD = '{"amount":100,"recipient":"alice"}';

describe('PT: SDK version gate', () => {
  it('confirms SDK v1.0.0', () => {
    expect(ASH_SDK_VERSION).toBe('1.0.0');
  });
});

// ── Proof Forgery ────────────────────────────────────────────────────

describe('PT: Proof forgery attacks', () => {
  it('PT-FORGE-001: Random proof rejected', () => {
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, 'a'.repeat(64));
    expect(result).toBe(false);
  });

  it('PT-FORGE-002: Proof from different nonce rejected', () => {
    const differentNonce = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
    const secret2 = ashDeriveClientSecret(differentNonce, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret2, TS, BINDING, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, proof);
    expect(result).toBe(false);
  });

  it('PT-FORGE-003: Proof from different context rejected', () => {
    const secret = ashDeriveClientSecret(NONCE, 'ctx_attacker', BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, proof);
    expect(result).toBe(false);
  });

  it('PT-FORGE-004: All-zero proof rejected', () => {
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, '0'.repeat(64));
    expect(result).toBe(false);
  });

  it('PT-FORGE-005: All-ff proof rejected', () => {
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, 'f'.repeat(64));
    expect(result).toBe(false);
  });

  it('PT-FORGE-006: Proof with one bit flipped rejected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    // Flip one hex character
    const flipped = (proof[0] === 'a' ? 'b' : 'a') + proof.slice(1);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, flipped);
    expect(result).toBe(false);
  });

  it('PT-FORGE-007: Correct proof accepted', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, proof);
    expect(result).toBe(true);
  });
});

// ── Payload Tampering ───────────────────────────────────────────────

describe('PT: Payload tampering', () => {
  it('PT-TAMPER-001: Modified amount detected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const tampered = ashCanonicalizeJson('{"amount":999,"recipient":"alice"}');
    const tamperedHash = ashHashBody(tampered);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, tamperedHash, proof);
    expect(result).toBe(false);
  });

  it('PT-TAMPER-002: Added field detected via full-body hash', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const tampered = ashCanonicalizeJson('{"amount":100,"recipient":"alice","admin":true}');
    const tamperedHash = ashHashBody(tampered);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, tamperedHash, proof);
    expect(result).toBe(false);
  });

  it('PT-TAMPER-003: Reordered JSON keys produce same hash', () => {
    const c1 = ashCanonicalizeJson('{"z":1,"a":2}');
    const c2 = ashCanonicalizeJson('{"a":2,"z":1}');
    expect(c1).toBe(c2);
    expect(ashHashBody(c1)).toBe(ashHashBody(c2));
  });

  it('PT-TAMPER-004: Changed recipient detected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const tampered = ashCanonicalizeJson('{"amount":100,"recipient":"attacker"}');
    const tamperedHash = ashHashBody(tampered);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, tamperedHash, proof);
    expect(result).toBe(false);
  });

  it('PT-TAMPER-005: Removed field detected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const tampered = ashCanonicalizeJson('{"amount":100}');
    const tamperedHash = ashHashBody(tampered);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, tamperedHash, proof);
    expect(result).toBe(false);
  });

  it('PT-TAMPER-006: Type change detected (string to number)', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const tampered = ashCanonicalizeJson('{"amount":"100","recipient":"alice"}');
    const tamperedHash = ashHashBody(tampered);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, tamperedHash, proof);
    expect(result).toBe(false);
  });

  it('PT-TAMPER-007: Null injection detected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    const tampered = ashCanonicalizeJson('{"amount":null,"recipient":"alice"}');
    const tamperedHash = ashHashBody(tampered);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, tamperedHash, proof);
    expect(result).toBe(false);
  });
});

// ── Binding Bypass ──────────────────────────────────────────────────

describe('PT: Binding bypass', () => {
  it('PT-BIND-001: Proof for /api/users fails on /api/admin', () => {
    const binding1 = ashNormalizeBinding('POST', '/api/users', '');
    const binding2 = ashNormalizeBinding('POST', '/api/admin', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding1);
    const bodyHash = ashHashBody('{}');
    const proof = ashBuildProof(secret, TS, binding1, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, binding2, TS, bodyHash, proof);
    expect(result).toBe(false);
  });

  it('PT-BIND-002: GET proof fails on POST', () => {
    const bindingGet = ashNormalizeBinding('GET', '/api/data', '');
    const bindingPost = ashNormalizeBinding('POST', '/api/data', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, bindingGet);
    const bodyHash = ashHashBody('{}');
    const proof = ashBuildProof(secret, TS, bindingGet, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, bindingPost, TS, bodyHash, proof);
    expect(result).toBe(false);
  });

  it('PT-BIND-003: Path traversal does not create binding bypass', () => {
    const b1 = ashNormalizeBinding('GET', '/api/users', '');
    const b2 = ashNormalizeBinding('GET', '/api/v1/../users', '');
    expect(b1).toBe(b2);
  });

  it('PT-BIND-004: Query parameter difference changes binding', () => {
    const b1 = ashNormalizeBinding('GET', '/api/data', 'page=1');
    const b2 = ashNormalizeBinding('GET', '/api/data', 'page=2');
    expect(b1).not.toBe(b2);
  });

  it('PT-BIND-005: Case-insensitive method normalization', () => {
    const b1 = ashNormalizeBinding('get', '/api/data', '');
    const b2 = ashNormalizeBinding('GET', '/api/data', '');
    expect(b1).toBe(b2);
  });

  it('PT-BIND-006: Double-encoded path does not leak', () => {
    const b1 = ashNormalizeBinding('GET', '/api/users', '');
    const b2 = ashNormalizeBinding('GET', '/api/%75sers', '');
    expect(b1).toBe(b2);
  });

  it('PT-BIND-007: Different query order normalizes to same binding', () => {
    const b1 = ashNormalizeBinding('GET', '/api', 'b=2&a=1');
    const b2 = ashNormalizeBinding('GET', '/api', 'a=1&b=2');
    expect(b1).toBe(b2);
  });
});

// ── Scope Manipulation ──────────────────────────────────────────────

describe('PT: Scope manipulation', () => {
  it('PT-SCOPE-001: Adding extra scope field changes proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount', 'recipient']);
    expect(r1.proof).not.toBe(r2.proof);
    expect(r1.scopeHash).not.toBe(r2.scopeHash);
  });

  it('PT-SCOPE-002: Removing scope field changes proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount', 'recipient']);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    expect(r1.proof).not.toBe(r2.proof);
  });

  it('PT-SCOPE-003: Scope order does not affect proof (auto-sorted)', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount', 'recipient']);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['recipient', 'amount']);
    expect(r1.proof).toBe(r2.proof);
    expect(r1.scopeHash).toBe(r2.scopeHash);
  });

  it('PT-SCOPE-004: Empty scope vs non-empty scope produce different proofs', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, []);
    const r2 = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    expect(r1.proof).not.toBe(r2.proof);
  });

  it('PT-SCOPE-005: Duplicate scope fields are deduplicated', () => {
    const h1 = ashHashScope(['amount', 'recipient']);
    const h2 = ashHashScope(['amount', 'recipient', 'amount']);
    expect(h1).toBe(h2);
  });

  it('PT-SCOPE-006: Scoped proof verifies correctly', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    const valid = ashVerifyProofScoped(
      NONCE, CTX, BINDING, TS, PAYLOAD,
      ['amount'], r.scopeHash, r.proof,
    );
    expect(valid).toBe(true);
  });

  it('PT-SCOPE-007: Scoped proof with tampered value fails', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    const tampered = '{"amount":999,"recipient":"alice"}';
    const valid = ashVerifyProofScoped(
      NONCE, CTX, BINDING, TS, tampered,
      ['amount'], r.scopeHash, r.proof,
    );
    expect(valid).toBe(false);
  });
});

// ── Chain Poisoning ─────────────────────────────────────────────────

describe('PT: Chain poisoning', () => {
  it('PT-CHAIN-001: Wrong previous proof produces wrong chain hash', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);

    const isValid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000100', PAYLOAD, r2.proof,
      [], '', r1.proof, r2.chainHash,
    );
    expect(isValid).toBe(true);

    const isInvalid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000100', PAYLOAD, r2.proof,
      [], '', 'a'.repeat(64), r2.chainHash,
    );
    expect(isInvalid).toBe(false);
  });

  it('PT-CHAIN-002: Missing chain when expected returns error', () => {
    expect(() =>
      ashVerifyProofUnified(
        NONCE, CTX, BINDING, TS, PAYLOAD, 'a'.repeat(64),
        [], '', null, 'a'.repeat(64),
      ),
    ).toThrow(AshError);
  });

  it('PT-CHAIN-003: Chain with no previous proof produces empty chain hash', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, [], null);
    expect(r.chainHash).toBe('');
  });

  it('PT-CHAIN-004: Three-step chain maintains integrity', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, '1700000000', BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);
    const r3 = ashBuildProofUnified(secret, '1700000200', BINDING, PAYLOAD, [], r2.proof);

    expect(r2.chainHash).toBe(ashHashProof(r1.proof));
    expect(r3.chainHash).toBe(ashHashProof(r2.proof));

    const valid3 = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000200', PAYLOAD, r3.proof,
      [], '', r2.proof, r3.chainHash,
    );
    expect(valid3).toBe(true);
  });

  it('PT-CHAIN-005: Skipping a chain step detected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, '1700000000', BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);
    const r3 = ashBuildProofUnified(secret, '1700000200', BINDING, PAYLOAD, [], r2.proof);

    // Try to verify r3 with r1 as previous (skipping r2)
    const valid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000200', PAYLOAD, r3.proof,
      [], '', r1.proof, r3.chainHash,
    );
    expect(valid).toBe(false);
  });
});

// ── Timestamp Replay ────────────────────────────────────────────────

describe('PT: Timestamp replay', () => {
  it('PT-REPLAY-001: Same proof with different timestamp fails', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, '1700000000', BINDING, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, BINDING, '1700000001', bodyHash, proof);
    expect(result).toBe(false);
  });

  it('PT-REPLAY-002: Each second produces a unique proof', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proofs = new Set<string>();
    for (let i = 0; i < 100; i++) {
      proofs.add(ashBuildProof(secret, String(1700000000 + i), BINDING, bodyHash));
    }
    expect(proofs.size).toBe(100);
  });

  it('PT-REPLAY-003: Proof for timestamp 0 does not work for timestamp 1', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, '0', BINDING, bodyHash);
    const result = ashVerifyProof(NONCE, CTX, BINDING, '1', bodyHash, proof);
    expect(result).toBe(false);
  });
});

// ── Cross-context attacks ───────────────────────────────────────────

describe('PT: Cross-context attacks', () => {
  it('PT-CROSS-001: Proof from ctx_a fails on ctx_b', () => {
    const secretA = ashDeriveClientSecret(NONCE, 'ctx_a', BINDING);
    const secretB = ashDeriveClientSecret(NONCE, 'ctx_b', BINDING);
    expect(secretA).not.toBe(secretB);

    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secretA, TS, BINDING, bodyHash);
    const result = ashVerifyProof(NONCE, 'ctx_b', BINDING, TS, bodyHash, proof);
    expect(result).toBe(false);
  });

  it('PT-CROSS-002: Same payload on different endpoints produces different proofs', () => {
    const b1 = ashNormalizeBinding('POST', '/api/transfer', '');
    const b2 = ashNormalizeBinding('POST', '/api/withdraw', '');
    const s1 = ashDeriveClientSecret(NONCE, CTX, b1);
    const s2 = ashDeriveClientSecret(NONCE, CTX, b2);
    expect(s1).not.toBe(s2);
  });
});
