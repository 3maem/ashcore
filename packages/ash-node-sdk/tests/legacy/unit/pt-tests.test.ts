/**
 * Penetration Tests (PT)
 *
 * Simulates attacker scenarios: proof forgery, replay attacks, parameter tampering,
 * binding bypass, scope manipulation, and chain poisoning.
 */
import { describe, it, expect } from 'vitest';
import {
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
  AshError,
} from '../../src/index.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_test_conformance_v1';
const BINDING = 'POST|/api/transfer|';
const TS = '1700000000';
const PAYLOAD = '{"amount":100,"recipient":"alice"}';

describe('PT: Proof forgery attacks', () => {
  it('PT-FORGE-001: Random proof rejected', () => {
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const result = ashVerifyProof(NONCE, CTX, BINDING, TS, bodyHash, 'a'.repeat(64));
    expect(result).toBe(false);
  });

  it('PT-FORGE-002: Proof from different nonce rejected', () => {
    const differentNonce = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
    const secret1 = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const secret2 = ashDeriveClientSecret(differentNonce, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret2, TS, BINDING, bodyHash);

    // Verify with original nonce should fail
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
});

describe('PT: Payload tampering', () => {
  it('PT-TAMPER-001: Modified amount detected', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);

    // Attacker changes amount
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
});

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
    // Both should normalize to the same binding
    expect(b1).toBe(b2);
  });
});

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
});

describe('PT: Chain poisoning', () => {
  it('PT-CHAIN-001: Wrong previous proof produces wrong chain hash', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, TS, BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);

    // Verify with correct chain
    const isValid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000100', PAYLOAD, r2.proof,
      [], '', r1.proof, r2.chainHash,
    );
    expect(isValid).toBe(true);

    // Verify with wrong previous proof
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
        [], '', null, 'a'.repeat(64), // chain_hash without previous_proof
      ),
    ).toThrow(AshError);
  });
});

describe('PT: Timestamp replay', () => {
  it('PT-REPLAY-001: Same proof with different timestamp fails', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const canonical = ashCanonicalizeJson(PAYLOAD);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, '1700000000', BINDING, bodyHash);

    // Try to replay with different timestamp
    const result = ashVerifyProof(NONCE, CTX, BINDING, '1700000001', bodyHash, proof);
    expect(result).toBe(false);
  });
});
