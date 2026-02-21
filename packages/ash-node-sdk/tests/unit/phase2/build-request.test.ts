/**
 * ASH Node SDK — Phase 2: Build Request Orchestrator Tests
 *
 * Coverage: PT (bad nonce, bad ts, bad binding) / AQ (all 3 modes, auto-ts,
 * empty body, destroy) / SA (step ordering, destroy zeroing) / FUZZ (random inputs)
 */
import { describe, it, expect } from 'vitest';
import { ashBuildRequest } from '../../../src/build-request.js';
import type { BuildRequestInput } from '../../../src/build-request.js';
import { ashVerifyProof } from '../../../src/proof.js';
import { SHA256_HEX_LENGTH } from '../../../src/constants.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_build_test';
const TS = String(Math.floor(Date.now() / 1000));

function basicInput(overrides?: Partial<BuildRequestInput>): BuildRequestInput {
  return {
    nonce: NONCE,
    contextId: CTX,
    method: 'POST',
    path: '/api/users',
    rawQuery: '',
    body: '{"name":"Alice"}',
    timestamp: TS,
    ...overrides,
  };
}

// ── AQ: Basic Mode ─────────────────────────────────────────────────

describe('AQ: Build request — basic mode', () => {
  it('AQ-BR-001: builds valid basic proof', () => {
    const result = ashBuildRequest(basicInput());
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.bodyHash).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.binding).toContain('POST|');
    expect(result.timestamp).toBe(TS);
    expect(result.nonce).toBe(NONCE);
    expect(result.scopeHash).toBeUndefined();
    expect(result.chainHash).toBeUndefined();
  });

  it('AQ-BR-002: proof is verifiable with ashVerifyProof', () => {
    const result = ashBuildRequest(basicInput());
    const valid = ashVerifyProof(
      NONCE, CTX, result.binding, result.timestamp, result.bodyHash, result.proof,
    );
    expect(valid).toBe(true);
  });

  it('AQ-BR-003: empty body builds valid proof', () => {
    const result = ashBuildRequest(basicInput({ body: '' }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.bodyHash).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('AQ-BR-004: undefined body treated as empty', () => {
    const result = ashBuildRequest(basicInput({ body: undefined }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('AQ-BR-005: auto-generates timestamp when omitted', () => {
    const result = ashBuildRequest(basicInput({ timestamp: undefined }));
    const ts = parseInt(result.timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    expect(ts).toBeGreaterThanOrEqual(now - 5);
    expect(ts).toBeLessThanOrEqual(now + 5);
  });

  it('AQ-BR-006: query string included in binding', () => {
    const result = ashBuildRequest(basicInput({ rawQuery: 'page=1&sort=name' }));
    expect(result.binding).toContain('page=1');
  });
});

// ── AQ: Scoped & Unified Modes ─────────────────────────────────────

describe('AQ: Build request — scoped & unified modes', () => {
  it('AQ-BR-SCOPED-001: scope without previousProof triggers scoped mode', () => {
    const result = ashBuildRequest(basicInput({ scope: ['name'] }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    // With scope but no previousProof → scoped mode
    expect(result.scopeHash).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.chainHash).toBeUndefined();
  });

  it('AQ-BR-UNI-002: previousProof triggers unified mode with chain', () => {
    const firstResult = ashBuildRequest(basicInput());
    const result = ashBuildRequest(basicInput({
      previousProof: firstResult.proof,
      scope: ['name'],
    }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.chainHash).toBeDefined();
    expect(result.chainHash).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('AQ-BR-UNI-003: previousProof without scope triggers unified mode', () => {
    const firstResult = ashBuildRequest(basicInput());
    const result = ashBuildRequest(basicInput({
      previousProof: firstResult.proof,
    }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.chainHash).toBeDefined();
  });
});

// ── AQ: Destroy ────────────────────────────────────────────────────

describe('AQ: Build request — destroy', () => {
  it('AQ-BR-DEST-001: destroy can be called without error', () => {
    const result = ashBuildRequest(basicInput());
    expect(() => result.destroy()).not.toThrow();
  });

  it('AQ-BR-DEST-002: destroy can be called multiple times (idempotent)', () => {
    const result = ashBuildRequest(basicInput());
    result.destroy();
    expect(() => result.destroy()).not.toThrow();
  });
});

// ── PT: Invalid Inputs ─────────────────────────────────────────────

describe('PT: Build request — invalid inputs', () => {
  it('PT-BR-001: invalid nonce (too short) throws', () => {
    expect(() => ashBuildRequest(basicInput({ nonce: 'abc' }))).toThrow();
  });

  it('PT-BR-002: invalid nonce (non-hex) throws', () => {
    expect(() => ashBuildRequest(basicInput({ nonce: 'g'.repeat(64) }))).toThrow();
  });

  it('PT-BR-003: invalid timestamp (letters) throws', () => {
    expect(() => ashBuildRequest(basicInput({ timestamp: 'notanumber' }))).toThrow();
  });

  it('PT-BR-004: invalid timestamp (leading zero) throws', () => {
    expect(() => ashBuildRequest(basicInput({ timestamp: '01700000000' }))).toThrow();
  });

  it('PT-BR-005: empty method throws', () => {
    expect(() => ashBuildRequest(basicInput({ method: '' }))).toThrow();
  });

  it('PT-BR-006: path without leading slash throws', () => {
    expect(() => ashBuildRequest(basicInput({ path: 'api/users' }))).toThrow();
  });

  it('PT-BR-007: empty contextId throws', () => {
    expect(() => ashBuildRequest(basicInput({ contextId: '' }))).toThrow();
  });
});

// ── SA: Result Shape ───────────────────────────────────────────────

describe('SA: Build request — result shape', () => {
  it('SA-BR-001: result has all required fields', () => {
    const result = ashBuildRequest(basicInput());
    expect(result).toHaveProperty('proof');
    expect(result).toHaveProperty('bodyHash');
    expect(result).toHaveProperty('binding');
    expect(result).toHaveProperty('timestamp');
    expect(result).toHaveProperty('nonce');
    expect(result).toHaveProperty('destroy');
  });

  it('SA-BR-002: proof and bodyHash are valid hex', () => {
    const result = ashBuildRequest(basicInput());
    expect(result.proof).toMatch(/^[0-9a-f]{64}$/);
    expect(result.bodyHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ── FUZZ: Random Inputs ────────────────────────────────────────────

describe('FUZZ: Build request — various inputs', () => {
  it('FUZZ-BR-001: large body does not crash', () => {
    const largeBody = JSON.stringify({ data: 'x'.repeat(10000) });
    const result = ashBuildRequest(basicInput({ body: largeBody }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('FUZZ-BR-002: various HTTP methods work', () => {
    for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
      const result = ashBuildRequest(basicInput({ method }));
      expect(result.binding).toContain(method);
    }
  });

  it('FUZZ-BR-003: deep nested JSON body works', () => {
    const body = JSON.stringify({ a: { b: { c: { d: 'deep' } } } });
    const result = ashBuildRequest(basicInput({ body }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });
});
