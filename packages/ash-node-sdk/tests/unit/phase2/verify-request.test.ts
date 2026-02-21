/**
 * ASH Node SDK — Phase 2: Verify Request Orchestrator Tests
 *
 * Coverage: PT (tampered body, wrong binding, expired ts, forged proof) /
 * AQ (all 3 modes, empty body, missing fields) / SA (step ordering, error per step) /
 * FUZZ (random inputs, partial valid)
 */
import { describe, it, expect } from 'vitest';
import { ashVerifyRequest } from '../../../src/verify-request.js';
import type { VerifyRequestInput } from '../../../src/verify-request.js';
import { ashBuildRequest } from '../../../src/build-request.js';
import {
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '../../../src/headers.js';
import { AshErrorCode } from '../../../src/errors.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_verify_test';

function buildAndVerifyInput(overrides?: {
  buildOverrides?: Record<string, unknown>;
  verifyOverrides?: Partial<VerifyRequestInput>;
  headerOverrides?: Record<string, string>;
}): VerifyRequestInput {
  const ts = String(Math.floor(Date.now() / 1000));
  const body = '{"name":"Alice"}';

  const buildResult = ashBuildRequest({
    nonce: NONCE,
    contextId: CTX,
    method: 'POST',
    path: '/api/users',
    rawQuery: '',
    body,
    timestamp: ts,
    ...overrides?.buildOverrides,
  });

  const headers: Record<string, string> = {
    [X_ASH_TIMESTAMP]: buildResult.timestamp,
    [X_ASH_NONCE]: NONCE,
    [X_ASH_BODY_HASH]: buildResult.bodyHash,
    [X_ASH_PROOF]: buildResult.proof,
    [X_ASH_CONTEXT_ID]: CTX,
    ...overrides?.headerOverrides,
  };

  return {
    headers,
    method: 'POST',
    path: '/api/users',
    rawQuery: '',
    body,
    nonce: NONCE,
    contextId: CTX,
    maxAgeSeconds: 300,
    clockSkewSeconds: 30,
    ...overrides?.verifyOverrides,
  };
}

// ── AQ: Successful Verification ────────────────────────────────────

describe('AQ: Verify request — success', () => {
  it('AQ-VR-001: basic mode verification succeeds', () => {
    const input = buildAndVerifyInput();
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
    expect(result.meta).toBeDefined();
    expect(result.meta!.mode).toBe('basic');
  });

  it('AQ-VR-002: meta contains valid timestamp', () => {
    const input = buildAndVerifyInput();
    const result = ashVerifyRequest(input);
    expect(result.meta!.timestamp).toBeGreaterThan(0);
  });

  it('AQ-VR-003: meta contains binding', () => {
    const input = buildAndVerifyInput();
    const result = ashVerifyRequest(input);
    expect(result.meta!.binding).toContain('POST|');
  });

  it('AQ-VR-004: empty body verification succeeds', () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const buildResult = ashBuildRequest({
      nonce: NONCE,
      contextId: CTX,
      method: 'GET',
      path: '/api/users',
      body: '',
      timestamp: ts,
    });

    const result = ashVerifyRequest({
      headers: {
        [X_ASH_TIMESTAMP]: ts,
        [X_ASH_NONCE]: NONCE,
        [X_ASH_BODY_HASH]: buildResult.bodyHash,
        [X_ASH_PROOF]: buildResult.proof,
        [X_ASH_CONTEXT_ID]: CTX,
      },
      method: 'GET',
      path: '/api/users',
      body: '',
      nonce: NONCE,
      contextId: CTX,
    });
    expect(result.ok).toBe(true);
  });

  it('AQ-VR-005: scoped mode verification succeeds', () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const body = '{"name":"Alice","age":30}';

    const buildResult = ashBuildRequest({
      nonce: NONCE,
      contextId: CTX,
      method: 'POST',
      path: '/api/users',
      body,
      timestamp: ts,
      scope: ['name'],
    });

    const result = ashVerifyRequest({
      headers: {
        [X_ASH_TIMESTAMP]: ts,
        [X_ASH_NONCE]: NONCE,
        [X_ASH_BODY_HASH]: buildResult.bodyHash,
        [X_ASH_PROOF]: buildResult.proof,
        [X_ASH_CONTEXT_ID]: CTX,
      },
      method: 'POST',
      path: '/api/users',
      body,
      nonce: NONCE,
      contextId: CTX,
      scope: ['name'],
    });
    expect(result.ok).toBe(true);
    expect(result.meta!.mode).toBe('scoped');
  });
});

// ── PT: Tampered Requests ──────────────────────────────────────────

describe('PT: Verify request — tampered requests', () => {
  it('PT-VR-001: tampered body fails', () => {
    const input = buildAndVerifyInput();
    input.body = '{"name":"Bob"}';
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });

  it('PT-VR-002: wrong method fails', () => {
    const input = buildAndVerifyInput();
    input.method = 'GET';
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });

  it('PT-VR-003: wrong path fails', () => {
    const input = buildAndVerifyInput();
    input.path = '/api/orders';
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });

  it('PT-VR-004: forged proof fails', () => {
    const input = buildAndVerifyInput({
      headerOverrides: { [X_ASH_PROOF]: 'f'.repeat(64) },
    });
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });

  it('PT-VR-005: tampered body hash fails', () => {
    const input = buildAndVerifyInput({
      headerOverrides: { [X_ASH_BODY_HASH]: 'a'.repeat(64) },
    });
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });

  it('PT-VR-006: wrong nonce fails', () => {
    const input = buildAndVerifyInput({
      verifyOverrides: { nonce: 'f'.repeat(64) },
    });
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });

  it('PT-VR-007: wrong context ID fails', () => {
    const input = buildAndVerifyInput({
      verifyOverrides: { contextId: 'ctx_wrong' },
    });
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
  });
});

// ── PT: Missing Headers ────────────────────────────────────────────

describe('PT: Verify request — missing headers', () => {
  it('PT-VR-MISS-001: missing proof header returns error', () => {
    const input = buildAndVerifyInput();
    delete (input.headers as Record<string, string>)[X_ASH_PROOF];
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe(AshErrorCode.PROOF_MISSING);
  });

  it('PT-VR-MISS-002: missing timestamp header returns error', () => {
    const input = buildAndVerifyInput();
    delete (input.headers as Record<string, string>)[X_ASH_TIMESTAMP];
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe(AshErrorCode.PROOF_MISSING);
  });

  it('PT-VR-MISS-003: missing nonce header returns error', () => {
    const input = buildAndVerifyInput();
    delete (input.headers as Record<string, string>)[X_ASH_NONCE];
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe(AshErrorCode.PROOF_MISSING);
  });
});

// ── PT: Expired Timestamp ──────────────────────────────────────────

describe('PT: Verify request — expired timestamp', () => {
  it('PT-VR-EXP-001: old timestamp returns error', () => {
    const oldTs = String(Math.floor(Date.now() / 1000) - 600);
    const input = buildAndVerifyInput({
      buildOverrides: { timestamp: oldTs },
    });
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe(AshErrorCode.TIMESTAMP_INVALID);
  });

  it('PT-VR-EXP-002: future timestamp beyond clock skew returns error', () => {
    const futureTs = String(Math.floor(Date.now() / 1000) + 600);
    const input = buildAndVerifyInput({
      buildOverrides: { timestamp: futureTs },
    });
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe(AshErrorCode.TIMESTAMP_INVALID);
  });
});

// ── SA: Error Handling ─────────────────────────────────────────────

describe('SA: Verify request — error handling', () => {
  it('SA-VR-001: errors are returned, not thrown', () => {
    const result = ashVerifyRequest({
      headers: {},
      method: 'GET',
      path: '/api',
      nonce: NONCE,
      contextId: CTX,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('SA-VR-002: error has AshError shape', () => {
    const result = ashVerifyRequest({
      headers: {},
      method: 'GET',
      path: '/api',
      nonce: NONCE,
      contextId: CTX,
    });
    expect(result.error).toHaveProperty('code');
    expect(result.error).toHaveProperty('httpStatus');
  });

  it('SA-VR-003: successful result has no error', () => {
    const input = buildAndVerifyInput();
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(true);
    expect(result.error).toBeUndefined();
  });
});

// ── FUZZ: Edge Cases ───────────────────────────────────────────────

describe('FUZZ: Verify request — edge cases', () => {
  it('FUZZ-VR-001: completely empty headers object', () => {
    const result = ashVerifyRequest({
      headers: {},
      method: 'GET',
      path: '/',
      nonce: NONCE,
      contextId: CTX,
    });
    expect(result.ok).toBe(false);
  });

  it('FUZZ-VR-002: extra headers do not interfere', () => {
    const input = buildAndVerifyInput();
    (input.headers as Record<string, string>)['x-custom'] = 'value';
    (input.headers as Record<string, string>)['authorization'] = 'Bearer xyz';
    const result = ashVerifyRequest(input);
    expect(result.ok).toBe(true);
  });

  it('FUZZ-VR-003: case-insensitive header names work', () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const body = '{"name":"Alice"}';
    const buildResult = ashBuildRequest({
      nonce: NONCE, contextId: CTX, method: 'POST', path: '/api/users',
      body, timestamp: ts,
    });

    const result = ashVerifyRequest({
      headers: {
        'X-ASH-TS': ts,
        'X-ASH-NONCE': NONCE,
        'X-ASH-BODY-HASH': buildResult.bodyHash,
        'X-ASH-PROOF': buildResult.proof,
        'X-ASH-CONTEXT-ID': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body,
      nonce: NONCE,
      contextId: CTX,
    });
    expect(result.ok).toBe(true);
  });
});
