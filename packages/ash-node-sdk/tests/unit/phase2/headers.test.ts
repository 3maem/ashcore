/**
 * ASH Node SDK — Phase 2: Headers Module Tests
 *
 * Coverage: PT (injection, control chars, oversized) / AQ (missing, empty,
 * multi-value, case) / SA (constant correctness) / FUZZ (random names/values)
 */
import { describe, it, expect } from 'vitest';
import {
  ashExtractHeaders,
  X_ASH_TIMESTAMP,
  X_ASH_NONCE,
  X_ASH_BODY_HASH,
  X_ASH_PROOF,
  X_ASH_CONTEXT_ID,
} from '../../../src/headers.js';
import { AshErrorCode } from '../../../src/errors.js';

const VALID_NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const VALID_BODY_HASH = 'a'.repeat(64);
const VALID_PROOF = 'b'.repeat(64);
const VALID_TS = '1700000000';
const VALID_CTX = 'ctx_test_123';

function validHeaders(): Record<string, string> {
  return {
    [X_ASH_TIMESTAMP]: VALID_TS,
    [X_ASH_NONCE]: VALID_NONCE,
    [X_ASH_BODY_HASH]: VALID_BODY_HASH,
    [X_ASH_PROOF]: VALID_PROOF,
    [X_ASH_CONTEXT_ID]: VALID_CTX,
  };
}

// ── SA: Constant Correctness ───────────────────────────────────────

describe('SA: Header constants', () => {
  it('SA-HDR-001: header names are lowercase kebab-case', () => {
    expect(X_ASH_TIMESTAMP).toBe('x-ash-ts');
    expect(X_ASH_NONCE).toBe('x-ash-nonce');
    expect(X_ASH_BODY_HASH).toBe('x-ash-body-hash');
    expect(X_ASH_PROOF).toBe('x-ash-proof');
    expect(X_ASH_CONTEXT_ID).toBe('x-ash-context-id');
  });

  it('SA-HDR-002: all five header constants are unique', () => {
    const all = [X_ASH_TIMESTAMP, X_ASH_NONCE, X_ASH_BODY_HASH, X_ASH_PROOF, X_ASH_CONTEXT_ID];
    expect(new Set(all).size).toBe(5);
  });
});

// ── AQ: Normal Extraction ──────────────────────────────────────────

describe('AQ: Header extraction — happy path', () => {
  it('AQ-HDR-001: extracts all headers from valid map', () => {
    const result = ashExtractHeaders(validHeaders());
    expect(result.timestamp).toBe(VALID_TS);
    expect(result.nonce).toBe(VALID_NONCE);
    expect(result.bodyHash).toBe(VALID_BODY_HASH);
    expect(result.proof).toBe(VALID_PROOF);
    expect(result.contextId).toBe(VALID_CTX);
  });

  it('AQ-HDR-002: case-insensitive lookup (uppercase)', () => {
    const headers = {
      'X-ASH-TS': VALID_TS,
      'X-ASH-NONCE': VALID_NONCE,
      'X-ASH-BODY-HASH': VALID_BODY_HASH,
      'X-ASH-PROOF': VALID_PROOF,
      'X-ASH-CONTEXT-ID': VALID_CTX,
    };
    const result = ashExtractHeaders(headers);
    expect(result.timestamp).toBe(VALID_TS);
    expect(result.proof).toBe(VALID_PROOF);
  });

  it('AQ-HDR-003: case-insensitive lookup (mixed case)', () => {
    const headers = {
      'X-Ash-Ts': VALID_TS,
      'X-Ash-Nonce': VALID_NONCE,
      'X-Ash-Body-Hash': VALID_BODY_HASH,
      'X-Ash-Proof': VALID_PROOF,
      'X-Ash-Context-Id': VALID_CTX,
    };
    const result = ashExtractHeaders(headers);
    expect(result.timestamp).toBe(VALID_TS);
  });

  it('AQ-HDR-004: multi-value array concatenation', () => {
    const headers: Record<string, string | string[]> = {
      [X_ASH_TIMESTAMP]: VALID_TS,
      [X_ASH_NONCE]: VALID_NONCE,
      [X_ASH_BODY_HASH]: VALID_BODY_HASH,
      [X_ASH_PROOF]: VALID_PROOF,
      [X_ASH_CONTEXT_ID]: ['ctx_a', 'ctx_b'],
    };
    const result = ashExtractHeaders(headers);
    expect(result.contextId).toBe('ctx_a, ctx_b');
  });

  it('AQ-HDR-005: returns correct AshHeaderBundle shape', () => {
    const result = ashExtractHeaders(validHeaders());
    const keys = Object.keys(result).sort();
    expect(keys).toEqual(['bodyHash', 'contextId', 'nonce', 'proof', 'timestamp']);
  });
});

// ── AQ: Missing / Empty Headers ────────────────────────────────────

describe('AQ: Header extraction — missing/empty', () => {
  const required = [
    ['timestamp', X_ASH_TIMESTAMP],
    ['nonce', X_ASH_NONCE],
    ['bodyHash', X_ASH_BODY_HASH],
    ['proof', X_ASH_PROOF],
    ['contextId', X_ASH_CONTEXT_ID],
  ] as const;

  for (const [label, headerName] of required) {
    it(`AQ-HDR-MISS-${label}: throws PROOF_MISSING when ${headerName} is absent`, () => {
      const h = validHeaders();
      delete (h as Record<string, string>)[headerName];
      expect(() => ashExtractHeaders(h)).toThrowError(
        expect.objectContaining({ code: AshErrorCode.PROOF_MISSING }),
      );
    });

    it(`AQ-HDR-EMPTY-${label}: throws PROOF_MISSING when ${headerName} is empty string`, () => {
      const h = validHeaders();
      (h as Record<string, string>)[headerName] = '';
      expect(() => ashExtractHeaders(h)).toThrowError(
        expect.objectContaining({ code: AshErrorCode.PROOF_MISSING }),
      );
    });
  }

  it('AQ-HDR-UNDEF: throws PROOF_MISSING when header value is undefined', () => {
    const h: Record<string, string | undefined> = validHeaders();
    h[X_ASH_PROOF] = undefined;
    expect(() => ashExtractHeaders(h)).toThrowError(
      expect.objectContaining({ code: AshErrorCode.PROOF_MISSING }),
    );
  });
});

// ── PT: Control Character Injection ────────────────────────────────

describe('PT: Header injection — control characters', () => {
  it('PT-HDR-001: rejects null byte in timestamp', () => {
    const h = validHeaders();
    h[X_ASH_TIMESTAMP] = '17000\x0000000';
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-002: rejects newline in nonce', () => {
    const h = validHeaders();
    h[X_ASH_NONCE] = VALID_NONCE.slice(0, 32) + '\n' + VALID_NONCE.slice(33);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-003: rejects carriage return in proof', () => {
    const h = validHeaders();
    h[X_ASH_PROOF] = VALID_PROOF.slice(0, 32) + '\r' + VALID_PROOF.slice(33);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-004: allows tab character (0x09)', () => {
    // Tab is the one control char exception
    const h = validHeaders();
    h[X_ASH_CONTEXT_ID] = 'ctx\ttest';
    // Should not throw on control-char check, but may fail length or other check
    // Tab (0x09) is explicitly excluded from control char rejection
    const result = ashExtractHeaders(h);
    expect(result.contextId).toBe('ctx\ttest');
  });

  it('PT-HDR-005: rejects form feed (0x0C) in body hash', () => {
    const h = validHeaders();
    h[X_ASH_BODY_HASH] = 'a'.repeat(32) + '\x0C' + 'a'.repeat(31);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-006: rejects bell character (0x07) in context ID', () => {
    const h = validHeaders();
    h[X_ASH_CONTEXT_ID] = 'ctx\x07test';
    expect(() => ashExtractHeaders(h)).toThrow();
  });
});

// ── PT: Oversized Headers ──────────────────────────────────────────

describe('PT: Header extraction — oversized values', () => {
  it('PT-HDR-OVER-001: rejects nonce exceeding MAX_NONCE_LENGTH', () => {
    const h = validHeaders();
    h[X_ASH_NONCE] = 'a'.repeat(513);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-OVER-002: rejects body hash longer than 64 chars', () => {
    const h = validHeaders();
    h[X_ASH_BODY_HASH] = 'a'.repeat(65);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-OVER-003: rejects proof longer than 64 chars', () => {
    const h = validHeaders();
    h[X_ASH_PROOF] = 'b'.repeat(65);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-OVER-004: rejects context ID longer than 256 chars', () => {
    const h = validHeaders();
    h[X_ASH_CONTEXT_ID] = 'c'.repeat(257);
    expect(() => ashExtractHeaders(h)).toThrow();
  });

  it('PT-HDR-OVER-005: rejects timestamp longer than 16 chars', () => {
    const h = validHeaders();
    h[X_ASH_TIMESTAMP] = '1'.repeat(17);
    expect(() => ashExtractHeaders(h)).toThrow();
  });
});

// ── FUZZ: Random values ────────────────────────────────────────────

describe('FUZZ: Header extraction — random inputs', () => {
  it('FUZZ-HDR-001: ignores unrelated headers', () => {
    const h: Record<string, string> = {
      ...validHeaders(),
      'x-custom-header': 'some value',
      'authorization': 'Bearer token',
      'content-type': 'application/json',
    };
    const result = ashExtractHeaders(h);
    expect(result.timestamp).toBe(VALID_TS);
  });

  it('FUZZ-HDR-002: empty header map throws PROOF_MISSING', () => {
    expect(() => ashExtractHeaders({})).toThrowError(
      expect.objectContaining({ code: AshErrorCode.PROOF_MISSING }),
    );
  });

  it('FUZZ-HDR-003: all undefined values throw PROOF_MISSING', () => {
    const h: Record<string, undefined> = {
      [X_ASH_TIMESTAMP]: undefined,
      [X_ASH_NONCE]: undefined,
      [X_ASH_BODY_HASH]: undefined,
      [X_ASH_PROOF]: undefined,
      [X_ASH_CONTEXT_ID]: undefined,
    };
    expect(() => ashExtractHeaders(h)).toThrowError(
      expect.objectContaining({ code: AshErrorCode.PROOF_MISSING }),
    );
  });

  it('FUZZ-HDR-004: Unicode in context ID is accepted if within limits', () => {
    const h = validHeaders();
    h[X_ASH_CONTEXT_ID] = 'ctx_\u00e9\u00e8\u00ea';
    const result = ashExtractHeaders(h);
    expect(result.contextId).toBe('ctx_\u00e9\u00e8\u00ea');
  });

  it('FUZZ-HDR-005: exact max-length nonce (512 chars) is accepted', () => {
    const h = validHeaders();
    h[X_ASH_NONCE] = 'a'.repeat(512);
    const result = ashExtractHeaders(h);
    expect(result.nonce.length).toBe(512);
  });

  it('FUZZ-HDR-006: exact max-length body hash (64 chars) is accepted', () => {
    const h = validHeaders();
    h[X_ASH_BODY_HASH] = 'f'.repeat(64);
    const result = ashExtractHeaders(h);
    expect(result.bodyHash.length).toBe(64);
  });
});
