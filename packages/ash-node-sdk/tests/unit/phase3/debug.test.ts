/**
 * ASH Node SDK — Phase 3: Debug Trace Tests
 *
 * Coverage: PT (secret leakage, tamper detection, error safety)
 *           AQ (step counts, modes, timing, error traces, formatting)
 *           SA (no secrets in trace, safe error messages)
 *           FUZZ (random inputs, unicode, large bodies, roundtrips)
 */
import { describe, it, expect } from 'vitest';
import { ashBuildRequestDebug, ashVerifyRequestDebug, ashFormatTrace } from '../../../src/debug.js';
import { ashBuildRequest } from '../../../src/build-request.js';
import { ashVerifyRequest } from '../../../src/verify-request.js';
import type { BuildRequestInput } from '../../../src/build-request.js';
import type { VerifyRequestInput } from '../../../src/verify-request.js';
import { SHA256_HEX_LENGTH } from '../../../src/constants.js';
import { randomBytes } from 'node:crypto';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_debug_test';
const TS = String(Math.floor(Date.now() / 1000));

function basicBuildInput(overrides?: Partial<BuildRequestInput>): BuildRequestInput {
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

function makeVerifyInput(buildResult: ReturnType<typeof ashBuildRequest>, overrides?: Partial<VerifyRequestInput>): VerifyRequestInput {
  return {
    headers: {
      'x-ash-ts': buildResult.timestamp,
      'x-ash-nonce': buildResult.nonce,
      'x-ash-body-hash': buildResult.bodyHash,
      'x-ash-proof': buildResult.proof,
      'x-ash-context-id': CTX,
    },
    method: 'POST',
    path: '/api/users',
    rawQuery: '',
    body: '{"name":"Alice"}',
    nonce: NONCE,
    contextId: CTX,
    maxAgeSeconds: 300,
    clockSkewSeconds: 30,
    ...overrides,
  };
}

// ── PT: Penetration Tests ─────────────────────────────────────────

describe('PT: Debug trace — secret protection', () => {
  it('PT-DBG-001: trace never contains full clientSecret', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const traceJson = JSON.stringify(result.trace);
    // clientSecret should be REDACTED, not the full 64-char hex
    expect(traceJson).toContain('[REDACTED]');
    // The actual derived secret should NOT appear in trace
    expect(traceJson).not.toMatch(/[0-9a-f]{64}.*[0-9a-f]{64}/);
  });

  it('PT-DBG-002: verify trace never leaks clientSecret', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    // Should not find any 64-char hex strings that could be secrets
    // (proofs and hashes are redacted to first8...)
    for (const step of result.trace) {
      if (step.name === 'derive_secret' || step.name === 'verify_proof') {
        const outputJson = JSON.stringify(step.output);
        expect(outputJson).not.toMatch(/"[0-9a-f]{64}"/);
      }
    }
  });

  it('PT-DBG-003: invalid inputs produce error trace not crash', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ nonce: 'bad' }));
    expect(result.proof).toBe('');
    expect(result.trace.length).toBeGreaterThanOrEqual(1);
    const lastStep = result.trace[result.trace.length - 1];
    expect(lastStep.ok).toBe(false);
    expect(lastStep.error).toBeDefined();
  });

  it('PT-DBG-004: tampered body detected at correct step', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult, { body: '{"name":"Bob"}' }));
    expect(result.ok).toBe(false);
    // Should fail at compare_body_hash (step 7) or verify_proof (step 8)
    const failedStep = result.trace.find(s => !s.ok);
    expect(failedStep).toBeDefined();
    expect(['compare_body_hash', 'verify_proof']).toContain(failedStep!.name);
  });

  it('PT-DBG-005: debug trace doesnt change proof output vs non-debug', () => {
    const input = basicBuildInput();
    const debugResult = ashBuildRequestDebug(input);
    const normalResult = ashBuildRequest(input);
    expect(debugResult.proof).toBe(normalResult.proof);
    expect(debugResult.bodyHash).toBe(normalResult.bodyHash);
    expect(debugResult.binding).toBe(normalResult.binding);
    expect(debugResult.timestamp).toBe(normalResult.timestamp);
  });

  it('PT-DBG-006: tampered proof detected at verify_proof step', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const tamperedHeaders = {
      'x-ash-ts': buildResult.timestamp,
      'x-ash-nonce': buildResult.nonce,
      'x-ash-body-hash': buildResult.bodyHash,
      'x-ash-proof': 'a'.repeat(64),
      'x-ash-context-id': CTX,
    };
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult, { headers: tamperedHeaders }));
    expect(result.ok).toBe(false);
    const failedStep = result.trace.find(s => !s.ok);
    expect(failedStep).toBeDefined();
    expect(failedStep!.name).toBe('verify_proof');
  });

  it('PT-DBG-007: tampered timestamp format produces error trace', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const tamperedHeaders = {
      'x-ash-ts': 'notdigits',
      'x-ash-nonce': buildResult.nonce,
      'x-ash-body-hash': buildResult.bodyHash,
      'x-ash-proof': buildResult.proof,
      'x-ash-context-id': CTX,
    };
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult, { headers: tamperedHeaders }));
    expect(result.ok).toBe(false);
    const failedStep = result.trace.find(s => !s.ok);
    expect(failedStep).toBeDefined();
    expect(failedStep!.name).toBe('validate_timestamp_format');
  });
});

// ── AQ: Assurance / Quality Tests ─────────────────────────────────

describe('AQ: Debug trace — build pipeline', () => {
  it('AQ-DBG-001: build trace has exactly 7 steps in order', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    expect(result.trace).toHaveLength(7);
    expect(result.trace.map(s => s.step)).toEqual([1, 2, 3, 4, 5, 6, 7]);
  });

  it('AQ-DBG-002: build trace step names match pipeline', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    expect(result.trace.map(s => s.name)).toEqual([
      'validate_nonce',
      'validate_timestamp',
      'normalize_binding',
      'hash_body',
      'derive_secret',
      'build_proof',
      'assemble_result',
    ]);
  });

  it('AQ-DBG-003: all steps marked ok=true on success', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    for (const step of result.trace) {
      expect(step.ok).toBe(true);
      expect(step.error).toBeUndefined();
    }
  });

  it('AQ-DBG-004: durationMs is non-negative for every step', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    for (const step of result.trace) {
      expect(step.durationMs).toBeGreaterThanOrEqual(0);
    }
  });

  it('AQ-DBG-005: totalDurationMs is non-negative', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('AQ-DBG-006: error at step 1 produces 1 trace entry', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ nonce: 'bad' }));
    expect(result.trace).toHaveLength(1);
    expect(result.trace[0].ok).toBe(false);
    expect(result.trace[0].name).toBe('validate_nonce');
  });

  it('AQ-DBG-007: error at step 2 produces 2 trace entries', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ timestamp: 'abc' }));
    expect(result.trace).toHaveLength(2);
    expect(result.trace[0].ok).toBe(true);
    expect(result.trace[1].ok).toBe(false);
    expect(result.trace[1].name).toBe('validate_timestamp');
  });

  it('AQ-DBG-008: timestamp auto-generation traced as generated=true', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ timestamp: undefined }));
    const tsStep = result.trace.find(s => s.name === 'validate_timestamp');
    expect(tsStep).toBeDefined();
    expect(tsStep!.input.generated).toBe(true);
  });

  it('AQ-DBG-009: explicit timestamp traced as generated=false', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const tsStep = result.trace.find(s => s.name === 'validate_timestamp');
    expect(tsStep!.input.generated).toBe(false);
  });

  it('AQ-DBG-010: empty body traced correctly', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ body: '' }));
    const hashStep = result.trace.find(s => s.name === 'hash_body');
    expect(hashStep!.input.bodyLength).toBe(0);
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('AQ-DBG-011: undefined body treated as empty', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ body: undefined }));
    const hashStep = result.trace.find(s => s.name === 'hash_body');
    expect(hashStep!.input.bodyLength).toBe(0);
  });

  it('AQ-DBG-012: query string flows through to binding', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ rawQuery: 'page=1&sort=name' }));
    const bindStep = result.trace.find(s => s.name === 'normalize_binding');
    expect(bindStep!.input.rawQuery).toBe('page=1&sort=name');
  });
});

describe('AQ: Debug trace — mode detection', () => {
  it('AQ-DBG-MODE-001: basic mode traced correctly', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    expect(result.mode).toBe('basic');
    const proofStep = result.trace.find(s => s.name === 'build_proof');
    expect(proofStep!.input.mode).toBe('basic');
  });

  it('AQ-DBG-MODE-002: scoped mode traced correctly', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ scope: ['name'] }));
    expect(result.mode).toBe('scoped');
    expect(result.scopeHash).toBeDefined();
    expect(result.scopeHash).toHaveLength(SHA256_HEX_LENGTH);
    const proofStep = result.trace.find(s => s.name === 'build_proof');
    expect(proofStep!.input.mode).toBe('scoped');
  });

  it('AQ-DBG-MODE-003: unified mode traced correctly', () => {
    const first = ashBuildRequest(basicBuildInput());
    const result = ashBuildRequestDebug(basicBuildInput({
      scope: ['name'],
      previousProof: first.proof,
    }));
    expect(result.mode).toBe('unified');
    expect(result.chainHash).toBeDefined();
    const proofStep = result.trace.find(s => s.name === 'build_proof');
    expect(proofStep!.input.mode).toBe('unified');
  });

  it('AQ-DBG-MODE-004: unified without scope still works', () => {
    const first = ashBuildRequest(basicBuildInput());
    const result = ashBuildRequestDebug(basicBuildInput({
      previousProof: first.proof,
    }));
    expect(result.mode).toBe('unified');
    expect(result.chainHash).toBeDefined();
  });
});

describe('AQ: Debug trace — verify pipeline', () => {
  it('AQ-DBG-V-001: verify trace has exactly 9 steps on success', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    expect(result.ok).toBe(true);
    expect(result.trace).toHaveLength(9);
    expect(result.trace.map(s => s.step)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  it('AQ-DBG-V-002: verify trace step names match pipeline', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    expect(result.trace.map(s => s.name)).toEqual([
      'extract_headers',
      'validate_timestamp_format',
      'validate_freshness',
      'validate_nonce',
      'normalize_binding',
      'hash_body',
      'compare_body_hash',
      'verify_proof',
      'assemble_result',
    ]);
  });

  it('AQ-DBG-V-003: all verify steps ok=true on valid request', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    for (const step of result.trace) {
      expect(step.ok).toBe(true);
    }
  });

  it('AQ-DBG-V-004: verify durationMs non-negative for all steps', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    for (const step of result.trace) {
      expect(step.durationMs).toBeGreaterThanOrEqual(0);
    }
  });

  it('AQ-DBG-V-005: verify totalDurationMs is non-negative', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
  });

  it('AQ-DBG-V-006: missing headers produces 1 error trace entry', () => {
    const result = ashVerifyRequestDebug(makeVerifyInput(
      ashBuildRequest(basicBuildInput()),
      { headers: {} },
    ));
    expect(result.ok).toBe(false);
    expect(result.trace.length).toBeGreaterThanOrEqual(1);
    expect(result.trace[result.trace.length - 1].ok).toBe(false);
    expect(result.trace[result.trace.length - 1].name).toBe('extract_headers');
  });

  it('AQ-DBG-V-007: verify meta present on success', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    expect(result.meta).toBeDefined();
    expect(result.meta!.mode).toBe('basic');
    expect(result.meta!.binding).toContain('POST|');
  });

  it('AQ-DBG-V-008: scoped verify traced correctly', () => {
    const buildResult = ashBuildRequest(basicBuildInput({ scope: ['name'] }));
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult, { scope: ['name'] }));
    expect(result.ok).toBe(true);
    expect(result.meta!.mode).toBe('scoped');
  });

  it('AQ-DBG-V-009: unified verify traced correctly', () => {
    const first = ashBuildRequest(basicBuildInput());
    const buildResult = ashBuildRequest(basicBuildInput({
      scope: ['name'],
      previousProof: first.proof,
    }));
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult, {
      scope: ['name'],
      previousProof: first.proof,
    }));
    expect(result.ok).toBe(true);
    expect(result.meta!.mode).toBe('unified');
  });
});

describe('AQ: formatTrace', () => {
  it('AQ-FMT-001: formatTrace output contains all step names', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const formatted = ashFormatTrace(result.trace);
    for (const step of result.trace) {
      expect(formatted).toContain(step.name);
    }
  });

  it('AQ-FMT-002: formatTrace handles empty trace array', () => {
    const formatted = ashFormatTrace([]);
    expect(formatted).toBe('(empty trace)');
  });

  it('AQ-FMT-003: formatTrace includes step numbers', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const formatted = ashFormatTrace(result.trace);
    expect(formatted).toContain('[1/7]');
    expect(formatted).toContain('[7/7]');
  });

  it('AQ-FMT-004: formatTrace shows OK for successful steps', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const formatted = ashFormatTrace(result.trace);
    expect(formatted).toContain('OK');
  });

  it('AQ-FMT-005: formatTrace shows FAIL for error steps', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ nonce: 'bad' }));
    const formatted = ashFormatTrace(result.trace);
    expect(formatted).toContain('FAIL');
  });

  it('AQ-FMT-006: formatTrace includes duration in ms', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const formatted = ashFormatTrace(result.trace);
    expect(formatted).toMatch(/\d+\.\d+ms/);
  });

  it('AQ-FMT-007: formatTrace includes error message on failure', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ nonce: 'bad' }));
    const formatted = ashFormatTrace(result.trace);
    expect(formatted).toContain('error:');
  });
});

// ── SA: Security Audit Tests ──────────────────────────────────────

describe('SA: Debug trace — security', () => {
  it('SA-DBG-001: no clientSecret value in any build trace step output', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    for (const step of result.trace) {
      const outputJson = JSON.stringify(step.output);
      // clientSecret is 64 hex chars; should only appear as [REDACTED]
      if (step.name === 'derive_secret') {
        expect(outputJson).toContain('[REDACTED]');
      }
    }
  });

  it('SA-DBG-002: no full proof in intermediate trace steps', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const proofStep = result.trace.find(s => s.name === 'build_proof');
    const outputJson = JSON.stringify(proofStep!.output);
    // Should contain truncated proof (first8...), not full 64-char
    expect(outputJson).toContain('...');
  });

  it('SA-DBG-003: no nonce-contextId-binding triple with secret', () => {
    const result = ashBuildRequestDebug(basicBuildInput());
    const deriveStep = result.trace.find(s => s.name === 'derive_secret');
    const outputJson = JSON.stringify(deriveStep!.output);
    // Output should only have [REDACTED], not the actual secret
    expect(outputJson).not.toMatch(/"[0-9a-f]{64}"/);
  });

  it('SA-DBG-004: error messages safe for logging', () => {
    const result = ashBuildRequestDebug(basicBuildInput({ nonce: 'bad' }));
    const failStep = result.trace.find(s => !s.ok);
    expect(failStep!.error).toBeDefined();
    // Error message should not contain the valid context ID
    expect(failStep!.error).not.toContain(CTX);
  });

  it('SA-DBG-005: debug verify returns same ok as non-debug', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const verifyInput = makeVerifyInput(buildResult);
    const debugResult = ashVerifyRequestDebug(verifyInput);
    const normalResult = ashVerifyRequest(verifyInput);
    expect(debugResult.ok).toBe(normalResult.ok);
  });

  it('SA-DBG-007: verify trace nonce is redacted', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    const headerStep = result.trace.find(s => s.name === 'extract_headers');
    const output = headerStep!.output as Record<string, unknown>;
    // Nonce should be truncated
    expect(String(output.nonce)).toContain('...');
  });

  it('SA-DBG-008: verify trace proof is redacted', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    const headerStep = result.trace.find(s => s.name === 'extract_headers');
    const output = headerStep!.output as Record<string, unknown>;
    expect(String(output.proof)).toContain('...');
  });

  it('SA-DBG-009: body hash comparison values are redacted', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult));
    const compareStep = result.trace.find(s => s.name === 'compare_body_hash');
    expect(String(compareStep!.input.computed)).toContain('...');
    expect(String(compareStep!.input.received)).toContain('...');
  });
});

// ── FUZZ: Fuzzing Tests ───────────────────────────────────────────

describe('FUZZ: Debug trace — random inputs', () => {
  it('FUZZ-DBG-001: random valid inputs produce valid traces', () => {
    for (let i = 0; i < 10; i++) {
      const nonce = randomBytes(32).toString('hex');
      const result = ashBuildRequestDebug(basicBuildInput({ nonce }));
      expect(result.trace.length).toBe(7);
      expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    }
  });

  it('FUZZ-DBG-002: random invalid nonces dont crash', () => {
    const badNonces = ['', 'xyz', '!@#$', 'a'.repeat(1000), '\x00\x01\x02'];
    for (const nonce of badNonces) {
      const result = ashBuildRequestDebug(basicBuildInput({ nonce }));
      expect(result.trace.length).toBeGreaterThanOrEqual(1);
      expect(result.trace[result.trace.length - 1].ok).toBe(false);
    }
  });

  it('FUZZ-DBG-003: unicode body traced without corruption', () => {
    const unicodeBodies = [
      '{"text":"مرحبا"}',
      '{"emoji":"🎉🎊"}',
      '{"jp":"日本語"}',
      '{"mixed":"hello مرحبا 你好"}',
    ];
    for (const body of unicodeBodies) {
      const result = ashBuildRequestDebug(basicBuildInput({ body }));
      expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
      expect(result.trace).toHaveLength(7);
    }
  });

  it('FUZZ-DBG-004: very large body traced with correct length', () => {
    const largeBody = JSON.stringify({ data: 'x'.repeat(50000) });
    const result = ashBuildRequestDebug(basicBuildInput({ body: largeBody }));
    const hashStep = result.trace.find(s => s.name === 'hash_body');
    expect(hashStep!.input.bodyLength).toBe(largeBody.length);
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('FUZZ-DBG-005: 20 random build+verify roundtrips with trace validation', () => {
    for (let i = 0; i < 20; i++) {
      const nonce = randomBytes(32).toString('hex');
      const buildInput = basicBuildInput({ nonce });
      const buildResult = ashBuildRequestDebug(buildInput);

      expect(buildResult.proof).toHaveLength(SHA256_HEX_LENGTH);
      expect(buildResult.trace).toHaveLength(7);

      const verifyResult = ashVerifyRequestDebug(makeVerifyInput(
        { ...buildResult },
        { nonce },
      ));
      expect(verifyResult.ok).toBe(true);
      expect(verifyResult.trace).toHaveLength(9);
    }
  });

  it('FUZZ-DBG-006: various invalid timestamps dont crash debug', () => {
    const badTimestamps = ['abc', '-1', '0.5', '', '999999999999999999'];
    for (const ts of badTimestamps) {
      const result = ashBuildRequestDebug(basicBuildInput({ timestamp: ts }));
      expect(result.trace.length).toBeGreaterThanOrEqual(1);
      // Either succeeds with a valid proof or fails gracefully
      expect(result.proof.length === SHA256_HEX_LENGTH || result.proof === '').toBe(true);
    }
  });

  it('FUZZ-DBG-007: various methods work in debug mode', () => {
    for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']) {
      const result = ashBuildRequestDebug(basicBuildInput({ method }));
      expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
      expect(result.mode).toBe('basic');
    }
  });

  it('FUZZ-DBG-008: deep nested JSON body in debug mode', () => {
    const body = JSON.stringify({ a: { b: { c: { d: { e: 'deep' } } } } });
    const result = ashBuildRequestDebug(basicBuildInput({ body }));
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('FUZZ-DBG-009: scope with many fields works', () => {
    const scope = Array.from({ length: 10 }, (_, i) => `field${i}`);
    const body = JSON.stringify(Object.fromEntries(scope.map(f => [f, `value_${f}`])));
    const result = ashBuildRequestDebug(basicBuildInput({ body, scope }));
    expect(result.mode).toBe('scoped');
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('FUZZ-DBG-010: verify with random garbage headers doesnt crash', () => {
    const buildResult = ashBuildRequest(basicBuildInput());
    const result = ashVerifyRequestDebug(makeVerifyInput(buildResult, {
      headers: { 'x-random': 'garbage', 'content-type': 'text/plain' },
    }));
    expect(result.ok).toBe(false);
    expect(result.trace.length).toBeGreaterThanOrEqual(1);
  });
});
