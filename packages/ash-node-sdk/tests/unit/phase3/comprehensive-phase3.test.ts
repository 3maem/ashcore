/**
 * ASH Node SDK — Phase 3: Comprehensive Cross-Cutting Tests
 *
 * Tests debug↔CLI interop, SDK↔CLI roundtrips, regression,
 * determinism, and concurrent safety.
 */
import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ashBuildRequest } from '../../../src/build-request.js';
import { ashVerifyRequest } from '../../../src/verify-request.js';
import { ashBuildRequestDebug, ashVerifyRequestDebug, ashFormatTrace } from '../../../src/debug.js';
import { ashHashBody, ashHashScope, ashHashProof } from '../../../src/hash.js';
import { ashDeriveClientSecret } from '../../../src/proof.js';
import { ashCanonicalizeJson } from '../../../src/canonicalize.js';
import type { BuildRequestInput } from '../../../src/build-request.js';
import { SHA256_HEX_LENGTH } from '../../../src/constants.js';

const CLI_PATH = resolve(__dirname, '../../../dist/cli.js');
const NODE = process.execPath;

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_comp_test';
const TS = String(Math.floor(Date.now() / 1000));

interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

function runCli(args: string[], timeout = 10000): Promise<CliResult> {
  return new Promise((resolve) => {
    const child = execFile(
      NODE, [CLI_PATH, ...args],
      {
        timeout,
        encoding: 'utf8',
        env: { ...process.env, MSYS_NO_PATHCONV: '1' },
      },
      (error, stdout, stderr) => {
        resolve({
          stdout: stdout ?? '',
          stderr: stderr ?? '',
          exitCode: error ? (error as any).code ?? error.status ?? (child.exitCode ?? 1) : 0,
        });
      },
    );
  });
}

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

// ── Debug ↔ CLI Inspect Consistency ──────────────────────────────

describe('Cross-cutting: Debug ↔ CLI inspect consistency', () => {
  it('CC-DI-001: debug build trace matches CLI inspect build trace', async () => {
    const debugResult = ashBuildRequestDebug(basicInput());

    const cliR = await runCli([
      'inspect', 'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice"}', '--timestamp', TS, '--json',
    ]);
    expect(cliR.exitCode).toBe(0);
    const cliOut = JSON.parse(cliR.stdout);

    // Same number of trace steps
    expect(cliOut.trace).toHaveLength(debugResult.trace.length);
    // Same step names
    expect(cliOut.trace.map((s: any) => s.name)).toEqual(
      debugResult.trace.map(s => s.name),
    );
    // Same mode
    expect(cliOut.mode).toBe(debugResult.mode);
    // Same proof
    expect(cliOut.proof).toBe(debugResult.proof);
  });

  it('CC-DI-002: debug verify trace matches CLI inspect verify trace', async () => {
    const buildResult = ashBuildRequest(basicInput());
    const debugVerify = ashVerifyRequestDebug({
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
    });

    const cliR = await runCli([
      'inspect', 'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice"}',
      '--proof', buildResult.proof,
      '--body-hash', buildResult.bodyHash,
      '--timestamp', buildResult.timestamp,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);

    const cliOut = JSON.parse(cliR.stdout);

    expect(cliOut.trace).toHaveLength(debugVerify.trace.length);
    expect(cliOut.ok).toBe(debugVerify.ok);
    expect(cliOut.trace.map((s: any) => s.name)).toEqual(
      debugVerify.trace.map(s => s.name),
    );
  });
});

// ── SDK → CLI Interop ────────────────────────────────────────────

describe('Cross-cutting: SDK build → CLI verify', () => {
  it('CC-SC-001: SDK build proof verifies via CLI', async () => {
    const result = ashBuildRequest(basicInput());

    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice"}',
      '--proof', result.proof,
      '--body-hash', result.bodyHash,
      '--timestamp', result.timestamp,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.ok).toBe(true);
  });

  it('CC-SC-002: SDK scoped build verifies via CLI', async () => {
    const result = ashBuildRequest(basicInput({ scope: ['name'] }));

    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice"}',
      '--proof', result.proof,
      '--body-hash', result.bodyHash,
      '--timestamp', result.timestamp,
      '--scope', 'name',
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.ok).toBe(true);
  });

  it('CC-SC-003: SDK unified build verifies via CLI', async () => {
    const first = ashBuildRequest(basicInput());
    const result = ashBuildRequest(basicInput({
      previousProof: first.proof,
      scope: ['name'],
    }));

    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice"}',
      '--proof', result.proof,
      '--body-hash', result.bodyHash,
      '--timestamp', result.timestamp,
      '--scope', 'name',
      '--previous-proof', first.proof,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.ok).toBe(true);
  });
});

// ── CLI → SDK Interop ────────────────────────────────────────────

describe('Cross-cutting: CLI build → SDK verify', () => {
  it('CC-CS-001: CLI build proof verifies via SDK', async () => {
    const buildR = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice"}', '--timestamp', TS, '--json',
    ]);
    expect(buildR.exitCode).toBe(0);
    const build = JSON.parse(buildR.stdout);

    const result = ashVerifyRequest({
      headers: {
        'x-ash-ts': build.timestamp,
        'x-ash-nonce': build.nonce,
        'x-ash-body-hash': build.bodyHash,
        'x-ash-proof': build.proof,
        'x-ash-context-id': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body: '{"name":"Alice"}',
      nonce: NONCE,
      contextId: CTX,
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    });
    expect(result.ok).toBe(true);
  });

  it('CC-CS-002: CLI scoped build verifies via SDK', async () => {
    const buildR = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--body', '{"name":"Alice","age":30}',
      '--scope', 'name',
      '--timestamp', TS, '--json',
    ]);
    expect(buildR.exitCode).toBe(0);
    const build = JSON.parse(buildR.stdout);

    const result = ashVerifyRequest({
      headers: {
        'x-ash-ts': build.timestamp,
        'x-ash-nonce': build.nonce,
        'x-ash-body-hash': build.bodyHash,
        'x-ash-proof': build.proof,
        'x-ash-context-id': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body: '{"name":"Alice","age":30}',
      nonce: NONCE,
      contextId: CTX,
      scope: ['name'],
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    });
    expect(result.ok).toBe(true);
  });
});

// ── Hash Command ↔ SDK Consistency ───────────────────────────────

describe('Cross-cutting: CLI hash ↔ SDK hash', () => {
  it('CC-HH-001: CLI hash body matches SDK ashHashBody', async () => {
    const body = '{"test":"value"}';
    const canonical = ashCanonicalizeJson(body);
    const sdkHash = ashHashBody(canonical);

    const r = await runCli(['hash', 'body', body, '--json']);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.hash).toBe(sdkHash);
  });

  it('CC-HH-002: CLI hash scope matches SDK ashHashScope', async () => {
    const fields = ['field1', 'field2', 'field3'];
    const sdkHash = ashHashScope(fields);

    const r = await runCli(['hash', 'scope', ...fields, '--json']);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.hash).toBe(sdkHash);
  });

  it('CC-HH-003: CLI hash proof matches SDK ashHashProof', async () => {
    const proof = 'a'.repeat(64);
    const sdkHash = ashHashProof(proof);

    const r = await runCli(['hash', 'proof', proof, '--json']);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.hash).toBe(sdkHash);
  });
});

// ── Derive Command ↔ SDK Consistency ─────────────────────────────

describe('Cross-cutting: CLI derive ↔ SDK derive', () => {
  it('CC-DD-001: CLI derive matches SDK ashDeriveClientSecret', async () => {
    const binding = 'GET|/api/users|';
    const sdkSecret = ashDeriveClientSecret(NONCE, CTX, binding);

    const r = await runCli([
      'derive', '--nonce', NONCE, '--context-id', CTX,
      '--binding', binding, '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.clientSecret).toBe(sdkSecret);
  });
});

// ── Error Code → Exit Code Mapping ───────────────────────────────

describe('Cross-cutting: Error codes → CLI exit codes', () => {
  it('CC-EC-001: validation error (bad nonce) exits 3', async () => {
    const r = await runCli([
      'build', '--nonce', 'bad', '--context-id', CTX,
      '--method', 'GET', '--path', '/api', '--json',
    ]);
    expect(r.exitCode).toBe(3);
    const out = JSON.parse(r.stdout);
    expect(out.error).toBe('ASH_VALIDATION_ERROR');
  });

  it('CC-EC-002: proof invalid exits 1', async () => {
    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--proof', 'a'.repeat(64),
      '--body-hash', 'b'.repeat(64),
      '--timestamp', TS,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(1);
  });

  it('CC-EC-003: missing args exits 2', async () => {
    const r = await runCli(['build', '--json']);
    expect(r.exitCode).toBe(2);
  });

  it('CC-EC-004: unknown command exits 2', async () => {
    const r = await runCli(['foo']);
    expect(r.exitCode).toBe(2);
  });
});

// ── Determinism ──────────────────────────────────────────────────

describe('Cross-cutting: Determinism', () => {
  it('CC-DET-001: debug trace format stable across repeated runs', () => {
    const input = basicInput();
    const r1 = ashBuildRequestDebug(input);
    const r2 = ashBuildRequestDebug(input);

    expect(r1.proof).toBe(r2.proof);
    expect(r1.trace.length).toBe(r2.trace.length);
    for (let i = 0; i < r1.trace.length; i++) {
      expect(r1.trace[i].name).toBe(r2.trace[i].name);
      expect(r1.trace[i].step).toBe(r2.trace[i].step);
      expect(r1.trace[i].ok).toBe(r2.trace[i].ok);
    }
  });

  it('CC-DET-002: formatTrace output stable', () => {
    const input = basicInput();
    const r1 = ashBuildRequestDebug(input);
    const r2 = ashBuildRequestDebug(input);

    const f1 = ashFormatTrace(r1.trace);
    const f2 = ashFormatTrace(r2.trace);

    // Step names and statuses should match (durations may differ)
    const strip = (s: string) => s.replace(/\d+\.\d+ms/g, 'Xms');
    expect(strip(f1)).toBe(strip(f2));
  });

  it('CC-DET-003: CLI build deterministic with same inputs', async () => {
    const args = [
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api', '--timestamp', TS, '--json',
    ];
    const r1 = await runCli(args);
    const r2 = await runCli(args);
    const out1 = JSON.parse(r1.stdout);
    const out2 = JSON.parse(r2.stdout);
    expect(out1.proof).toBe(out2.proof);
    expect(out1.bodyHash).toBe(out2.bodyHash);
  });
});

// ── Regression ───────────────────────────────────────────────────

describe('Cross-cutting: Regression — Phase 3 doesnt break Layer 1/2', () => {
  it('CC-REG-001: basic ashBuildRequest still works', () => {
    const result = ashBuildRequest(basicInput());
    expect(result.proof).toHaveLength(SHA256_HEX_LENGTH);
    expect(result.bodyHash).toHaveLength(SHA256_HEX_LENGTH);
  });

  it('CC-REG-002: basic ashVerifyRequest still works', () => {
    const buildResult = ashBuildRequest(basicInput());
    const verifyResult = ashVerifyRequest({
      headers: {
        'x-ash-ts': buildResult.timestamp,
        'x-ash-nonce': buildResult.nonce,
        'x-ash-body-hash': buildResult.bodyHash,
        'x-ash-proof': buildResult.proof,
        'x-ash-context-id': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body: '{"name":"Alice"}',
      nonce: NONCE,
      contextId: CTX,
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    });
    expect(verifyResult.ok).toBe(true);
  });

  it('CC-REG-003: scoped build/verify still works', () => {
    const result = ashBuildRequest(basicInput({ scope: ['name'] }));
    expect(result.scopeHash).toHaveLength(SHA256_HEX_LENGTH);

    const verifyResult = ashVerifyRequest({
      headers: {
        'x-ash-ts': result.timestamp,
        'x-ash-nonce': result.nonce,
        'x-ash-body-hash': result.bodyHash,
        'x-ash-proof': result.proof,
        'x-ash-context-id': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body: '{"name":"Alice"}',
      nonce: NONCE,
      contextId: CTX,
      scope: ['name'],
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    });
    expect(verifyResult.ok).toBe(true);
  });

  it('CC-REG-004: unified build/verify still works', () => {
    const first = ashBuildRequest(basicInput());
    const result = ashBuildRequest(basicInput({
      previousProof: first.proof,
      scope: ['name'],
    }));
    expect(result.chainHash).toHaveLength(SHA256_HEX_LENGTH);

    const verifyResult = ashVerifyRequest({
      headers: {
        'x-ash-ts': result.timestamp,
        'x-ash-nonce': result.nonce,
        'x-ash-body-hash': result.bodyHash,
        'x-ash-proof': result.proof,
        'x-ash-context-id': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body: '{"name":"Alice"}',
      nonce: NONCE,
      contextId: CTX,
      scope: ['name'],
      previousProof: first.proof,
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    });
    expect(verifyResult.ok).toBe(true);
  });

  it('CC-REG-005: debug build returns identical result as non-debug', () => {
    const input = basicInput();
    const debugResult = ashBuildRequestDebug(input);
    const normalResult = ashBuildRequest(input);
    expect(debugResult.proof).toBe(normalResult.proof);
    expect(debugResult.bodyHash).toBe(normalResult.bodyHash);
    expect(debugResult.binding).toBe(normalResult.binding);
    expect(debugResult.timestamp).toBe(normalResult.timestamp);
    expect(debugResult.nonce).toBe(normalResult.nonce);
    expect(debugResult.scopeHash).toBe(normalResult.scopeHash);
    expect(debugResult.chainHash).toBe(normalResult.chainHash);
  });

  it('CC-REG-006: debug verify returns identical ok as non-debug', () => {
    const buildResult = ashBuildRequest(basicInput());
    const verifyInput = {
      headers: {
        'x-ash-ts': buildResult.timestamp,
        'x-ash-nonce': buildResult.nonce,
        'x-ash-body-hash': buildResult.bodyHash,
        'x-ash-proof': buildResult.proof,
        'x-ash-context-id': CTX,
      },
      method: 'POST',
      path: '/api/users',
      body: '{"name":"Alice"}',
      nonce: NONCE,
      contextId: CTX,
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    };
    const debugResult = ashVerifyRequestDebug(verifyInput);
    const normalResult = ashVerifyRequest(verifyInput);
    expect(debugResult.ok).toBe(normalResult.ok);
    expect(debugResult.meta).toBeDefined();
    expect(normalResult.meta).toBeDefined();
    expect(debugResult.meta!.mode).toBe(normalResult.meta!.mode);
    expect(debugResult.meta!.binding).toBe(normalResult.meta!.binding);
  });
});

// ── Concurrent CLI ───────────────────────────────────────────────

describe('Cross-cutting: Concurrent CLI invocations', () => {
  it('CC-CON-001: 5 concurrent build+verify pairs dont interfere', async () => {
    const promises = Array.from({ length: 5 }, async (_, i) => {
      const nonce = randomBytes(32).toString('hex');
      const buildR = await runCli([
        'build', '--nonce', nonce, '--context-id', CTX,
        '--method', 'GET', '--path', '/api/test',
        '--timestamp', TS, '--json',
      ]);
      expect(buildR.exitCode).toBe(0);
      const build = JSON.parse(buildR.stdout);

      const verifyR = await runCli([
        'verify', '--nonce', nonce, '--context-id', CTX,
        '--method', 'GET', '--path', '/api/test',
        '--proof', build.proof,
        '--body-hash', build.bodyHash,
        '--timestamp', build.timestamp,
        '--max-age', '300', '--clock-skew', '30', '--json',
      ]);
      expect(verifyR.exitCode).toBe(0);
      const verify = JSON.parse(verifyR.stdout);
      expect(verify.ok).toBe(true);
      return i;
    });

    await Promise.all(promises);
  });

  it('CC-CON-002: concurrent CLI builds with different nonces produce different proofs', async () => {
    const nonces = Array.from({ length: 3 }, () => randomBytes(32).toString('hex'));

    const results = await Promise.all(nonces.map(nonce =>
      runCli([
        'build', '--nonce', nonce, '--context-id', CTX,
        '--method', 'GET', '--path', '/api',
        '--timestamp', TS, '--json',
      ]),
    ));

    const proofs = results.map(r => JSON.parse(r.stdout).proof);
    // All proofs should be unique
    expect(new Set(proofs).size).toBe(3);
  });
});

// ── Edge Cases ───────────────────────────────────────────────────

describe('Cross-cutting: Edge cases', () => {
  it('CC-EDGE-001: empty body roundtrip SDK→CLI', async () => {
    const result = ashBuildRequest(basicInput({ body: '' }));

    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/users',
      '--proof', result.proof,
      '--body-hash', result.bodyHash,
      '--timestamp', result.timestamp,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    expect(JSON.parse(r.stdout).ok).toBe(true);
  });

  it('CC-EDGE-002: query string roundtrip CLI→SDK', async () => {
    const buildR = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api/search',
      '--query', 'q=hello&page=1',
      '--timestamp', TS, '--json',
    ]);
    expect(buildR.exitCode).toBe(0);
    const build = JSON.parse(buildR.stdout);

    const result = ashVerifyRequest({
      headers: {
        'x-ash-ts': build.timestamp,
        'x-ash-nonce': build.nonce,
        'x-ash-body-hash': build.bodyHash,
        'x-ash-proof': build.proof,
        'x-ash-context-id': CTX,
      },
      method: 'GET',
      path: '/api/search',
      rawQuery: 'q=hello&page=1',
      nonce: NONCE,
      contextId: CTX,
      maxAgeSeconds: 300,
      clockSkewSeconds: 30,
    });
    expect(result.ok).toBe(true);
  });

  it('CC-EDGE-003: debug trace with error still has correct error type', () => {
    const result = ashBuildRequestDebug(basicInput({ nonce: 'tooshort' }));
    expect(result.proof).toBe('');
    expect(result.trace).toHaveLength(1);
    expect(result.trace[0].error).toContain('hex characters');
  });

  it('CC-EDGE-004: all 3 modes produce different proofs for same input', () => {
    const first = ashBuildRequest(basicInput());

    const basic = ashBuildRequestDebug(basicInput());
    const scoped = ashBuildRequestDebug(basicInput({ scope: ['name'] }));
    const unified = ashBuildRequestDebug(basicInput({
      scope: ['name'],
      previousProof: first.proof,
    }));

    expect(basic.mode).toBe('basic');
    expect(scoped.mode).toBe('scoped');
    expect(unified.mode).toBe('unified');

    // All should produce different proofs
    const proofs = [basic.proof, scoped.proof, unified.proof];
    expect(new Set(proofs).size).toBe(3);
  });

  it('CC-EDGE-005: inspect build with invalid input shows error trace', async () => {
    const r = await runCli([
      'inspect', 'build', '--nonce', 'bad',
      '--context-id', CTX, '--method', 'GET', '--path', '/api', '--json',
    ]);
    // Should exit non-zero
    expect(r.exitCode).not.toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.trace.length).toBeGreaterThanOrEqual(1);
    const lastStep = out.trace[out.trace.length - 1];
    expect(lastStep.ok).toBe(false);
  });
});
