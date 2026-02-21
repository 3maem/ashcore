/**
 * ASH Node SDK — Phase 3: CLI Tests
 *
 * Tests the CLI via child_process.execFile on the built dist/cli.js.
 * Coverage: PT (injection, oversized args) / AQ (roundtrips, all commands)
 *           SA (no secrets in stderr, exit codes) / FUZZ (random args)
 */
import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

const CLI_PATH = resolve(__dirname, '../../../dist/cli.js');
const NODE = process.execPath;

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_cli_test';
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

function parseJson(output: string): any {
  return JSON.parse(output.trim());
}

// ── AQ: Build Command ────────────────────────────────────────────

describe('AQ: CLI build command', () => {
  it('AQ-CLI-B-001: build produces valid proof with all fields', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api/users', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.proof).toHaveLength(64);
    expect(out.bodyHash).toHaveLength(64);
    expect(out.binding).toContain('GET|');
    expect(out.nonce).toBe(NONCE);
  });

  it('AQ-CLI-B-002: build --json output is always valid JSON', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/data',
      '--body', '{"key":"value"}', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    expect(() => JSON.parse(r.stdout)).not.toThrow();
  });

  it('AQ-CLI-B-003: build text output contains proof line', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
    ]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('proof:');
    expect(r.stdout).toContain('bodyHash:');
    expect(r.stdout).toContain('binding:');
    expect(r.stdout).toContain('timestamp:');
  });

  it('AQ-CLI-B-004: build auto-generates timestamp when omitted', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api', '--json',
    ]);
    const out = parseJson(r.stdout);
    const ts = parseInt(out.timestamp, 10);
    const now = Math.floor(Date.now() / 1000);
    expect(ts).toBeGreaterThanOrEqual(now - 5);
    expect(ts).toBeLessThanOrEqual(now + 5);
  });

  it('AQ-CLI-B-005: build with explicit timestamp uses it', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--timestamp', TS, '--json',
    ]);
    const out = parseJson(r.stdout);
    expect(out.timestamp).toBe(TS);
  });

  it('AQ-CLI-B-006: build with scope produces scopeHash', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api',
      '--body', '{"name":"test","age":25}',
      '--scope', 'name,age', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.scopeHash).toHaveLength(64);
  });

  it('AQ-CLI-B-007: build with previous-proof produces chainHash', async () => {
    const first = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--timestamp', TS, '--json',
    ]);
    const firstOut = parseJson(first.stdout);

    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--timestamp', TS, '--previous-proof', firstOut.proof, '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.chainHash).toHaveLength(64);
  });

  it('AQ-CLI-B-008: build --help exits 0', async () => {
    const r = await runCli(['build', '--help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Usage');
  });
});

// ── AQ: Build + Verify Roundtrip ─────────────────────────────────

describe('AQ: CLI build+verify roundtrip', () => {
  it('AQ-CLI-RND-001: build output verifies successfully', async () => {
    const buildR = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/data',
      '--body', '{"name":"test"}', '--timestamp', TS, '--json',
    ]);
    expect(buildR.exitCode).toBe(0);
    const build = parseJson(buildR.stdout);

    const verifyR = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api/data',
      '--body', '{"name":"test"}',
      '--proof', build.proof,
      '--body-hash', build.bodyHash,
      '--timestamp', build.timestamp,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(verifyR.exitCode).toBe(0);
    const verify = parseJson(verifyR.stdout);
    expect(verify.ok).toBe(true);
    expect(verify.mode).toBe('basic');
  });

  it('AQ-CLI-RND-002: verify exit code 1 for invalid proof', async () => {
    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--proof', 'a'.repeat(64),
      '--body-hash', 'b'.repeat(64),
      '--timestamp', TS,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(1);
    const out = parseJson(r.stdout);
    expect(out.ok).toBe(false);
  });

  it('AQ-CLI-RND-003: verify text output shows OK for valid proof', async () => {
    const buildR = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--timestamp', TS, '--json',
    ]);
    const build = parseJson(buildR.stdout);

    const verifyR = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--proof', build.proof,
      '--body-hash', build.bodyHash,
      '--timestamp', build.timestamp,
      '--max-age', '300', '--clock-skew', '30',
    ]);
    expect(verifyR.exitCode).toBe(0);
    expect(verifyR.stdout).toContain('OK');
  });

  it('AQ-CLI-RND-004: verify text output shows FAILED for invalid', async () => {
    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--proof', 'a'.repeat(64),
      '--body-hash', 'b'.repeat(64),
      '--timestamp', TS,
      '--max-age', '300', '--clock-skew', '30',
    ]);
    expect(r.exitCode).toBe(1);
    expect(r.stdout).toContain('FAILED');
  });
});

// ── AQ: Hash Command ─────────────────────────────────────────────

describe('AQ: CLI hash command', () => {
  it('AQ-CLI-H-001: hash body produces 64-char hex', async () => {
    const r = await runCli(['hash', 'body', '{"test":true}', '--json']);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.hash).toHaveLength(64);
  });

  it('AQ-CLI-H-002: hash scope produces 64-char hex', async () => {
    const r = await runCli(['hash', 'scope', 'field1', 'field2', '--json']);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.hash).toHaveLength(64);
  });

  it('AQ-CLI-H-003: hash proof produces 64-char hex', async () => {
    const r = await runCli(['hash', 'proof', 'a'.repeat(64), '--json']);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.hash).toHaveLength(64);
  });

  it('AQ-CLI-H-004: hash --help exits 0', async () => {
    const r = await runCli(['hash', '--help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Usage');
  });

  it('AQ-CLI-H-005: hash text output is just the hash', async () => {
    const r = await runCli(['hash', 'body', '{"x":1}']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ── AQ: Derive Command ───────────────────────────────────────────

describe('AQ: CLI derive command', () => {
  it('AQ-CLI-D-001: derive produces 64-char hex secret', async () => {
    const r = await runCli([
      'derive', '--nonce', NONCE, '--context-id', CTX,
      '--binding', 'GET|/api|', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.clientSecret).toHaveLength(64);
  });

  it('AQ-CLI-D-002: derive text output is just the secret', async () => {
    const r = await runCli([
      'derive', '--nonce', NONCE, '--context-id', CTX,
      '--binding', 'GET|/api|',
    ]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout.trim()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('AQ-CLI-D-003: derive --help exits 0', async () => {
    const r = await runCli(['derive', '--help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Usage');
  });
});

// ── AQ: Inspect Command ──────────────────────────────────────────

describe('AQ: CLI inspect command', () => {
  it('AQ-CLI-I-001: inspect build includes all 7 trace steps', async () => {
    const r = await runCli([
      'inspect', 'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.trace).toHaveLength(7);
    expect(out.mode).toBe('basic');
  });

  it('AQ-CLI-I-002: inspect verify includes 9 trace steps on valid', async () => {
    const buildR = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--timestamp', TS, '--json',
    ]);
    const build = parseJson(buildR.stdout);

    const r = await runCli([
      'inspect', 'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--proof', build.proof,
      '--body-hash', build.bodyHash,
      '--timestamp', build.timestamp,
      '--max-age', '300', '--clock-skew', '30', '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.ok).toBe(true);
    expect(out.trace).toHaveLength(9);
  });

  it('AQ-CLI-I-003: inspect text output shows step traces', async () => {
    const r = await runCli([
      'inspect', 'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
    ]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('validate_nonce');
    expect(r.stdout).toContain('build_proof');
    expect(r.stdout).toContain('OK');
  });

  it('AQ-CLI-I-004: inspect --help exits 0', async () => {
    const r = await runCli(['inspect', '--help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Usage');
  });
});

// ── AQ: Version & Help ───────────────────────────────────────────

describe('AQ: CLI version & help', () => {
  it('AQ-CLI-VH-001: version prints correct version string', async () => {
    const r = await runCli(['version']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('@3maem/ash-node-sdk');
    expect(r.stdout).toContain('v1.2.0');
  });

  it('AQ-CLI-VH-002: --version works too', async () => {
    const r = await runCli(['--version']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('v1.2.0');
  });

  it('AQ-CLI-VH-003: help prints usage', async () => {
    const r = await runCli(['help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Commands:');
    expect(r.stdout).toContain('ash build');
  });

  it('AQ-CLI-VH-004: --help prints usage', async () => {
    const r = await runCli(['--help']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Commands:');
  });

  it('AQ-CLI-VH-005: no args prints help', async () => {
    const r = await runCli([]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Commands:');
  });
});

// ── AQ: Missing Args ─────────────────────────────────────────────

describe('AQ: CLI missing arguments', () => {
  it('AQ-CLI-MA-001: build without --nonce prints error', async () => {
    const r = await runCli(['build', '--context-id', CTX, '--method', 'GET', '--path', '/api', '--json']);
    expect(r.exitCode).toBe(2);
    const out = parseJson(r.stdout);
    expect(out.error).toBe('USAGE_ERROR');
    expect(out.message).toContain('--nonce');
  });

  it('AQ-CLI-MA-002: build without --method prints error', async () => {
    const r = await runCli(['build', '--nonce', NONCE, '--context-id', CTX, '--path', '/api', '--json']);
    expect(r.exitCode).toBe(2);
    const out = parseJson(r.stdout);
    expect(out.message).toContain('--method');
  });

  it('AQ-CLI-MA-003: verify without --proof prints error', async () => {
    const r = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--body-hash', 'a'.repeat(64), '--timestamp', TS, '--json',
    ]);
    expect(r.exitCode).toBe(2);
    const out = parseJson(r.stdout);
    expect(out.message).toContain('--proof');
  });

  it('AQ-CLI-MA-004: unknown command prints error exit 2', async () => {
    const r = await runCli(['nonexistent']);
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain('Unknown command');
  });

  it('AQ-CLI-MA-005: unknown command --json prints JSON error', async () => {
    const r = await runCli(['nonexistent', '--json']);
    expect(r.exitCode).toBe(2);
    const out = parseJson(r.stdout);
    expect(out.error).toBe('USAGE_ERROR');
  });
});

// ── PT: Penetration Tests ─────────────────────────────────────────

describe('PT: CLI security', () => {
  it('PT-CLI-001: shell metacharacters in --body dont execute', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api',
      '--body', '$(echo hacked)', '--json',
    ]);
    // Should either succeed (treating it as literal) or fail cleanly
    expect([0, 3]).toContain(r.exitCode);
    if (r.exitCode === 0) {
      const out = parseJson(r.stdout);
      expect(out.proof).toHaveLength(64);
    }
  });

  it('PT-CLI-002: invalid hex in --nonce produces clean error', async () => {
    const r = await runCli([
      'build', '--nonce', 'zzzz_not_hex_at_all_need32chars!!!',
      '--context-id', CTX, '--method', 'GET', '--path', '/api', '--json',
    ]);
    expect([2, 3]).toContain(r.exitCode);
    const out = parseJson(r.stdout);
    expect(out.error).toBe('ASH_VALIDATION_ERROR');
    expect(out.message).toBeDefined();
  });

  it('PT-CLI-003: --json output is always valid JSON even on error', async () => {
    const cases = [
      ['build', '--json'],
      ['build', '--nonce', 'bad', '--json'],
      ['verify', '--json'],
      ['hash', '--json'],
    ];
    for (const args of cases) {
      const r = await runCli(args);
      if (r.stdout.trim().length > 0) {
        expect(() => JSON.parse(r.stdout.trim())).not.toThrow();
      }
    }
  });

  it('PT-CLI-004: oversized nonce rejected gracefully', async () => {
    const bigNonce = 'a'.repeat(2000);
    const r = await runCli([
      'build', '--nonce', bigNonce, '--context-id', CTX,
      '--method', 'GET', '--path', '/api', '--json',
    ]);
    expect(r.exitCode).not.toBe(0);
    const out = parseJson(r.stdout);
    expect(out.error).toBe('ASH_VALIDATION_ERROR');
  });

  it('PT-CLI-005: pipe characters in method handled safely', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET|POST', '--path', '/api', '--json',
    ]);
    expect(r.exitCode).toBe(3);
    const out = parseJson(r.stdout);
    expect(out.error).toBeDefined();
  });
});

// ── SA: Security Audit ────────────────────────────────────────────

describe('SA: CLI security audit', () => {
  it('SA-CLI-001: stderr never contains clientSecret', async () => {
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
    ]);
    // The derived client secret should not appear in stderr
    expect(r.stderr).not.toMatch(/[0-9a-f]{64}/);
  });

  it('SA-CLI-002: --json error output has error+message structure', async () => {
    const r = await runCli(['build', '--json']);
    expect(r.exitCode).toBe(2);
    const out = parseJson(r.stdout);
    expect(out).toHaveProperty('error');
    expect(out).toHaveProperty('message');
  });

  it('SA-CLI-003: exit codes are consistent', async () => {
    // Success
    const version = await runCli(['version']);
    expect(version.exitCode).toBe(0);

    // Usage error
    const unknown = await runCli(['nonexistent']);
    expect(unknown.exitCode).toBe(2);

    // Invalid proof
    const invalid = await runCli([
      'verify', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
      '--proof', 'a'.repeat(64), '--body-hash', 'b'.repeat(64),
      '--timestamp', TS, '--max-age', '300', '--clock-skew', '30',
    ]);
    expect(invalid.exitCode).toBe(1);
  });

  it('SA-CLI-004: no stack traces in output', async () => {
    const r = await runCli([
      'build', '--nonce', 'bad', '--context-id', CTX,
      '--method', 'GET', '--path', '/api',
    ]);
    expect(r.stderr).not.toContain('    at ');
    expect(r.stdout).not.toContain('    at ');
  });
});

// ── FUZZ: Random Inputs ───────────────────────────────────────────

describe('FUZZ: CLI random inputs', () => {
  it('FUZZ-CLI-001: random garbage arguments exit 2', async () => {
    const r = await runCli(['--foo', '--bar', '--baz']);
    expect(r.exitCode).toBe(2);
  });

  it('FUZZ-CLI-002: empty string args handled gracefully', async () => {
    const r = await runCli(['build', '--nonce', '', '--context-id', '', '--method', '', '--path', '', '--json']);
    expect([2, 3]).toContain(r.exitCode);
    if (r.stdout.trim()) {
      expect(() => JSON.parse(r.stdout.trim())).not.toThrow();
    }
  });

  it('FUZZ-CLI-003: random valid roundtrips work', async () => {
    for (let i = 0; i < 5; i++) {
      const nonce = randomBytes(32).toString('hex');
      const buildR = await runCli([
        'build', '--nonce', nonce, '--context-id', CTX,
        '--method', 'GET', '--path', '/api/test',
        '--timestamp', TS, '--json',
      ]);
      expect(buildR.exitCode).toBe(0);
      const build = parseJson(buildR.stdout);

      const verifyR = await runCli([
        'verify', '--nonce', nonce, '--context-id', CTX,
        '--method', 'GET', '--path', '/api/test',
        '--proof', build.proof,
        '--body-hash', build.bodyHash,
        '--timestamp', build.timestamp,
        '--max-age', '300', '--clock-skew', '30', '--json',
      ]);
      expect(verifyR.exitCode).toBe(0);
      const verify = parseJson(verifyR.stdout);
      expect(verify.ok).toBe(true);
    }
  });

  it('FUZZ-CLI-004: very long body value handled', async () => {
    const longBody = JSON.stringify({ data: 'x'.repeat(10000) });
    const r = await runCli([
      'build', '--nonce', NONCE, '--context-id', CTX,
      '--method', 'POST', '--path', '/api',
      '--body', longBody, '--json',
    ]);
    expect(r.exitCode).toBe(0);
    const out = parseJson(r.stdout);
    expect(out.proof).toHaveLength(64);
  });

  it('FUZZ-CLI-005: hash with no subcommand exits 2', async () => {
    const r = await runCli(['hash', '--json']);
    expect(r.exitCode).toBe(2);
  });

  it('FUZZ-CLI-006: derive with missing binding exits 2', async () => {
    const r = await runCli(['derive', '--nonce', NONCE, '--context-id', CTX, '--json']);
    expect(r.exitCode).toBe(2);
  });
});
