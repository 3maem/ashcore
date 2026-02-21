/**
 * ASH Node SDK — CLI Tool
 *
 * Commands: build, verify, hash, derive, inspect, version, help
 * Zero dependencies — uses Node.js built-in parseArgs.
 */
import { parseArgs } from 'node:util';
import { ashBuildRequest } from './build-request.js';
import { ashVerifyRequest } from './verify-request.js';
import { ashHashBody, ashHashScope, ashHashProof } from './hash.js';
import { ashDeriveClientSecret } from './proof.js';
import { ashNormalizeBinding } from './binding.js';
import { ashCanonicalizeJson } from './canonicalize.js';
import { ashBuildRequestDebug, ashVerifyRequestDebug, ashFormatTrace } from './debug.js';
import { AshError } from './errors.js';

const SDK_VERSION = '1.2.0';

// ── Exit codes ────────────────────────────────────────────────────

const EXIT_OK = 0;
const EXIT_INVALID = 1;
const EXIT_USAGE = 2;
const EXIT_ERROR = 3;

// ── Helpers ───────────────────────────────────────────────────────

function writeOut(text: string): void {
  process.stdout.write(text + '\n');
}

function writeErr(text: string): void {
  process.stderr.write(text + '\n');
}

function exitUsage(message: string, jsonMode: boolean): never {
  if (jsonMode) {
    writeOut(JSON.stringify({ error: 'USAGE_ERROR', message }));
  } else {
    writeErr(`Error: ${message}`);
    writeErr('Run "ash help" for usage information.');
  }
  process.exit(EXIT_USAGE);
}

function exitError(err: unknown, jsonMode: boolean): never {
  const message = err instanceof Error ? err.message : String(err);
  const code = err instanceof AshError ? err.code : 'ASH_INTERNAL_ERROR';
  const httpStatus = err instanceof AshError ? err.httpStatus : 500;
  if (jsonMode) {
    writeOut(JSON.stringify({ error: code, message, httpStatus }));
  } else {
    writeErr(`Error: ${message} (${code})`);
  }
  process.exit(EXIT_ERROR);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

// ── Command: build ────────────────────────────────────────────────

async function cmdBuild(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      nonce: { type: 'string' },
      'context-id': { type: 'string' },
      method: { type: 'string' },
      path: { type: 'string' },
      query: { type: 'string' },
      body: { type: 'string' },
      timestamp: { type: 'string' },
      scope: { type: 'string' },
      'previous-proof': { type: 'string' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    writeOut(`Usage: ash build --nonce <hex> --context-id <id> --method <method> --path <path>
  [--query "key=val"] [--body '{"a":1}'] [--timestamp <unix>]
  [--scope field1,field2] [--previous-proof <hex>] [--json]

Build an ASH proof for a request.`);
    process.exit(EXIT_OK);
  }

  const jsonMode = values.json ?? false;

  if (!values.nonce) exitUsage('Missing required argument: --nonce', jsonMode);
  if (!values['context-id']) exitUsage('Missing required argument: --context-id', jsonMode);
  if (!values.method) exitUsage('Missing required argument: --method', jsonMode);
  if (!values.path) exitUsage('Missing required argument: --path', jsonMode);

  let body = values.body;
  if (body === '-') {
    body = await readStdin();
  }

  const scope = values.scope ? values.scope.split(',').filter(s => s.length > 0) : undefined;

  try {
    const result = ashBuildRequest({
      nonce: values.nonce!,
      contextId: values['context-id']!,
      method: values.method!,
      path: values.path!,
      rawQuery: values.query,
      body,
      timestamp: values.timestamp,
      scope,
      previousProof: values['previous-proof'],
    });

    if (jsonMode) {
      const output: Record<string, unknown> = {
        proof: result.proof,
        bodyHash: result.bodyHash,
        binding: result.binding,
        timestamp: result.timestamp,
        nonce: result.nonce,
      };
      if (result.scopeHash) output.scopeHash = result.scopeHash;
      if (result.chainHash) output.chainHash = result.chainHash;
      writeOut(JSON.stringify(output));
    } else {
      writeOut(`proof: ${result.proof}`);
      writeOut(`bodyHash: ${result.bodyHash}`);
      writeOut(`binding: ${result.binding}`);
      writeOut(`timestamp: ${result.timestamp}`);
      if (result.scopeHash) writeOut(`scopeHash: ${result.scopeHash}`);
      if (result.chainHash) writeOut(`chainHash: ${result.chainHash}`);
    }

    result.destroy();
    process.exit(EXIT_OK);
  } catch (err: unknown) {
    exitError(err, jsonMode);
  }
}

// ── Command: verify ───────────────────────────────────────────────

async function cmdVerify(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      nonce: { type: 'string' },
      'context-id': { type: 'string' },
      method: { type: 'string' },
      path: { type: 'string' },
      query: { type: 'string' },
      body: { type: 'string' },
      proof: { type: 'string' },
      'body-hash': { type: 'string' },
      timestamp: { type: 'string' },
      scope: { type: 'string' },
      'previous-proof': { type: 'string' },
      'max-age': { type: 'string' },
      'clock-skew': { type: 'string' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    writeOut(`Usage: ash verify --nonce <hex> --context-id <id> --method <method> --path <path>
  --proof <hex> --body-hash <hex> --timestamp <unix>
  [--query "key=val"] [--body '{"a":1}']
  [--scope field1,field2] [--previous-proof <hex>]
  [--max-age 300] [--clock-skew 30] [--json]

Verify an ASH proof for a request.`);
    process.exit(EXIT_OK);
  }

  const jsonMode = values.json ?? false;

  if (!values.nonce) exitUsage('Missing required argument: --nonce', jsonMode);
  if (!values['context-id']) exitUsage('Missing required argument: --context-id', jsonMode);
  if (!values.method) exitUsage('Missing required argument: --method', jsonMode);
  if (!values.path) exitUsage('Missing required argument: --path', jsonMode);
  if (!values.proof) exitUsage('Missing required argument: --proof', jsonMode);
  if (!values['body-hash']) exitUsage('Missing required argument: --body-hash', jsonMode);
  if (!values.timestamp) exitUsage('Missing required argument: --timestamp', jsonMode);

  let body = values.body;
  if (body === '-') {
    body = await readStdin();
  }

  const scope = values.scope ? values.scope.split(',').filter(s => s.length > 0) : undefined;

  try {
    const headers: Record<string, string> = {
      'x-ash-ts': values.timestamp!,
      'x-ash-nonce': values.nonce!,
      'x-ash-body-hash': values['body-hash']!,
      'x-ash-proof': values.proof!,
      'x-ash-context-id': values['context-id']!,
    };

    const result = ashVerifyRequest({
      headers,
      method: values.method!,
      path: values.path!,
      rawQuery: values.query,
      body,
      nonce: values.nonce!,
      contextId: values['context-id']!,
      scope,
      previousProof: values['previous-proof'],
      maxAgeSeconds: values['max-age'] ? parseInt(values['max-age'], 10) : undefined,
      clockSkewSeconds: values['clock-skew'] ? parseInt(values['clock-skew'], 10) : undefined,
    });

    if (jsonMode) {
      writeOut(JSON.stringify({
        ok: result.ok,
        mode: result.meta?.mode,
        binding: result.meta?.binding,
        error: result.error ? { code: result.error.code, message: result.error.message } : undefined,
      }));
    } else {
      if (result.ok) {
        writeOut(`OK — ${result.meta!.mode} mode, binding: ${result.meta!.binding}`);
      } else {
        const code = result.error?.code ?? 'UNKNOWN';
        const status = result.error?.httpStatus ?? 500;
        writeOut(`FAILED — ${code} (${status})`);
      }
    }

    process.exit(result.ok ? EXIT_OK : EXIT_INVALID);
  } catch (err: unknown) {
    exitError(err, jsonMode);
  }
}

// ── Command: hash ─────────────────────────────────────────────────

function cmdHash(argv: string[]): void {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    allowPositionals: true,
    strict: true,
  });

  if (values.help) {
    writeOut(`Usage:
  ash hash body <string>         — SHA-256 hash of canonical body
  ash hash scope <fields...>     — SHA-256 hash of sorted scope
  ash hash proof <hex>           — SHA-256 hash of proof for chaining`);
    process.exit(EXIT_OK);
  }

  const jsonMode = values.json ?? false;
  const subcommand = positionals[0];

  if (!subcommand) exitUsage('Missing hash subcommand: body, scope, or proof', jsonMode);

  try {
    let hashResult: string;

    switch (subcommand) {
      case 'body': {
        const input = positionals.slice(1).join(' ');
        const canonical = input.length > 0 ? ashCanonicalizeJson(input) : '';
        hashResult = ashHashBody(canonical);
        break;
      }
      case 'scope': {
        const fields = positionals.slice(1);
        if (fields.length === 0) exitUsage('No scope fields provided', jsonMode);
        hashResult = ashHashScope(fields);
        break;
      }
      case 'proof': {
        const proofHex = positionals[1];
        if (!proofHex) exitUsage('No proof hex provided', jsonMode);
        hashResult = ashHashProof(proofHex);
        break;
      }
      default:
        exitUsage(`Unknown hash subcommand: ${subcommand}`, jsonMode);
    }

    if (jsonMode) {
      writeOut(JSON.stringify({ hash: hashResult }));
    } else {
      writeOut(hashResult);
    }
    process.exit(EXIT_OK);
  } catch (err: unknown) {
    exitError(err, jsonMode);
  }
}

// ── Command: derive ───────────────────────────────────────────────

function cmdDerive(argv: string[]): void {
  const { values } = parseArgs({
    args: argv,
    options: {
      nonce: { type: 'string' },
      'context-id': { type: 'string' },
      binding: { type: 'string' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    writeOut(`Usage: ash derive --nonce <hex> --context-id <id> --binding "GET|/api/users|"

Derive client secret from nonce, context ID, and binding.`);
    process.exit(EXIT_OK);
  }

  const jsonMode = values.json ?? false;

  if (!values.nonce) exitUsage('Missing required argument: --nonce', jsonMode);
  if (!values['context-id']) exitUsage('Missing required argument: --context-id', jsonMode);
  if (!values.binding) exitUsage('Missing required argument: --binding', jsonMode);

  try {
    const secret = ashDeriveClientSecret(values.nonce!, values['context-id']!, values.binding!);

    if (jsonMode) {
      writeOut(JSON.stringify({ clientSecret: secret }));
    } else {
      writeOut(secret);
    }
    process.exit(EXIT_OK);
  } catch (err: unknown) {
    exitError(err, jsonMode);
  }
}

// ── Command: inspect ──────────────────────────────────────────────

async function cmdInspect(argv: string[]): Promise<void> {
  const subcommand = argv[0];
  const subArgs = argv.slice(1);

  if (!subcommand || subcommand === '--help') {
    writeOut(`Usage:
  ash inspect build  [same args as ash build]
  ash inspect verify [same args as ash verify]

Show debug trace for build or verify operations.`);
    process.exit(EXIT_OK);
  }

  if (subcommand === 'build') {
    const { values } = parseArgs({
      args: subArgs,
      options: {
        nonce: { type: 'string' },
        'context-id': { type: 'string' },
        method: { type: 'string' },
        path: { type: 'string' },
        query: { type: 'string' },
        body: { type: 'string' },
        timestamp: { type: 'string' },
        scope: { type: 'string' },
        'previous-proof': { type: 'string' },
        json: { type: 'boolean', default: false },
      },
      strict: true,
    });

    const jsonMode = values.json ?? false;

    if (!values.nonce) exitUsage('Missing required argument: --nonce', jsonMode);
    if (!values['context-id']) exitUsage('Missing required argument: --context-id', jsonMode);
    if (!values.method) exitUsage('Missing required argument: --method', jsonMode);
    if (!values.path) exitUsage('Missing required argument: --path', jsonMode);

    let body = values.body;
    if (body === '-') body = await readStdin();

    const scope = values.scope ? values.scope.split(',').filter(s => s.length > 0) : undefined;

    try {
      const result = ashBuildRequestDebug({
        nonce: values.nonce!,
        contextId: values['context-id']!,
        method: values.method!,
        path: values.path!,
        rawQuery: values.query,
        body,
        timestamp: values.timestamp,
        scope,
        previousProof: values['previous-proof'],
      });

      if (jsonMode) {
        writeOut(JSON.stringify({
          proof: result.proof,
          bodyHash: result.bodyHash,
          binding: result.binding,
          timestamp: result.timestamp,
          mode: result.mode,
          totalDurationMs: result.totalDurationMs,
          trace: result.trace,
        }));
      } else {
        writeOut(ashFormatTrace(result.trace));
        writeOut('');
        if (result.proof) {
          writeOut(`proof: ${result.proof}`);
          writeOut(`mode: ${result.mode}`);
          writeOut(`totalDuration: ${result.totalDurationMs.toFixed(2)}ms`);
        }
      }

      result.destroy();
      process.exit(result.proof ? EXIT_OK : EXIT_ERROR);
    } catch (err: unknown) {
      exitError(err, jsonMode);
    }
  } else if (subcommand === 'verify') {
    const { values } = parseArgs({
      args: subArgs,
      options: {
        nonce: { type: 'string' },
        'context-id': { type: 'string' },
        method: { type: 'string' },
        path: { type: 'string' },
        query: { type: 'string' },
        body: { type: 'string' },
        proof: { type: 'string' },
        'body-hash': { type: 'string' },
        timestamp: { type: 'string' },
        scope: { type: 'string' },
        'previous-proof': { type: 'string' },
        'max-age': { type: 'string' },
        'clock-skew': { type: 'string' },
        json: { type: 'boolean', default: false },
      },
      strict: true,
    });

    const jsonMode = values.json ?? false;

    if (!values.nonce) exitUsage('Missing required argument: --nonce', jsonMode);
    if (!values['context-id']) exitUsage('Missing required argument: --context-id', jsonMode);
    if (!values.method) exitUsage('Missing required argument: --method', jsonMode);
    if (!values.path) exitUsage('Missing required argument: --path', jsonMode);
    if (!values.proof) exitUsage('Missing required argument: --proof', jsonMode);
    if (!values['body-hash']) exitUsage('Missing required argument: --body-hash', jsonMode);
    if (!values.timestamp) exitUsage('Missing required argument: --timestamp', jsonMode);

    let body = values.body;
    if (body === '-') body = await readStdin();

    const scope = values.scope ? values.scope.split(',').filter(s => s.length > 0) : undefined;

    try {
      const headers: Record<string, string> = {
        'x-ash-ts': values.timestamp!,
        'x-ash-nonce': values.nonce!,
        'x-ash-body-hash': values['body-hash']!,
        'x-ash-proof': values.proof!,
        'x-ash-context-id': values['context-id']!,
      };

      const result = ashVerifyRequestDebug({
        headers,
        method: values.method!,
        path: values.path!,
        rawQuery: values.query,
        body,
        nonce: values.nonce!,
        contextId: values['context-id']!,
        scope,
        previousProof: values['previous-proof'],
        maxAgeSeconds: values['max-age'] ? parseInt(values['max-age'], 10) : undefined,
        clockSkewSeconds: values['clock-skew'] ? parseInt(values['clock-skew'], 10) : undefined,
      });

      if (jsonMode) {
        writeOut(JSON.stringify({
          ok: result.ok,
          mode: result.meta?.mode,
          binding: result.meta?.binding,
          totalDurationMs: result.totalDurationMs,
          trace: result.trace,
          error: result.error ? { code: result.error.code, message: result.error.message } : undefined,
        }));
      } else {
        writeOut(ashFormatTrace(result.trace));
        writeOut('');
        if (result.ok) {
          writeOut(`OK — ${result.meta!.mode} mode`);
        } else {
          const code = result.error?.code ?? 'UNKNOWN';
          writeOut(`FAILED — ${code}`);
        }
        writeOut(`totalDuration: ${result.totalDurationMs.toFixed(2)}ms`);
      }

      process.exit(result.ok ? EXIT_OK : EXIT_INVALID);
    } catch (err: unknown) {
      exitError(err, jsonMode);
    }
  } else {
    exitUsage(`Unknown inspect subcommand: ${subcommand}. Use "build" or "verify".`, false);
  }
}

// ── Command: version ──────────────────────────────────────────────

function cmdVersion(): void {
  writeOut(`@3maem/ash-node-sdk v${SDK_VERSION}`);
  process.exit(EXIT_OK);
}

// ── Command: help ─────────────────────────────────────────────────

function cmdHelp(): void {
  writeOut(`@3maem/ash-node-sdk v${SDK_VERSION} — ASH CLI Tool

Commands:
  ash build      Build an ASH proof (client-side)
  ash verify     Verify an ASH proof (server-side)
  ash hash       Hash body, scope, or proof
  ash derive     Derive client secret
  ash inspect    Show debug trace for build or verify
  ash version    Print SDK version
  ash help       Print this help message

Use "ash <command> --help" for more information on a specific command.

Exit codes:
  0  Success / valid proof
  1  Invalid proof
  2  Usage error (missing args, unknown command)
  3  Internal error`);
  process.exit(EXIT_OK);
}

// ── Main ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];
  const commandArgs = args.slice(1);

  if (!command || command === 'help' || command === '--help') {
    cmdHelp();
    return;
  }

  switch (command) {
    case 'build':
      await cmdBuild(commandArgs);
      break;
    case 'verify':
      await cmdVerify(commandArgs);
      break;
    case 'hash':
      cmdHash(commandArgs);
      break;
    case 'derive':
      cmdDerive(commandArgs);
      break;
    case 'inspect':
      await cmdInspect(commandArgs);
      break;
    case 'version':
    case '--version':
    case '-v':
      cmdVersion();
      break;
    default: {
      const jsonIdx = args.indexOf('--json');
      const jsonMode = jsonIdx !== -1;
      if (jsonMode) {
        writeOut(JSON.stringify({ error: 'USAGE_ERROR', message: `Unknown command: ${command}` }));
      } else {
        writeErr(`Unknown command: ${command}`);
        writeErr('Run "ash help" for usage information.');
      }
      process.exit(EXIT_USAGE);
    }
  }
}

main().catch((err) => {
  writeErr(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(EXIT_ERROR);
});
