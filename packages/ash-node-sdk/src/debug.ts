/**
 * ASH Node SDK — Phase 3: Debug Trace Functions
 *
 * Provides step-by-step debug tracing for ashBuildRequest and ashVerifyRequest.
 * Captures each pipeline step with timing, inputs, outputs, and error info.
 * Sensitive values (clientSecret) are REDACTED in trace output.
 */
import { performance } from 'node:perf_hooks';
import { ashValidateNonce, ashValidateTimestampFormat, ashValidateTimestamp } from './validate.js';
import { ashNormalizeBinding } from './binding.js';
import { ashHashBody } from './hash.js';
import { ashDeriveClientSecret, ashBuildProof } from './proof.js';
import { ashBuildProofScoped } from './proof-scoped.js';
import { ashBuildProofUnified } from './proof-unified.js';
import { ashCanonicalizeJson } from './canonicalize.js';
import { ashExtractHeaders } from './headers.js';
import { ashTimingSafeEqual } from './compare.js';
import { AshError } from './errors.js';
import { DEFAULT_MAX_TIMESTAMP_AGE_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS } from './constants.js';
import type { BuildRequestInput, BuildRequestResult } from './build-request.js';
import type { VerifyRequestInput, VerifyResult } from './verify-request.js';

// ── Types ──────────────────────────────────────────────────────────

export interface TraceStep {
  step: number;
  name: string;
  input: Record<string, unknown>;
  output: unknown;
  durationMs: number;
  ok: boolean;
  error?: string;
}

export interface BuildRequestDebugResult extends BuildRequestResult {
  trace: TraceStep[];
  mode: 'basic' | 'scoped' | 'unified';
  totalDurationMs: number;
}

export interface VerifyRequestDebugResult extends VerifyResult {
  trace: TraceStep[];
  totalDurationMs: number;
}

// ── Helpers ────────────────────────────────────────────────────────

function redact(value: string): string {
  if (value.length <= 8) return '[REDACTED]';
  return value.slice(0, 8) + '...';
}

function traceStep(
  trace: TraceStep[],
  stepNum: number,
  name: string,
  inputData: Record<string, unknown>,
  fn: () => unknown,
): unknown {
  const start = performance.now();
  try {
    const output = fn();
    const durationMs = performance.now() - start;
    trace.push({
      step: stepNum,
      name,
      input: inputData,
      output,
      durationMs,
      ok: true,
    });
    return output;
  } catch (err: unknown) {
    const durationMs = performance.now() - start;
    const errorMessage = err instanceof Error ? err.message : String(err);
    trace.push({
      step: stepNum,
      name,
      input: inputData,
      output: null,
      durationMs,
      ok: false,
      error: errorMessage,
    });
    throw err;
  }
}

// ── ashBuildRequestDebug ──────────────────────────────────────────

export function ashBuildRequestDebug(input: BuildRequestInput): BuildRequestDebugResult {
  const totalStart = performance.now();
  const trace: TraceStep[] = [];

  try {
    // Step 1: Validate nonce
    traceStep(trace, 1, 'validate_nonce', { nonce: redact(input.nonce) }, () => {
      ashValidateNonce(input.nonce);
      return { valid: true };
    });

    // Step 2: Validate or generate timestamp
    const generated = input.timestamp === undefined || input.timestamp === null;
    const timestamp = input.timestamp ?? String(Math.floor(Date.now() / 1000));
    traceStep(trace, 2, 'validate_timestamp', { timestamp, generated }, () => {
      ashValidateTimestampFormat(timestamp);
      return { timestamp };
    });

    // Step 3: Normalize binding
    const binding = traceStep(
      trace, 3, 'normalize_binding',
      { method: input.method, path: input.path, rawQuery: input.rawQuery ?? '' },
      () => {
        const b = ashNormalizeBinding(input.method, input.path, input.rawQuery ?? '');
        return { binding: b };
      },
    ) as { binding: string };

    // Step 4: Hash body
    const bodyStr = input.body ?? '';
    const bodyHash = traceStep(
      trace, 4, 'hash_body',
      { bodyLength: bodyStr.length, canonical: bodyStr.length > 0 },
      () => {
        const bh = ashHashBody(bodyStr.length > 0 ? ashCanonicalizeJson(bodyStr) : '');
        return { bodyHash: bh };
      },
    ) as { bodyHash: string };

    // Step 5: Derive client secret
    traceStep(
      trace, 5, 'derive_secret',
      { nonce: redact(input.nonce), contextId: input.contextId, binding: binding.binding },
      () => {
        ashDeriveClientSecret(input.nonce, input.contextId, binding.binding);
        return { clientSecret: '[REDACTED]' };
      },
    );
    // Compute actual secret (not traced)
    const clientSecret = ashDeriveClientSecret(input.nonce, input.contextId, binding.binding);

    // Step 6: Build proof — auto-detect mode
    const hasScope = input.scope && input.scope.length > 0;
    const hasPreviousProof = input.previousProof && input.previousProof.length > 0;

    let proof: string;
    let scopeHash: string | undefined;
    let chainHash: string | undefined;
    let mode: 'basic' | 'scoped' | 'unified';

    if (hasPreviousProof) {
      mode = 'unified';
      const proofResult = traceStep(
        trace, 6, 'build_proof',
        { mode, hmacMessage: `${timestamp}|${binding.binding}|bodyHash|scopeHash|chainHash` },
        () => {
          const payload = bodyStr.length > 0 ? bodyStr : '';
          const r = ashBuildProofUnified(
            clientSecret, timestamp, binding.binding, payload,
            input.scope ?? [], input.previousProof ?? null,
          );
          return {
            proof: redact(r.proof),
            scopeHash: r.scopeHash.length > 0 ? redact(r.scopeHash) : undefined,
            chainHash: r.chainHash.length > 0 ? redact(r.chainHash) : undefined,
          };
        },
      ) as { proof: string; scopeHash?: string; chainHash?: string };
      // Compute actual values (unredacted)
      const payload = bodyStr.length > 0 ? bodyStr : '';
      const actualResult = ashBuildProofUnified(
        clientSecret, timestamp, binding.binding, payload,
        input.scope ?? [], input.previousProof ?? null,
      );
      proof = actualResult.proof;
      scopeHash = actualResult.scopeHash.length > 0 ? actualResult.scopeHash : undefined;
      chainHash = actualResult.chainHash.length > 0 ? actualResult.chainHash : undefined;
    } else if (hasScope) {
      mode = 'scoped';
      traceStep(
        trace, 6, 'build_proof',
        { mode, hmacMessage: `${timestamp}|${binding.binding}|bodyHash|scopeHash` },
        () => {
          const payload = bodyStr.length > 0 ? bodyStr : '';
          const r = ashBuildProofScoped(
            clientSecret, timestamp, binding.binding, payload, input.scope!,
          );
          return {
            proof: redact(r.proof),
            scopeHash: r.scopeHash.length > 0 ? redact(r.scopeHash) : undefined,
          };
        },
      );
      const payload = bodyStr.length > 0 ? bodyStr : '';
      const actualResult = ashBuildProofScoped(
        clientSecret, timestamp, binding.binding, payload, input.scope!,
      );
      proof = actualResult.proof;
      scopeHash = actualResult.scopeHash.length > 0 ? actualResult.scopeHash : undefined;
    } else {
      mode = 'basic';
      traceStep(
        trace, 6, 'build_proof',
        { mode, hmacMessage: `${timestamp}|${binding.binding}|bodyHash` },
        () => {
          const p = ashBuildProof(clientSecret, timestamp, binding.binding, bodyHash.bodyHash);
          return { proof: redact(p) };
        },
      );
      proof = ashBuildProof(clientSecret, timestamp, binding.binding, bodyHash.bodyHash);
    }

    // Step 7: Assemble result
    traceStep(trace, 7, 'assemble_result', { fieldCount: scopeHash ? (chainHash ? 7 : 6) : 5 }, () => {
      return { proof: redact(proof) };
    });

    const totalDurationMs = performance.now() - totalStart;

    let _proof = proof;
    let _clientSecret: string | null = clientSecret;

    return {
      proof: _proof,
      bodyHash: bodyHash.bodyHash,
      binding: binding.binding,
      timestamp,
      nonce: input.nonce,
      scopeHash,
      chainHash,
      destroy() {
        _proof = '';
        _clientSecret = null;
      },
      trace,
      mode,
      totalDurationMs,
    };
  } catch (err: unknown) {
    const totalDurationMs = performance.now() - totalStart;

    // Return a result with trace up to the error point
    return {
      proof: '',
      bodyHash: '',
      binding: '',
      timestamp: '',
      nonce: input.nonce,
      destroy() { /* no-op */ },
      trace,
      mode: 'basic',
      totalDurationMs,
    } as BuildRequestDebugResult;
  }
}

// ── ashVerifyRequestDebug ─────────────────────────────────────────

export function ashVerifyRequestDebug(input: VerifyRequestInput): VerifyRequestDebugResult {
  const totalStart = performance.now();
  const trace: TraceStep[] = [];
  const maxAge = input.maxAgeSeconds ?? DEFAULT_MAX_TIMESTAMP_AGE_SECONDS;
  const clockSkew = input.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  try {
    // Step 1: Extract headers
    const hdr = traceStep(trace, 1, 'extract_headers', { headerCount: Object.keys(input.headers).length }, () => {
      const h = ashExtractHeaders(input.headers);
      return {
        timestamp: h.timestamp,
        nonce: redact(h.nonce),
        bodyHash: redact(h.bodyHash),
        proof: redact(h.proof),
      };
    }) as { timestamp: string; nonce: string; bodyHash: string; proof: string };
    const actualHdr = ashExtractHeaders(input.headers);

    // Step 2: Validate timestamp format
    const tsValue = traceStep(trace, 2, 'validate_timestamp_format', { timestamp: actualHdr.timestamp }, () => {
      const val = ashValidateTimestampFormat(actualHdr.timestamp);
      return { parsedValue: val };
    }) as { parsedValue: number };

    // Step 3: Validate freshness
    traceStep(trace, 3, 'validate_freshness', { timestamp: actualHdr.timestamp, maxAge, clockSkew }, () => {
      ashValidateTimestamp(actualHdr.timestamp, maxAge, clockSkew);
      const now = Math.floor(Date.now() / 1000);
      const ageSeconds = now - tsValue.parsedValue;
      return { ageSeconds, withinWindow: true };
    });

    // Step 4: Validate nonce
    traceStep(trace, 4, 'validate_nonce', { nonce: redact(actualHdr.nonce) }, () => {
      ashValidateNonce(actualHdr.nonce);
      return { valid: true };
    });

    // Step 5: Normalize binding
    const bindingResult = traceStep(
      trace, 5, 'normalize_binding',
      { method: input.method, path: input.path, rawQuery: input.rawQuery ?? '' },
      () => {
        const b = ashNormalizeBinding(input.method, input.path, input.rawQuery ?? '');
        return { binding: b };
      },
    ) as { binding: string };

    // Step 6: Hash body
    const bodyStr = input.body ?? '';
    const computedBodyHash = traceStep(
      trace, 6, 'hash_body',
      { bodyLength: bodyStr.length },
      () => {
        const bh = ashHashBody(bodyStr.length > 0 ? ashCanonicalizeJson(bodyStr) : '');
        return { bodyHash: bh };
      },
    ) as { bodyHash: string };

    // Step 7: Compare body hash
    const bodyHashMatch = ashTimingSafeEqual(computedBodyHash.bodyHash, actualHdr.bodyHash);
    traceStep(trace, 7, 'compare_body_hash', {
      computed: redact(computedBodyHash.bodyHash),
      received: redact(actualHdr.bodyHash),
    }, () => {
      if (!bodyHashMatch) {
        throw AshError.proofInvalid();
      }
      return { match: true };
    });

    // Step 8: Verify proof
    const hasScope = input.scope && input.scope.length > 0;
    const hasPreviousProof = input.previousProof && input.previousProof.length > 0;
    let mode: 'basic' | 'scoped' | 'unified';
    const clientSecret = ashDeriveClientSecret(input.nonce, input.contextId, bindingResult.binding);

    if (hasPreviousProof) {
      mode = 'unified';
    } else if (hasScope) {
      mode = 'scoped';
    } else {
      mode = 'basic';
    }

    const proofMatch = traceStep(
      trace, 8, 'verify_proof',
      { mode, hmacMessage: `timestamp|binding|bodyHash${hasScope ? '|scopeHash' : ''}${hasPreviousProof ? '|chainHash' : ''}` },
      () => {
        if (hasPreviousProof) {
          const result = ashBuildProofUnified(
            clientSecret, actualHdr.timestamp, bindingResult.binding,
            bodyStr, input.scope ?? [], input.previousProof ?? null,
          );
          const match = ashTimingSafeEqual(result.proof, actualHdr.proof);
          if (!match) throw AshError.proofInvalid();
          return { match: true };
        } else if (hasScope) {
          const result = ashBuildProofScoped(
            clientSecret, actualHdr.timestamp, bindingResult.binding,
            bodyStr, input.scope!,
          );
          const match = ashTimingSafeEqual(result.proof, actualHdr.proof);
          if (!match) throw AshError.proofInvalid();
          return { match: true };
        } else {
          const expectedProof = ashBuildProof(
            clientSecret, actualHdr.timestamp, bindingResult.binding,
            computedBodyHash.bodyHash,
          );
          const match = ashTimingSafeEqual(expectedProof, actualHdr.proof);
          if (!match) throw AshError.proofInvalid();
          return { match: true };
        }
      },
    ) as { match: boolean };

    // Step 9: Assemble result
    traceStep(trace, 9, 'assemble_result', { mode, binding: bindingResult.binding }, () => {
      return { ok: true };
    });

    const totalDurationMs = performance.now() - totalStart;

    return {
      ok: true,
      meta: { mode, timestamp: tsValue.parsedValue, binding: bindingResult.binding },
      trace,
      totalDurationMs,
    };
  } catch (err: unknown) {
    const totalDurationMs = performance.now() - totalStart;

    const ashErr = err instanceof AshError
      ? err
      : AshError.internalError(err instanceof Error ? err.message : 'Unknown error during verification');

    return {
      ok: false,
      error: ashErr,
      trace,
      totalDurationMs,
    };
  }
}

// ── ashFormatTrace ────────────────────────────────────────────────

export function ashFormatTrace(trace: TraceStep[]): string {
  if (trace.length === 0) return '(empty trace)';

  const totalSteps = trace.length > 0 ? Math.max(...trace.map(s => s.step), trace.length) : 0;
  const lines: string[] = [];

  for (const step of trace) {
    const status = step.ok ? 'OK' : 'FAIL';
    const duration = step.durationMs.toFixed(2);
    const dots = '.'.repeat(Math.max(1, 30 - step.name.length));
    lines.push(`[${step.step}/${totalSteps}] ${step.name} ${dots} ${status} (${duration}ms)`);

    // Format output details
    if (step.output && typeof step.output === 'object') {
      for (const [key, value] of Object.entries(step.output as Record<string, unknown>)) {
        const display = typeof value === 'string' ? `"${value}"` : String(value);
        lines.push(`      ${key}: ${display}`);
      }
    }

    if (step.error) {
      lines.push(`      error: "${step.error}"`);
    }
  }

  return lines.join('\n');
}
