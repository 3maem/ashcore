import { AshError } from './errors.js';
import { DEFAULT_MAX_TIMESTAMP_AGE_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS } from './constants.js';
import { ashExtractHeaders } from './headers.js';
import { ashValidateTimestampFormat, ashValidateTimestamp, ashValidateNonce } from './validate.js';
import { ashNormalizeBinding } from './binding.js';
import { ashHashBody } from './hash.js';
import { ashTimingSafeEqual } from './compare.js';
import { ashDeriveClientSecret, ashBuildProof } from './proof.js';
import { ashBuildProofScoped } from './proof-scoped.js';
import { ashBuildProofUnified } from './proof-unified.js';
import { ashCanonicalizeJson } from './canonicalize.js';

// ── Types ──────────────────────────────────────────────────────────

export interface VerifyRequestInput {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  rawQuery?: string;
  body?: string;
  nonce: string;
  contextId: string;
  scope?: string[];
  previousProof?: string;
  maxAgeSeconds?: number;
  clockSkewSeconds?: number;
}

export interface VerifyResult {
  ok: boolean;
  error?: AshError;
  meta?: {
    mode: 'basic' | 'scoped' | 'unified';
    timestamp: number;
    binding: string;
  };
}

// ── Main Function ──────────────────────────────────────────────────

/**
 * 9-step verify orchestrator.
 *
 * 1. Extract headers
 * 2. Validate timestamp format
 * 3. Validate freshness
 * 4. Validate nonce
 * 5. Normalize binding
 * 6. Hash body
 * 7. Compare body hash
 * 8. Verify proof
 * 9. Return VerifyResult
 *
 * Errors at each step are caught and returned as { ok: false, error }.
 */
export function ashVerifyRequest(input: VerifyRequestInput): VerifyResult {
  const maxAge = input.maxAgeSeconds ?? DEFAULT_MAX_TIMESTAMP_AGE_SECONDS;
  const clockSkew = input.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  try {
    // Step 1: Extract headers
    const hdr = ashExtractHeaders(input.headers);

    // Step 2: Validate timestamp format
    const tsValue = ashValidateTimestampFormat(hdr.timestamp);

    // Step 3: Validate freshness
    ashValidateTimestamp(hdr.timestamp, maxAge, clockSkew);

    // Step 4: Validate nonce format
    ashValidateNonce(hdr.nonce);

    // Step 5: Normalize binding
    const binding = ashNormalizeBinding(input.method, input.path, input.rawQuery ?? '');

    // Step 6: Hash body
    const bodyStr = input.body ?? '';
    const bodyHash = ashHashBody(bodyStr.length > 0 ? ashCanonicalizeJson(bodyStr) : '');

    // Step 7: Compare body hash
    if (!ashTimingSafeEqual(bodyHash, hdr.bodyHash)) {
      return {
        ok: false,
        error: AshError.proofInvalid(),
      };
    }

    // Step 8: Verify proof — auto-detect mode
    const hasScope = input.scope && input.scope.length > 0;
    const hasPreviousProof = input.previousProof && input.previousProof.length > 0;

    let mode: 'basic' | 'scoped' | 'unified';

    const clientSecret = ashDeriveClientSecret(input.nonce, input.contextId, binding);

    if (hasPreviousProof || (hasScope && hasPreviousProof)) {
      // Unified mode
      mode = 'unified';
      const payload = bodyStr;
      const result = ashBuildProofUnified(
        clientSecret,
        hdr.timestamp,
        binding,
        payload,
        input.scope ?? [],
        input.previousProof ?? null,
      );
      if (!ashTimingSafeEqual(result.proof, hdr.proof)) {
        return { ok: false, error: AshError.proofInvalid() };
      }
    } else if (hasScope) {
      // Scoped mode
      mode = 'scoped';
      const payload = bodyStr;
      const result = ashBuildProofScoped(
        clientSecret,
        hdr.timestamp,
        binding,
        payload,
        input.scope!,
      );
      if (!ashTimingSafeEqual(result.proof, hdr.proof)) {
        return { ok: false, error: AshError.proofInvalid() };
      }
    } else {
      // Basic mode
      mode = 'basic';
      const expectedProof = ashBuildProof(clientSecret, hdr.timestamp, binding, bodyHash);
      if (!ashTimingSafeEqual(expectedProof, hdr.proof)) {
        return { ok: false, error: AshError.proofInvalid() };
      }
    }

    // Step 9: Return success
    return {
      ok: true,
      meta: { mode, timestamp: tsValue, binding },
    };
  } catch (err: unknown) {
    if (err instanceof AshError) {
      return { ok: false, error: err };
    }
    return {
      ok: false,
      error: AshError.internalError(
        err instanceof Error ? err.message : 'Unknown error during verification',
      ),
    };
  }
}
