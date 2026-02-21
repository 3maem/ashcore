import { createHmac } from 'node:crypto';
import { MAX_BINDING_LENGTH, MAX_PAYLOAD_SIZE } from './constants.js';
import { AshError, AshErrorCode } from './errors.js';
import { ashCanonicalizeJsonValue } from './canonicalize.js';
import { ashHashBody, ashHashScope, ashHashProof } from './hash.js';
import { ashExtractScopedFields } from './proof-scoped.js';
import { ashDeriveClientSecret } from './proof.js';
import { ashTimingSafeEqual } from './compare.js';
import { ashValidateTimestampFormat } from './validate.js';
import type { UnifiedProofResult } from './types.js';

function hmacSha256(key: string, message: string): string {
  return createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

/**
 * Build unified proof (client-side).
 *
 * Supports optional scoping and chaining:
 * - scope: Fields to protect (empty = full payload)
 * - previousProof: Previous proof in chain (null/undefined/"" = no chaining)
 *
 * Formula:
 *   scopeHash = scope.length > 0 ? SHA256(sorted(scope).join("\x1F")) : ""
 *   bodyHash = SHA256(canonicalize(scopedPayload))
 *   chainHash = previousProof ? SHA256(previousProof) : ""
 *   proof = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
 */
export function ashBuildProofUnified(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: string,
  scope: string[],
  previousProof?: string | null,
): UnifiedProofResult {
  if (clientSecret.length === 0) {
    throw AshError.validationError('client_secret cannot be empty');
  }
  ashValidateTimestampFormat(timestamp);
  if (binding.length === 0) {
    throw AshError.validationError('binding cannot be empty');
  }
  if (binding.length > MAX_BINDING_LENGTH) {
    throw AshError.validationError(`binding exceeds maximum length of ${MAX_BINDING_LENGTH} bytes`);
  }
  if (payload.length > MAX_PAYLOAD_SIZE) {
    throw AshError.validationError(`Payload exceeds maximum size of ${MAX_PAYLOAD_SIZE} bytes`);
  }

  // Parse payload
  let jsonPayload: unknown;
  if (payload.length === 0 || payload.trim().length === 0) {
    jsonPayload = {};
  } else {
    try {
      jsonPayload = JSON.parse(payload);
    } catch {
      throw AshError.canonicalizationError();
    }
  }

  const scopedPayload = ashExtractScopedFields(jsonPayload, scope);
  const canonicalScoped = ashCanonicalizeJsonValue(scopedPayload);
  const bodyHash = ashHashBody(canonicalScoped);
  const scopeHash = ashHashScope(scope);

  // Chain hash: SHA256 of previous proof's ASCII hex bytes
  let chainHash = '';
  if (previousProof && previousProof.length > 0) {
    chainHash = ashHashProof(previousProof);
  }

  const message = `${timestamp}|${binding}|${bodyHash}|${scopeHash}|${chainHash}`;
  const proof = hmacSha256(clientSecret, message);

  return { proof, scopeHash, chainHash };
}

/**
 * Verify unified proof (server-side).
 */
export function ashVerifyProofUnified(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: string,
  clientProof: string,
  scope: string[],
  scopeHash: string,
  previousProof: string | null | undefined,
  chainHash: string,
): boolean {
  ashValidateTimestampFormat(timestamp);

  // Consistency: scope/scopeHash
  if (scope.length === 0 && scopeHash.length > 0) {
    throw AshError.scopeMismatch('scope_hash must be empty when scope is empty');
  }
  if (scope.length > 0 && scopeHash.length === 0) {
    throw AshError.scopeMismatch('scope_hash must not be empty when scope is provided');
  }

  // Verify scope hash
  if (scope.length > 0) {
    const expectedScopeHash = ashHashScope(scope);
    if (!ashTimingSafeEqual(expectedScopeHash, scopeHash)) {
      return false;
    }
  }

  // Consistency: previousProof/chainHash
  const hasPrevious = previousProof != null && previousProof.length > 0;
  if (!hasPrevious && chainHash.length > 0) {
    throw new AshError(AshErrorCode.CHAIN_BROKEN, 'chain_hash must be empty when previous_proof is absent');
  }

  // Verify chain hash
  if (hasPrevious) {
    const expectedChainHash = ashHashProof(previousProof!);
    if (!ashTimingSafeEqual(expectedChainHash, chainHash)) {
      return false;
    }
  }

  // Derive and verify proof
  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const result = ashBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof);
  return ashTimingSafeEqual(result.proof, clientProof);
}
