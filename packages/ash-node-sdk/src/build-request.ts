import { ashValidateNonce, ashValidateTimestampFormat } from './validate.js';
import { ashNormalizeBinding } from './binding.js';
import { ashHashBody } from './hash.js';
import { ashDeriveClientSecret, ashBuildProof } from './proof.js';
import { ashBuildProofScoped } from './proof-scoped.js';
import { ashBuildProofUnified } from './proof-unified.js';
import { ashCanonicalizeJson } from './canonicalize.js';

// ── Types ──────────────────────────────────────────────────────────

export interface BuildRequestInput {
  nonce: string;
  contextId: string;
  method: string;
  path: string;
  rawQuery?: string;
  body?: string;
  timestamp?: string;
  scope?: string[];
  previousProof?: string;
}

export interface BuildRequestResult {
  proof: string;
  bodyHash: string;
  binding: string;
  timestamp: string;
  nonce: string;
  scopeHash?: string;
  chainHash?: string;
  destroy(): void;
}

// ── Main Function ──────────────────────────────────────────────────

/**
 * 7-step build orchestrator.
 *
 * 1. Validate nonce
 * 2. Validate/generate timestamp
 * 3. Normalize binding
 * 4. Hash body
 * 5. Derive client secret
 * 6. Build proof (auto-detect mode)
 * 7. Return result with destroy()
 */
export function ashBuildRequest(input: BuildRequestInput): BuildRequestResult {
  // Step 1: Validate nonce
  ashValidateNonce(input.nonce);

  // Step 2: Validate or generate timestamp
  const timestamp = input.timestamp ?? String(Math.floor(Date.now() / 1000));
  ashValidateTimestampFormat(timestamp);

  // Step 3: Normalize binding
  const binding = ashNormalizeBinding(input.method, input.path, input.rawQuery ?? '');

  // Step 4: Hash body
  const bodyStr = input.body ?? '';
  const bodyHash = ashHashBody(bodyStr.length > 0 ? ashCanonicalizeJson(bodyStr) : '');

  // Step 5: Derive client secret
  const clientSecret = ashDeriveClientSecret(input.nonce, input.contextId, binding);

  // Step 6: Build proof — auto-detect mode
  const hasScope = input.scope && input.scope.length > 0;
  const hasPreviousProof = input.previousProof && input.previousProof.length > 0;

  let proof: string;
  let scopeHash: string | undefined;
  let chainHash: string | undefined;

  if (hasPreviousProof) {
    // Unified mode (optional scope + chaining)
    const payload = bodyStr.length > 0 ? bodyStr : '';
    const result = ashBuildProofUnified(
      clientSecret,
      timestamp,
      binding,
      payload,
      input.scope ?? [],
      input.previousProof ?? null,
    );
    proof = result.proof;
    scopeHash = result.scopeHash.length > 0 ? result.scopeHash : undefined;
    chainHash = result.chainHash.length > 0 ? result.chainHash : undefined;
  } else if (hasScope) {
    // Scoped mode (scope without chaining)
    const payload = bodyStr.length > 0 ? bodyStr : '';
    const result = ashBuildProofScoped(
      clientSecret,
      timestamp,
      binding,
      payload,
      input.scope!,
    );
    proof = result.proof;
    scopeHash = result.scopeHash.length > 0 ? result.scopeHash : undefined;
  } else {
    // Basic mode
    proof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
  }

  // Step 7: Return result with destroy()
  let _proof = proof;
  let _clientSecret: string | null = clientSecret;

  return {
    proof: _proof,
    bodyHash,
    binding,
    timestamp,
    nonce: input.nonce,
    scopeHash,
    chainHash,
    destroy() {
      _proof = '';
      _clientSecret = null;
    },
  };
}
