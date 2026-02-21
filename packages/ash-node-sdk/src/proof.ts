import { createHmac } from 'node:crypto';
import { MAX_BINDING_LENGTH, MAX_CONTEXT_ID_LENGTH } from './constants.js';
import { AshError } from './errors.js';
import { ashValidateNonce, ashValidateTimestampFormat, ashValidateTimestamp, ashValidateHash } from './validate.js';
import { ashTimingSafeEqual } from './compare.js';
import { ashHashBody } from './hash.js';

/**
 * HMAC-SHA256 helper: key and message are both UTF-8 strings.
 * Returns lowercase hex.
 */
function hmacSha256(key: string, message: string): string {
  return createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

/**
 * Derive client secret from server nonce.
 *
 * Formula: clientSecret = HMAC-SHA256(key=nonce_lowercase_ascii, data=contextId|binding)
 *
 * The HMAC key is the ASCII bytes of the lowercase hex nonce string (NOT hex-decoded binary).
 */
export function ashDeriveClientSecret(nonce: string, contextId: string, binding: string): string {
  // Validate nonce
  ashValidateNonce(nonce);

  // Validate context_id
  if (contextId.length === 0) {
    throw AshError.validationError('context_id cannot be empty');
  }

  if (contextId.length > MAX_CONTEXT_ID_LENGTH) {
    throw AshError.validationError(
      `context_id exceeds maximum length of ${MAX_CONTEXT_ID_LENGTH} characters`,
    );
  }

  // Context ID charset: A-Z a-z 0-9 _ - .
  if (!/^[A-Za-z0-9_\-.]+$/.test(contextId)) {
    throw AshError.validationError(
      'context_id must contain only ASCII alphanumeric characters, underscore, hyphen, or dot',
    );
  }

  // Validate binding
  if (binding.length === 0) {
    throw AshError.validationError('binding cannot be empty');
  }

  if (binding.length > MAX_BINDING_LENGTH) {
    throw AshError.validationError(
      `binding exceeds maximum length of ${MAX_BINDING_LENGTH} bytes`,
    );
  }

  // Normalize nonce to lowercase for cross-SDK consistency
  const nonceKey = nonce.toLowerCase();

  // HMAC-SHA256(key=nonce_ascii, data="contextId|binding")
  const message = `${contextId}|${binding}`;
  return hmacSha256(nonceKey, message);
}

/**
 * Build cryptographic proof (client-side).
 *
 * Formula: proof = HMAC-SHA256(key=clientSecret_ascii, data=timestamp|binding|bodyHash)
 */
export function ashBuildProof(
  clientSecret: string,
  timestamp: string,
  binding: string,
  bodyHash: string,
): string {
  if (clientSecret.length === 0) {
    throw AshError.validationError('client_secret cannot be empty');
  }

  // Validate timestamp format
  ashValidateTimestampFormat(timestamp);

  if (binding.length === 0) {
    throw AshError.validationError('binding cannot be empty');
  }

  if (binding.length > MAX_BINDING_LENGTH) {
    throw AshError.validationError(
      `binding exceeds maximum length of ${MAX_BINDING_LENGTH} bytes`,
    );
  }

  // Validate body_hash format
  ashValidateHash(bodyHash, 'body_hash');

  // Normalize body_hash to lowercase
  const normalizedHash = bodyHash.toLowerCase();

  const message = `${timestamp}|${binding}|${normalizedHash}`;
  return hmacSha256(clientSecret, message);
}

/**
 * Verify proof (server-side).
 * Re-derives secret, rebuilds proof, timing-safe compares.
 *
 * @returns true if proof is valid, false if invalid.
 * @throws AshError if inputs are malformed.
 */
export function ashVerifyProof(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string,
): boolean {
  ashValidateTimestampFormat(timestamp);

  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const expectedProof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
  return ashTimingSafeEqual(expectedProof, clientProof);
}

/**
 * Verify proof with timestamp freshness check.
 */
export function ashVerifyProofWithFreshness(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string,
  maxAgeSeconds: number,
  clockSkewSeconds: number,
): boolean {
  ashValidateTimestamp(timestamp, maxAgeSeconds, clockSkewSeconds);

  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const expectedProof = ashBuildProof(clientSecret, timestamp, binding, bodyHash);
  return ashTimingSafeEqual(expectedProof, clientProof);
}
