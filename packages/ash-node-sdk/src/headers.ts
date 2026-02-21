import { MAX_NONCE_LENGTH, SHA256_HEX_LENGTH } from './constants.js';
import { AshError } from './errors.js';

// ── Header Name Constants ──────────────────────────────────────────

export const X_ASH_TIMESTAMP = 'x-ash-ts';
export const X_ASH_NONCE = 'x-ash-nonce';
export const X_ASH_BODY_HASH = 'x-ash-body-hash';
export const X_ASH_PROOF = 'x-ash-proof';
export const X_ASH_CONTEXT_ID = 'x-ash-context-id';

/** Maximum proof length (SHA-256 HMAC hex = 64 chars). */
const MAX_PROOF_LENGTH = SHA256_HEX_LENGTH;

/** Maximum timestamp length (max Unix ts year ~3000 = 11 digits). */
const MAX_TIMESTAMP_LENGTH = 16;

/** Maximum context ID length (matches MAX_CONTEXT_ID_LENGTH = 256). */
const MAX_CONTEXT_ID_LENGTH = 256;

// ── Types ──────────────────────────────────────────────────────────

export interface AshHeaderBundle {
  timestamp: string;
  nonce: string;
  bodyHash: string;
  proof: string;
  contextId: string;
}

// ── Control character regex (ASCII 0-31 except tab 0x09) ───────────

const CONTROL_CHAR_RE = /[\x00-\x08\x0A-\x1F]/;

// ── Helpers ────────────────────────────────────────────────────────

/**
 * Case-insensitive header lookup.
 * Handles multi-value headers (arrays or comma-separated strings).
 */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  // Try exact match first, then case-insensitive scan
  const lowerName = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lowerName) {
      const val = headers[key];
      if (val === undefined) return undefined;
      if (Array.isArray(val)) {
        // Multi-value: concatenate with comma
        return val.join(', ');
      }
      return val;
    }
  }
  return undefined;
}

/**
 * Validate a header value: reject control characters.
 */
function validateHeaderValue(value: string, headerName: string): void {
  if (CONTROL_CHAR_RE.test(value)) {
    throw AshError.validationError(
      `Header ${headerName} contains invalid control characters`,
    );
  }
}

/**
 * Validate a header value does not exceed a length limit.
 */
function enforceLength(value: string, maxLength: number, headerName: string): void {
  if (value.length > maxLength) {
    throw AshError.validationError(
      `Header ${headerName} exceeds maximum length of ${maxLength} characters`,
    );
  }
}

// ── Main Function ──────────────────────────────────────────────────

/**
 * Extract and validate ASH headers from a request header map.
 *
 * - Case-insensitive lookup
 * - Multi-value concatenation (array → comma-separated)
 * - Control character rejection (ASCII 0-31 except tab)
 * - Length limit enforcement
 *
 * @throws AshError(PROOF_MISSING) if any required header is absent or empty.
 * @throws AshError(VALIDATION_ERROR) on control chars or oversized values.
 */
export function ashExtractHeaders(
  headers: Record<string, string | string[] | undefined>,
): AshHeaderBundle {
  const timestamp = getHeader(headers, X_ASH_TIMESTAMP);
  const nonce = getHeader(headers, X_ASH_NONCE);
  const bodyHash = getHeader(headers, X_ASH_BODY_HASH);
  const proof = getHeader(headers, X_ASH_PROOF);
  const contextId = getHeader(headers, X_ASH_CONTEXT_ID);

  // All five headers are required
  if (!timestamp || timestamp.length === 0) {
    throw AshError.proofMissing();
  }
  if (!nonce || nonce.length === 0) {
    throw AshError.proofMissing();
  }
  if (!bodyHash || bodyHash.length === 0) {
    throw AshError.proofMissing();
  }
  if (!proof || proof.length === 0) {
    throw AshError.proofMissing();
  }
  if (!contextId || contextId.length === 0) {
    throw AshError.proofMissing();
  }

  // Validate control characters
  validateHeaderValue(timestamp, X_ASH_TIMESTAMP);
  validateHeaderValue(nonce, X_ASH_NONCE);
  validateHeaderValue(bodyHash, X_ASH_BODY_HASH);
  validateHeaderValue(proof, X_ASH_PROOF);
  validateHeaderValue(contextId, X_ASH_CONTEXT_ID);

  // Enforce length limits
  enforceLength(timestamp, MAX_TIMESTAMP_LENGTH, X_ASH_TIMESTAMP);
  enforceLength(nonce, MAX_NONCE_LENGTH, X_ASH_NONCE);
  enforceLength(bodyHash, SHA256_HEX_LENGTH, X_ASH_BODY_HASH);
  enforceLength(proof, MAX_PROOF_LENGTH, X_ASH_PROOF);
  enforceLength(contextId, MAX_CONTEXT_ID_LENGTH, X_ASH_CONTEXT_ID);

  return {
    timestamp,
    nonce,
    bodyHash,
    proof,
    contextId,
  };
}
