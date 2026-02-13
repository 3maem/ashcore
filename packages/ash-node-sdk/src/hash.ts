import { createHash } from 'node:crypto';
import { SCOPE_FIELD_DELIMITER, MAX_SCOPE_FIELD_NAME_LENGTH, MAX_TOTAL_SCOPE_LENGTH } from './constants.js';
import { AshError } from './errors.js';

/**
 * SHA-256 hash of a string, returned as lowercase hex.
 */
function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Compute SHA-256 hash of canonical body.
 */
export function ashHashBody(canonicalBody: string): string {
  return sha256hex(canonicalBody);
}

/**
 * Hash a proof for chaining purposes.
 * Hashes the ASCII bytes of the proof hex string (NOT decoded binary).
 *
 * @throws AshError if proof is empty.
 */
export function ashHashProof(proof: string): string {
  if (proof.length === 0) {
    throw AshError.validationError('proof cannot be empty for chain hashing');
  }
  return sha256hex(proof);
}

/**
 * Sort, deduplicate, and join scope field names with unit separator,
 * then SHA-256 hash.
 *
 * Returns empty string if scope is empty.
 *
 * @throws AshError if any field name is invalid.
 */
export function ashHashScope(scope: string[]): string {
  if (scope.length === 0) return '';

  let totalLength = 0;

  for (const field of scope) {
    if (field.length === 0) {
      throw AshError.validationError('Scope field names cannot be empty');
    }
    if (field.length > MAX_SCOPE_FIELD_NAME_LENGTH) {
      throw AshError.validationError(
        `Scope field name exceeds maximum length of ${MAX_SCOPE_FIELD_NAME_LENGTH} characters`,
      );
    }
    if (field.includes(SCOPE_FIELD_DELIMITER)) {
      throw AshError.validationError(
        'Scope field contains reserved delimiter character (U+001F)',
      );
    }
    totalLength += field.length + 1;
  }

  if (totalLength > MAX_TOTAL_SCOPE_LENGTH) {
    throw AshError.validationError(
      `Total scope length exceeds maximum of ${MAX_TOTAL_SCOPE_LENGTH} bytes`,
    );
  }

  // Sort and deduplicate
  const sorted = [...new Set(scope)].sort();
  const joined = sorted.join(SCOPE_FIELD_DELIMITER);
  return sha256hex(joined);
}

/**
 * Hash scoped body: extract scoped fields, canonicalize, then SHA-256.
 * For internal use by proof-scoped and proof-unified.
 */
export function ashHashScopedBody(
  canonicalScopedPayload: string,
): string {
  return sha256hex(canonicalScopedPayload);
}
