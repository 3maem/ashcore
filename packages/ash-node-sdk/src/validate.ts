import {
  MIN_NONCE_HEX_CHARS,
  MAX_NONCE_LENGTH,
  MAX_TIMESTAMP,
  SHA256_HEX_LENGTH,
} from './constants.js';
import { AshError } from './errors.js';

const HEX_RE = /^[0-9a-fA-F]+$/;
const DIGITS_RE = /^[0-9]+$/;

/**
 * Validate nonce format and length. Does NOT check uniqueness.
 *
 * Rules:
 * - Minimum 32 hex characters (128 bits entropy)
 * - Maximum 512 characters
 * - All characters must be ASCII hexadecimal
 */
export function ashValidateNonce(nonce: string): void {
  if (nonce.length < MIN_NONCE_HEX_CHARS) {
    throw AshError.validationError(
      `Nonce must be at least ${MIN_NONCE_HEX_CHARS} hex characters (${MIN_NONCE_HEX_CHARS / 2} bytes) for adequate entropy`,
    );
  }

  if (nonce.length > MAX_NONCE_LENGTH) {
    throw AshError.validationError(
      `Nonce exceeds maximum length of ${MAX_NONCE_LENGTH} characters`,
    );
  }

  if (!HEX_RE.test(nonce)) {
    throw AshError.validationError(
      'Nonce must contain only hexadecimal characters (0-9, a-f, A-F)',
    );
  }
}

/**
 * Validate timestamp format only (not freshness).
 *
 * Rules:
 * - Non-empty
 * - Digits only (no whitespace, no signs)
 * - No leading zeros (except "0" itself)
 * - Parses as valid number within bounds
 *
 * @returns The parsed timestamp as a number.
 */
export function ashValidateTimestampFormat(timestamp: string): number {
  if (timestamp.length === 0) {
    throw AshError.timestampInvalid('Timestamp cannot be empty');
  }

  if (!DIGITS_RE.test(timestamp)) {
    throw AshError.timestampInvalid('Timestamp must contain only digits (0-9)');
  }

  // Reject leading zeros (except "0" itself)
  if (timestamp.length > 1 && timestamp[0] === '0') {
    throw AshError.timestampInvalid('Timestamp must not have leading zeros');
  }

  const ts = Number(timestamp);

  if (ts > MAX_TIMESTAMP) {
    throw AshError.timestampInvalid('Timestamp exceeds maximum allowed value');
  }

  return ts;
}

/**
 * Validate timestamp freshness against system clock.
 *
 * @param timestamp - Unix timestamp string (seconds)
 * @param maxAgeSeconds - Maximum allowed age
 * @param clockSkewSeconds - Tolerance for future timestamps
 * @returns The parsed timestamp value.
 */
export function ashValidateTimestamp(
  timestamp: string,
  maxAgeSeconds: number,
  clockSkewSeconds: number,
): number {
  const ts = ashValidateTimestampFormat(timestamp);

  const now = Math.floor(Date.now() / 1000);

  // Check for future timestamp
  if (ts > now + clockSkewSeconds) {
    throw AshError.timestampInvalid('Timestamp is in the future');
  }

  // Check for expired timestamp
  if (now > ts && now - ts > maxAgeSeconds) {
    throw AshError.timestampInvalid('Timestamp has expired');
  }

  return ts;
}

/**
 * Validate a SHA-256 hex hash string (64 hex chars).
 */
export function ashValidateHash(hash: string, label: string): void {
  if (hash.length !== SHA256_HEX_LENGTH) {
    throw AshError.validationError(
      `${label} must be ${SHA256_HEX_LENGTH} hex characters (SHA-256), got ${hash.length}`,
    );
  }

  if (!HEX_RE.test(hash)) {
    throw AshError.validationError(
      `${label} must contain only hexadecimal characters (0-9, a-f, A-F)`,
    );
  }
}
