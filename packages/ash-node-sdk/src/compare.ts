import { timingSafeEqual } from 'node:crypto';

/**
 * Timing-safe string comparison.
 *
 * Uses Node.js crypto.timingSafeEqual internally.
 * Handles different-length inputs safely by comparing padded buffers
 * plus a separate length check.
 */
export function ashTimingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  // If different lengths, pad the shorter one and compare,
  // then reject based on length mismatch.
  if (bufA.length !== bufB.length) {
    // Use max length to ensure constant-time comparison work
    const maxLen = Math.max(bufA.length, bufB.length);
    // If either is zero-length, still need to do work
    if (maxLen === 0) return true;
    const padA = Buffer.alloc(maxLen, 0);
    const padB = Buffer.alloc(maxLen, 0);
    bufA.copy(padA);
    bufB.copy(padB);
    // Perform the comparison (result is ignored — lengths differ)
    timingSafeEqual(padA, padB);
    return false;
  }

  // Same length: handle empty strings
  if (bufA.length === 0) return true;

  return timingSafeEqual(bufA, bufB);
}
