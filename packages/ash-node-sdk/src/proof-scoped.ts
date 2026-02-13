import { MAX_SCOPE_FIELDS, MAX_TOTAL_ARRAY_ALLOCATION, MAX_BINDING_LENGTH, MAX_PAYLOAD_SIZE, SCOPE_FIELD_DELIMITER } from './constants.js';
import { AshError, AshErrorCode } from './errors.js';
import { ashCanonicalizeJsonValue } from './canonicalize.js';
import { ashHashBody, ashHashScope } from './hash.js';
import { ashDeriveClientSecret } from './proof.js';
import { ashTimingSafeEqual } from './compare.js';
import { ashValidateTimestampFormat } from './validate.js';
import { createHmac } from 'node:crypto';
import type { ScopedProofResult } from './types.js';

function hmacSha256(key: string, message: string): string {
  return createHmac('sha256', key).update(message, 'utf8').digest('hex');
}

/**
 * Navigate a parsed JSON value along a scope path (dot/bracket notation).
 * Returns the value at the path, or undefined if not found.
 */
function getNestedValue(payload: unknown, fieldPath: string): unknown {
  // Parse the path into segments: "user.address.city" → ["user", "address", "city"]
  // Handle bracket notation: "items[0].id" → ["items", "[0]", "id"]
  const segments: Array<{ key: string } | { index: number }> = [];

  let remaining = fieldPath;
  while (remaining.length > 0) {
    const bracketIdx = remaining.indexOf('[');
    const dotIdx = remaining.indexOf('.');

    if (bracketIdx === 0) {
      // Array index
      const closeBracket = remaining.indexOf(']');
      if (closeBracket === -1) return undefined;
      const indexStr = remaining.slice(1, closeBracket);
      const index = parseInt(indexStr, 10);
      if (isNaN(index) || index < 0) return undefined;
      segments.push({ index });
      remaining = remaining.slice(closeBracket + 1);
      if (remaining.startsWith('.')) remaining = remaining.slice(1);
    } else if (dotIdx === -1 && bracketIdx === -1) {
      // Last segment
      segments.push({ key: remaining });
      remaining = '';
    } else if (bracketIdx !== -1 && (dotIdx === -1 || bracketIdx < dotIdx)) {
      // Key before bracket
      const key = remaining.slice(0, bracketIdx);
      if (key.length > 0) segments.push({ key });
      remaining = remaining.slice(bracketIdx);
    } else {
      // Key before dot
      const key = remaining.slice(0, dotIdx);
      if (key.length > 0) segments.push({ key });
      remaining = remaining.slice(dotIdx + 1);
    }
  }

  let current: unknown = payload;
  for (const seg of segments) {
    if (current === null || current === undefined) return undefined;
    if ('key' in seg) {
      if (typeof current !== 'object' || Array.isArray(current)) return undefined;
      current = (current as Record<string, unknown>)[seg.key];
    } else {
      if (!Array.isArray(current)) return undefined;
      if (seg.index >= current.length) return undefined;
      current = current[seg.index];
    }
  }

  return current;
}

/**
 * Set a nested value in a result object along a scope path.
 * Builds the nested structure as needed.
 */
function setNestedValue(result: Record<string, unknown>, fieldPath: string, value: unknown): void {
  const segments: Array<{ key: string } | { index: number }> = [];

  let remaining = fieldPath;
  while (remaining.length > 0) {
    const bracketIdx = remaining.indexOf('[');
    const dotIdx = remaining.indexOf('.');

    if (bracketIdx === 0) {
      const closeBracket = remaining.indexOf(']');
      if (closeBracket === -1) return;
      const index = parseInt(remaining.slice(1, closeBracket), 10);
      if (isNaN(index) || index < 0) return;
      segments.push({ index });
      remaining = remaining.slice(closeBracket + 1);
      if (remaining.startsWith('.')) remaining = remaining.slice(1);
    } else if (dotIdx === -1 && bracketIdx === -1) {
      segments.push({ key: remaining });
      remaining = '';
    } else if (bracketIdx !== -1 && (dotIdx === -1 || bracketIdx < dotIdx)) {
      const key = remaining.slice(0, bracketIdx);
      if (key.length > 0) segments.push({ key });
      remaining = remaining.slice(bracketIdx);
    } else {
      const key = remaining.slice(0, dotIdx);
      if (key.length > 0) segments.push({ key });
      remaining = remaining.slice(dotIdx + 1);
    }
  }

  // Walk the path, creating intermediate objects/arrays as needed
  let current: unknown = result;
  for (let i = 0; i < segments.length - 1; i++) {
    const seg = segments[i];
    const nextSeg = segments[i + 1];
    const nextIsArray = 'index' in nextSeg;

    if ('key' in seg) {
      const obj = current as Record<string, unknown>;
      if (obj[seg.key] === undefined) {
        obj[seg.key] = nextIsArray ? [] : {};
      }
      current = obj[seg.key];
    } else {
      const arr = current as unknown[];
      while (arr.length <= seg.index) arr.push(undefined);
      if (arr[seg.index] === undefined || arr[seg.index] === null) {
        arr[seg.index] = nextIsArray ? [] : {};
      }
      current = arr[seg.index];
    }
  }

  // Set the final value
  const lastSeg = segments[segments.length - 1];
  if ('key' in lastSeg) {
    (current as Record<string, unknown>)[lastSeg.key] = value;
  } else {
    const arr = current as unknown[];
    while (arr.length <= lastSeg.index) arr.push(undefined);
    arr[lastSeg.index] = value;
  }
}

/**
 * Calculate total array allocation needed for scope paths.
 */
function calculateTotalArrayAllocation(scope: string[]): number {
  let total = 0;
  for (const path of scope) {
    const matches = path.matchAll(/\[(\d+)\]/g);
    for (const m of matches) {
      const idx = parseInt(m[1], 10);
      total += idx + 1;
    }
  }
  return total;
}

/**
 * Extract scoped fields from a parsed payload (lenient mode).
 * Missing fields are silently ignored.
 */
export function ashExtractScopedFields(
  payload: unknown,
  scope: string[],
): unknown {
  return extractScopedFieldsInternal(payload, scope, false);
}

/**
 * Extract scoped fields from a parsed payload (strict mode).
 * Throws if any field is missing.
 */
export function ashExtractScopedFieldsStrict(
  payload: unknown,
  scope: string[],
): unknown {
  return extractScopedFieldsInternal(payload, scope, true);
}

function extractScopedFieldsInternal(
  payload: unknown,
  scope: string[],
  strict: boolean,
): unknown {
  if (scope.length === 0) {
    return payload;
  }

  if (scope.length > MAX_SCOPE_FIELDS) {
    throw AshError.validationError(`Scope exceeds maximum of ${MAX_SCOPE_FIELDS} fields`);
  }

  const totalAlloc = calculateTotalArrayAllocation(scope);
  if (totalAlloc > MAX_TOTAL_ARRAY_ALLOCATION) {
    throw AshError.validationError(
      `Scope array indices exceed maximum total allocation of ${MAX_TOTAL_ARRAY_ALLOCATION} elements`,
    );
  }

  // Validate field names
  for (const field of scope) {
    if (field.length === 0) {
      throw AshError.validationError('Scope field names cannot be empty');
    }
    if (field.includes(SCOPE_FIELD_DELIMITER)) {
      throw AshError.validationError('Scope field contains reserved delimiter character (U+001F)');
    }
  }

  const result: Record<string, unknown> = {};

  for (const fieldPath of scope) {
    const value = getNestedValue(payload, fieldPath);
    if (value !== undefined) {
      setNestedValue(result, fieldPath, value);
    } else if (strict) {
      throw new AshError(
        AshErrorCode.SCOPED_FIELD_MISSING,
        `Required scoped field missing: ${fieldPath}`,
      );
    }
  }

  return result;
}

/**
 * Build scoped proof (client-side).
 *
 * Formula: proof = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash)
 */
export function ashBuildProofScoped(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: string,
  scope: string[],
): ScopedProofResult {
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

  const message = `${timestamp}|${binding}|${bodyHash}|${scopeHash}`;
  const proof = hmacSha256(clientSecret, message);

  return { proof, scopeHash };
}

/**
 * Verify scoped proof (server-side).
 */
export function ashVerifyProofScoped(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: string,
  scope: string[],
  scopeHash: string,
  clientProof: string,
): boolean {
  ashValidateTimestampFormat(timestamp);

  // Consistency check: scope/scopeHash must be both empty or both non-empty
  if (scope.length === 0 && scopeHash.length > 0) {
    throw AshError.scopeMismatch('scope_hash must be empty when scope is empty');
  }
  if (scope.length > 0 && scopeHash.length === 0) {
    throw AshError.scopeMismatch('scope_hash must not be empty when scope is provided');
  }

  // Verify scope hash
  const expectedScopeHash = ashHashScope(scope);
  if (!ashTimingSafeEqual(expectedScopeHash, scopeHash)) {
    return false;
  }

  const clientSecret = ashDeriveClientSecret(nonce, contextId, binding);
  const result = ashBuildProofScoped(clientSecret, timestamp, binding, payload, scope);
  return ashTimingSafeEqual(result.proof, clientProof);
}
