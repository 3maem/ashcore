import { MAX_PAYLOAD_SIZE, MAX_RECURSION_DEPTH, MAX_QUERY_PARAMS } from './constants.js';
import { AshError, AshErrorCode } from './errors.js';

// ── Percent-encoding helpers ──────────────────────────────────────────

/** Characters that are unreserved per RFC 3986 and should NOT be encoded. */
const UNRESERVED_RE = /[A-Za-z0-9\-_.~]/;

/**
 * Percent-encode a string with uppercase hex digits.
 * Unreserved characters (A-Z a-z 0-9 - _ . ~) are NOT encoded.
 * Space is encoded as %20 (not +).
 * Everything else is encoded as %XX per UTF-8 byte.
 */
function percentEncodeUppercase(input: string): string {
  const buf = Buffer.from(input, 'utf8');
  let result = '';
  for (const byte of buf) {
    const ch = String.fromCharCode(byte);
    if (UNRESERVED_RE.test(ch)) {
      result += ch;
    } else {
      result += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return result;
}

/**
 * Percent-decode a query string component.
 * + is treated as literal plus (NOT space) per ashcore spec.
 */
function percentDecodeQuery(input: string): string {
  const bytes: number[] = [];
  let i = 0;
  while (i < input.length) {
    if (input[i] === '%') {
      if (i + 2 >= input.length) {
        throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'Invalid percent encoding');
      }
      const hex = input.substring(i + 1, i + 3);
      const byte = parseInt(hex, 16);
      if (isNaN(byte)) {
        throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'Invalid percent encoding hex');
      }
      bytes.push(byte);
      i += 3;
    } else {
      // + is literal plus, not space
      const charBytes = Buffer.from(input[i], 'utf8');
      for (const b of charBytes) bytes.push(b);
      i++;
    }
  }
  const decoded = Buffer.from(bytes).toString('utf8');
  // Check for invalid UTF-8 (replacement character indicates failure)
  return decoded;
}

/**
 * Parse query pairs from a raw query string.
 * Handles: stripping leading ?, fragment #, splitting on &, key=value parsing.
 */
function parseQueryPairs(input: string): Array<[string, string]> {
  // Strip leading ?
  let q = input.startsWith('?') ? input.slice(1) : input;

  // Strip fragment
  const hashIdx = q.indexOf('#');
  if (hashIdx !== -1) q = q.slice(0, hashIdx);

  if (q.length === 0) return [];

  const pairs: Array<[string, string]> = [];

  for (const part of q.split('&')) {
    if (part.length === 0) continue;

    const eqIdx = part.indexOf('=');
    let key: string;
    let value: string;
    if (eqIdx === -1) {
      key = part;
      value = '';
    } else {
      key = part.slice(0, eqIdx);
      value = part.slice(eqIdx + 1);
    }

    // Percent-decode
    const decodedKey = percentDecodeQuery(key);
    const decodedValue = percentDecodeQuery(value);

    // NFC normalize
    const normalizedKey = decodedKey.normalize('NFC');
    const normalizedValue = decodedValue.normalize('NFC');

    pairs.push([normalizedKey, normalizedValue]);
  }

  return pairs;
}

// ── Query Canonicalization ─────────────────────────────────────────────

/**
 * Canonicalize a URL query string.
 *
 * Rules:
 * 1. Strip leading ? if present
 * 2. Strip fragment (#) and everything after
 * 3. Split on & to get key=value pairs
 * 4. Keys without values get empty string value
 * 5. Percent-decode (+ is literal plus, NOT space)
 * 6. NFC normalize
 * 7. Sort by key (byte order)
 * 8. Sort by value for duplicate keys (byte order)
 * 9. Re-encode with uppercase hex
 * 10. Join with &
 */
export function ashCanonicalizeQuery(input: string): string {
  if (input.length > MAX_PAYLOAD_SIZE) {
    throw new AshError(
      AshErrorCode.CANONICALIZATION_ERROR,
      `Query string exceeds maximum size of ${MAX_PAYLOAD_SIZE} bytes`,
    );
  }

  const pairs = parseQueryPairs(input);

  if (pairs.length === 0) return '';

  if (pairs.length > MAX_QUERY_PARAMS) {
    throw new AshError(
      AshErrorCode.CANONICALIZATION_ERROR,
      `Query string exceeds maximum of ${MAX_QUERY_PARAMS} parameters`,
    );
  }

  // Sort by key (byte order), then by value for duplicate keys
  pairs.sort((a, b) => {
    const keyCmp = Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8'));
    if (keyCmp !== 0) return keyCmp;
    return Buffer.compare(Buffer.from(a[1], 'utf8'), Buffer.from(b[1], 'utf8'));
  });

  // Re-encode and join
  return pairs
    .map(([k, v]) => `${percentEncodeUppercase(k)}=${percentEncodeUppercase(v)}`)
    .join('&');
}

/**
 * Canonicalize URL-encoded form data.
 * Same rules as query canonicalization.
 */
export function ashCanonicalizeUrlencoded(input: string): string {
  if (input.length > MAX_PAYLOAD_SIZE) {
    throw new AshError(
      AshErrorCode.CANONICALIZATION_ERROR,
      `Payload exceeds maximum size of ${MAX_PAYLOAD_SIZE} bytes`,
    );
  }

  if (input.length === 0) return '';

  // Strip leading ? and fragment for consistency with query canonicalization
  let q = input.startsWith('?') ? input.slice(1) : input;
  const hashIdx = q.indexOf('#');
  if (hashIdx !== -1) q = q.slice(0, hashIdx);
  if (q.length === 0) return '';

  const pairs: Array<[string, string]> = [];

  for (const part of q.split('&')) {
    if (part.length === 0) continue;

    const eqIdx = part.indexOf('=');
    let key: string;
    let value: string;
    if (eqIdx === -1) {
      key = part;
      value = '';
    } else {
      key = part.slice(0, eqIdx);
      value = part.slice(eqIdx + 1);
    }

    const decodedKey = percentDecodeQuery(key);
    const decodedValue = percentDecodeQuery(value);

    const normalizedKey = decodedKey.normalize('NFC');
    const normalizedValue = decodedValue.normalize('NFC');

    pairs.push([normalizedKey, normalizedValue]);
  }

  if (pairs.length > MAX_QUERY_PARAMS) {
    throw new AshError(
      AshErrorCode.CANONICALIZATION_ERROR,
      `Query string exceeds maximum of ${MAX_QUERY_PARAMS} parameters`,
    );
  }

  // Sort by key (byte order), then by value
  pairs.sort((a, b) => {
    const keyCmp = Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8'));
    if (keyCmp !== 0) return keyCmp;
    return Buffer.compare(Buffer.from(a[1], 'utf8'), Buffer.from(b[1], 'utf8'));
  });

  return pairs
    .map(([k, v]) => `${percentEncodeUppercase(k)}=${percentEncodeUppercase(v)}`)
    .join('&');
}

// ── JSON Canonicalization (RFC 8785 / JCS) ──────────────────────────

/**
 * Compare two strings by UTF-16 code unit order per RFC 8785 Section 3.2.3.
 */
function cmpUtf16CodeUnits(a: string, b: string): number {
  // JavaScript strings are UTF-16 natively, so we can compare code units directly.
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = a.charCodeAt(i) - b.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  return a.length - b.length;
}

/**
 * Serialize a value to JSON with JCS-compliant rules.
 * - Sorted keys (UTF-16 code unit order)
 * - No whitespace
 * - ES6 Number.prototype.toString() for numbers
 * - Proper JSON string escaping
 */
function jcsSerialize(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'null';

  const type = typeof value;

  if (type === 'boolean') return value ? 'true' : 'false';

  if (type === 'number') {
    const n = value as number;
    if (!isFinite(n)) {
      throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'NaN/Infinity not supported in JCS');
    }
    // Object.is(-0, n) handles -0 → 0
    if (Object.is(n, -0)) return '0';
    // ES6 Number.prototype.toString() — JavaScript natively does this
    return String(n);
  }

  if (type === 'string') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map(v => jcsSerialize(v));
    return '[' + items.join(',') + ']';
  }

  if (type === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(cmpUtf16CodeUnits);
    const entries = keys.map(k => JSON.stringify(k) + ':' + jcsSerialize(obj[k]));
    return '{' + entries.join(',') + '}';
  }

  throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'Unsupported JSON type');
}

/**
 * Recursively canonicalize a parsed JSON value:
 * - NFC normalize strings
 * - Convert -0 to 0
 * - Convert whole floats to integers (handled natively by JS)
 * - Reject NaN/Infinity
 * - Track depth for recursion limit
 */
function canonicalizeValue(value: unknown, depth: number): unknown {
  if (depth >= MAX_RECURSION_DEPTH) {
    throw new AshError(
      AshErrorCode.CANONICALIZATION_ERROR,
      `JSON exceeds maximum nesting depth of ${MAX_RECURSION_DEPTH}`,
    );
  }

  if (value === null || value === undefined) return null;

  const type = typeof value;

  if (type === 'boolean') return value;

  if (type === 'number') {
    const n = value as number;
    if (!isFinite(n)) {
      throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'NaN/Infinity not supported');
    }
    if (Object.is(n, -0)) return 0;
    return n;
  }

  if (type === 'string') {
    // NFC normalize
    return (value as string).normalize('NFC');
  }

  if (Array.isArray(value)) {
    return value.map(v => canonicalizeValue(v, depth + 1));
  }

  if (type === 'object') {
    const obj = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(obj)) {
      const canonicalKey = key.normalize('NFC');
      result[canonicalKey] = canonicalizeValue(obj[key], depth + 1);
    }
    return result;
  }

  throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'Unsupported JSON type');
}

/**
 * Canonicalize a JSON string to deterministic form (RFC 8785 / JCS).
 *
 * Rules:
 * - Minified (no whitespace)
 * - Keys sorted by UTF-16 code unit order
 * - Array order preserved
 * - Unicode NFC normalization on strings
 * - -0 → 0, whole floats → integers
 * - NaN/Infinity rejected
 * - Duplicate keys: last wins (native JSON.parse behavior)
 */
export function ashCanonicalizeJson(input: string): string {
  if (input.length > MAX_PAYLOAD_SIZE) {
    throw new AshError(
      AshErrorCode.CANONICALIZATION_ERROR,
      `Payload exceeds maximum size of ${MAX_PAYLOAD_SIZE} bytes`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    throw new AshError(AshErrorCode.CANONICALIZATION_ERROR, 'Invalid JSON format');
  }

  const canonical = canonicalizeValue(parsed, 0);
  return jcsSerialize(canonical);
}

/**
 * Canonicalize a parsed JSON value to deterministic string.
 */
export function ashCanonicalizeJsonValue(value: unknown): string {
  const canonical = canonicalizeValue(value, 0);
  return jcsSerialize(canonical);
}
