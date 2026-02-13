import { MAX_BINDING_LENGTH } from './constants.js';
import { AshError, AshErrorCode } from './errors.js';
import { ashCanonicalizeQuery } from './canonicalize.js';

/** Characters safe in URL paths — unreserved + sub-delimiters + : @ / */
const PATH_SAFE_RE = /[A-Za-z0-9\-_.~!$&'()*+,=:@/]/;

/**
 * Percent-decode a URL path.
 */
function percentDecodePath(input: string): string {
  const bytes: number[] = [];
  let i = 0;
  while (i < input.length) {
    if (input[i] === '%') {
      if (i + 2 >= input.length) {
        throw AshError.validationError('Invalid percent encoding in path');
      }
      const hex = input.substring(i + 1, i + 3);
      const byte = parseInt(hex, 16);
      if (isNaN(byte)) {
        throw AshError.validationError('Invalid percent encoding hex in path');
      }
      bytes.push(byte);
      i += 3;
    } else {
      const charBytes = Buffer.from(input[i], 'utf8');
      for (const b of charBytes) bytes.push(b);
      i++;
    }
  }
  const result = Buffer.from(bytes).toString('utf8');
  return result;
}

/**
 * Normalize path segments: resolve . and .., collapse //, remove trailing /.
 */
function normalizePathSegments(path: string): string {
  const segments: string[] = [];

  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
    } else {
      segments.push(segment);
    }
  }

  if (segments.length === 0) return '/';
  return '/' + segments.join('/');
}

/**
 * Percent-encode a URL path, preserving safe characters.
 */
function percentEncodePath(input: string): string {
  const buf = Buffer.from(input, 'utf8');
  let result = '';

  for (const byte of buf) {
    const ch = String.fromCharCode(byte);
    if (PATH_SAFE_RE.test(ch)) {
      result += ch;
    } else {
      result += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
    }
  }

  return result;
}

/**
 * Normalize a binding string to canonical form.
 *
 * Format: METHOD|PATH|CANONICAL_QUERY
 *
 * Rules:
 * - Method: ASCII uppercase, reject non-ASCII, reject pipe/control chars
 * - Path: percent-decode → NFC → reject null/control/? → resolve ./..// → remove trailing / → re-encode
 * - Query: canonicalize via ashCanonicalizeQuery
 */
export function ashNormalizeBinding(method: string, path: string, query: string): string {
  // Validate method
  const trimmedMethod = method.trim();
  if (trimmedMethod.length === 0) {
    throw AshError.validationError('Method cannot be empty');
  }

  // ASCII-only check
  for (let i = 0; i < trimmedMethod.length; i++) {
    const code = trimmedMethod.charCodeAt(i);
    if (code > 127) {
      throw AshError.validationError('Method must contain only ASCII characters');
    }
  }

  // Reject pipe and control characters
  for (let i = 0; i < trimmedMethod.length; i++) {
    const code = trimmedMethod.charCodeAt(i);
    if (trimmedMethod[i] === '|') {
      throw AshError.validationError("Method must not contain '|' (binding delimiter)");
    }
    if (code < 0x20 || code === 0x7f) {
      throw AshError.validationError('Method must not contain control characters');
    }
  }

  const upperMethod = trimmedMethod.toUpperCase();

  // Validate path
  const trimmedPath = path.trim();
  if (!trimmedPath.startsWith('/')) {
    throw AshError.validationError('Path must start with /');
  }

  // Percent-decode path
  const decodedPath = percentDecodePath(trimmedPath);

  // NFC normalize
  const nfcPath = decodedPath.normalize('NFC');

  // Reject null bytes
  if (nfcPath.includes('\0')) {
    throw AshError.validationError('Path must not contain null bytes (including encoded %00)');
  }

  // Reject control characters
  for (let i = 0; i < nfcPath.length; i++) {
    const code = nfcPath.charCodeAt(i);
    if ((code < 0x20 && code !== 0x2f /* / */) || code === 0x7f) {
      throw AshError.validationError(
        'Path must not contain control characters (including encoded forms)',
      );
    }
  }

  // Reject ? in decoded path
  if (nfcPath.includes('?')) {
    throw AshError.validationError(
      "Path must not contain '?' (including encoded %3F) - use ashNormalizeBindingFromUrl for combined path+query",
    );
  }

  // Normalize segments
  const normalizedPath = normalizePathSegments(nfcPath);

  // Re-encode
  const encodedPath = percentEncodePath(normalizedPath);

  // Canonicalize query
  const trimmedQuery = query.trim();
  const canonicalQuery = trimmedQuery.length === 0 ? '' : ashCanonicalizeQuery(trimmedQuery);

  // Build binding
  const binding = `${upperMethod}|${encodedPath}|${canonicalQuery}`;

  // Validate total binding length
  if (binding.length > MAX_BINDING_LENGTH) {
    throw AshError.validationError(
      `Binding exceeds maximum length of ${MAX_BINDING_LENGTH} bytes`,
    );
  }

  return binding;
}

/**
 * Normalize a binding from a full URL path (including query string).
 * Strips fragment, splits on ?, delegates to ashNormalizeBinding.
 */
export function ashNormalizeBindingFromUrl(method: string, fullPath: string): string {
  // Strip fragment
  const defragmented = fullPath.split('#')[0];

  const qIdx = defragmented.indexOf('?');
  if (qIdx === -1) {
    return ashNormalizeBinding(method, defragmented, '');
  }
  return ashNormalizeBinding(method, defragmented.slice(0, qIdx), defragmented.slice(qIdx + 1));
}
