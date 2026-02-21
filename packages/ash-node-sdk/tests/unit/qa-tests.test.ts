/**
 * ASH Node SDK v1.0.0 — Quality Assurance Tests (QA)
 *
 * Comprehensive edge cases, boundary conditions, consistency checks,
 * and cross-function integration tests.
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import {
  ASH_SDK_VERSION,
  ashCanonicalizeJson,
  ashCanonicalizeJsonValue,
  ashCanonicalizeQuery,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashNormalizeBindingFromUrl,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashBuildProofScoped,
  ashVerifyProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashHashBody,
  ashHashProof,
  ashHashScope,
  ashValidateNonce,
  ashValidateTimestampFormat,
  ashValidateTimestamp,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  AshError,
  AshErrorCode,
  MAX_PAYLOAD_SIZE,
  MAX_RECURSION_DEPTH,
  MAX_SCOPE_FIELDS,
  MAX_NONCE_LENGTH,
  MIN_NONCE_HEX_CHARS,
  MAX_BINDING_LENGTH,
  MAX_CONTEXT_ID_LENGTH,
  MAX_QUERY_PARAMS,
  MAX_TIMESTAMP,
  SHA256_HEX_LENGTH,
  SCOPE_FIELD_DELIMITER,
  PIPE_DELIMITER,
  DEFAULT_MAX_TIMESTAMP_AGE_SECONDS,
  DEFAULT_CLOCK_SKEW_SECONDS,
} from '../../src/index.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_qa_test';
const BINDING = 'POST|/api/test|';
const TS = '1700000000';

describe('QA: SDK version and constants', () => {
  it('QA-VER-001: SDK version is 1.0.0', () => {
    expect(ASH_SDK_VERSION).toBe('1.0.0');
  });

  it('QA-CONST-001: Constants have correct values', () => {
    expect(MAX_PAYLOAD_SIZE).toBe(10 * 1024 * 1024);
    expect(MAX_RECURSION_DEPTH).toBe(64);
    expect(MIN_NONCE_HEX_CHARS).toBe(32);
    expect(MAX_NONCE_LENGTH).toBe(512);
    expect(MAX_BINDING_LENGTH).toBe(8192);
    expect(MAX_CONTEXT_ID_LENGTH).toBe(256);
    expect(SHA256_HEX_LENGTH).toBe(64);
    expect(SCOPE_FIELD_DELIMITER).toBe('\x1F');
    expect(PIPE_DELIMITER).toBe('|');
    expect(DEFAULT_MAX_TIMESTAMP_AGE_SECONDS).toBe(300);
    expect(DEFAULT_CLOCK_SKEW_SECONDS).toBe(30);
    expect(MAX_SCOPE_FIELDS).toBe(100);
    expect(MAX_QUERY_PARAMS).toBe(1024);
  });
});

// ── JSON Canonicalization Edge Cases ────────────────────────────────

describe('QA: JSON canonicalization edge cases', () => {
  it('QA-JSON-001: Empty object', () => {
    expect(ashCanonicalizeJson('{}')).toBe('{}');
  });

  it('QA-JSON-002: Empty array', () => {
    expect(ashCanonicalizeJson('[]')).toBe('[]');
  });

  it('QA-JSON-003: Null', () => {
    expect(ashCanonicalizeJson('null')).toBe('null');
  });

  it('QA-JSON-004: Boolean true', () => {
    expect(ashCanonicalizeJson('true')).toBe('true');
  });

  it('QA-JSON-005: Boolean false', () => {
    expect(ashCanonicalizeJson('false')).toBe('false');
  });

  it('QA-JSON-006: Integer zero', () => {
    expect(ashCanonicalizeJson('0')).toBe('0');
  });

  it('QA-JSON-007: Negative zero becomes 0', () => {
    expect(ashCanonicalizeJson('-0')).toBe('0');
  });

  it('QA-JSON-008: String with escaped chars', () => {
    expect(ashCanonicalizeJson('"hello\\nworld"')).toBe('"hello\\nworld"');
  });

  it('QA-JSON-009: String with unicode escape', () => {
    expect(ashCanonicalizeJson('"\\u0041"')).toBe('"A"');
  });

  it('QA-JSON-010: Nested objects with sorted keys', () => {
    const result = ashCanonicalizeJson('{"b":{"d":1,"c":2},"a":3}');
    expect(result).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it('QA-JSON-011: Mixed array with types', () => {
    const result = ashCanonicalizeJson('[1,"two",true,null,{},[]]');
    expect(result).toBe('[1,"two",true,null,{},[]]');
  });

  it('QA-JSON-012: Duplicate keys — last wins', () => {
    const result = ashCanonicalizeJson('{"a":1,"a":2}');
    expect(result).toBe('{"a":2}');
  });

  it('QA-JSON-013: Whitespace stripped (pretty JSON)', () => {
    const result = ashCanonicalizeJson('{\n  "b": 1,\n  "a": 2\n}');
    expect(result).toBe('{"a":2,"b":1}');
  });

  it('QA-JSON-014: Floating point precision', () => {
    expect(ashCanonicalizeJson('1.0')).toBe('1');
    expect(ashCanonicalizeJson('1.5')).toBe('1.5');
    expect(ashCanonicalizeJson('0.1')).toBe('0.1');
  });

  it('QA-JSON-015: Large integer', () => {
    expect(ashCanonicalizeJson('9007199254740992')).toBe('9007199254740992');
  });

  it('QA-JSON-016: Negative integer', () => {
    expect(ashCanonicalizeJson('-42')).toBe('-42');
  });

  it('QA-JSON-017: Scientific notation normalized', () => {
    expect(ashCanonicalizeJson('1e2')).toBe('100');
  });

  it('QA-JSON-018: Empty string', () => {
    expect(ashCanonicalizeJson('""')).toBe('""');
  });

  it('QA-JSON-019: String with only whitespace', () => {
    expect(ashCanonicalizeJson('"   "')).toBe('"   "');
  });

  it('QA-JSON-020: Deeply nested array', () => {
    const input = '['.repeat(60) + '1' + ']'.repeat(60);
    expect(() => ashCanonicalizeJson(input)).not.toThrow();
  });

  it('QA-JSON-021: ashCanonicalizeJsonValue roundtrips with parsed object', () => {
    const obj = { z: 1, a: 'hello', m: [3, 2, 1] };
    const result = ashCanonicalizeJsonValue(obj);
    expect(result).toBe('{"a":"hello","m":[3,2,1],"z":1}');
  });

  it('QA-JSON-022: UTF-16 key sort order', () => {
    // '\u00e9' (233) sorts after 'z' (122) in UTF-16
    const result = ashCanonicalizeJson('{"\\u00e9":1,"z":2,"a":3}');
    expect(result).toBe('{"a":3,"z":2,"\u00e9":1}');
  });

  it('QA-JSON-023: NFC normalization on strings', () => {
    // 'e\u0301' (e + combining acute) → '\u00e9' (precomposed)
    const result = ashCanonicalizeJson('{"key":"caf\\u0065\\u0301"}');
    expect(result).toContain('caf\u00e9');
  });
});

// ── Query Canonicalization Edge Cases ────────────────────────────────

describe('QA: Query canonicalization edge cases', () => {
  it('QA-QUERY-001: Empty query returns empty string', () => {
    expect(ashCanonicalizeQuery('')).toBe('');
  });

  it('QA-QUERY-002: Query with leading ? stripped', () => {
    expect(ashCanonicalizeQuery('?a=1')).toBe('a=1');
  });

  it('QA-QUERY-003: Fragment stripped', () => {
    expect(ashCanonicalizeQuery('a=1#fragment')).toBe('a=1');
  });

  it('QA-QUERY-004: Key without value', () => {
    expect(ashCanonicalizeQuery('key')).toBe('key=');
  });

  it('QA-QUERY-005: Plus is literal (not space)', () => {
    const result = ashCanonicalizeQuery('a=1+2');
    expect(result).toContain('%2B');
    expect(result).not.toContain(' ');
  });

  it('QA-QUERY-006: Duplicate keys sorted by value', () => {
    const result = ashCanonicalizeQuery('a=2&a=1');
    expect(result).toBe('a=1&a=2');
  });

  it('QA-QUERY-007: Percent encoding normalized to uppercase', () => {
    const result = ashCanonicalizeQuery('key=%61');
    expect(result).toBe('key=a');
  });

  it('QA-QUERY-008: Special chars encoded', () => {
    const result = ashCanonicalizeQuery('key=hello world');
    expect(result).toContain('%20');
  });

  it('QA-QUERY-009: Unreserved chars not encoded', () => {
    const result = ashCanonicalizeQuery('key=hello-world_test.value~123');
    expect(result).toBe('key=hello-world_test.value~123');
  });

  it('QA-QUERY-010: Empty pairs skipped', () => {
    const result = ashCanonicalizeQuery('a=1&&b=2');
    expect(result).toBe('a=1&b=2');
  });

  it('QA-QUERY-011: Urlencoded produces same result', () => {
    expect(ashCanonicalizeUrlencoded('b=2&a=1')).toBe(ashCanonicalizeQuery('b=2&a=1'));
  });
});

// ── Binding Normalization Edge Cases ────────────────────────────────

describe('QA: Binding normalization edge cases', () => {
  it('QA-BIND-001: Root path', () => {
    expect(ashNormalizeBinding('GET', '/', '')).toBe('GET|/|');
  });

  it('QA-BIND-002: Trailing slash removed', () => {
    expect(ashNormalizeBinding('GET', '/api/', '')).toBe('GET|/api|');
  });

  it('QA-BIND-003: Double slash collapsed', () => {
    expect(ashNormalizeBinding('GET', '/api//users', '')).toBe('GET|/api/users|');
  });

  it('QA-BIND-004: Dot segment resolved', () => {
    expect(ashNormalizeBinding('GET', '/api/./users', '')).toBe('GET|/api/users|');
  });

  it('QA-BIND-005: Parent segment resolved', () => {
    expect(ashNormalizeBinding('GET', '/api/v1/../users', '')).toBe('GET|/api/users|');
  });

  it('QA-BIND-006: Method case insensitive', () => {
    expect(ashNormalizeBinding('post', '/api', '')).toBe('POST|/api|');
  });

  it('QA-BIND-007: All standard HTTP methods accepted', () => {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    for (const m of methods) {
      expect(() => ashNormalizeBinding(m, '/api', '')).not.toThrow();
    }
  });

  it('QA-BIND-008: ashNormalizeBindingFromUrl splits path and query', () => {
    const result = ashNormalizeBindingFromUrl('GET', '/api/users?page=1&sort=name');
    const expected = ashNormalizeBinding('GET', '/api/users', 'page=1&sort=name');
    expect(result).toBe(expected);
  });

  it('QA-BIND-009: ashNormalizeBindingFromUrl strips fragment', () => {
    const result = ashNormalizeBindingFromUrl('GET', '/api/users#section');
    const expected = ashNormalizeBinding('GET', '/api/users', '');
    expect(result).toBe(expected);
  });

  it('QA-BIND-010: ashNormalizeBindingFromUrl with query and fragment', () => {
    const result = ashNormalizeBindingFromUrl('GET', '/api?a=1#frag');
    const expected = ashNormalizeBinding('GET', '/api', 'a=1');
    expect(result).toBe(expected);
  });

  it('QA-BIND-011: Path with Unicode characters encoded correctly', () => {
    const result = ashNormalizeBinding('GET', '/api/caf\u00e9', '');
    expect(result).toContain('GET|/api/caf');
  });

  it('QA-BIND-012: Method with whitespace trimmed', () => {
    expect(ashNormalizeBinding('  GET  ', '/api', '')).toBe('GET|/api|');
  });
});

// ── Scoped Fields Edge Cases ────────────────────────────────────────

describe('QA: Scoped field extraction edge cases', () => {
  it('QA-SCOPE-001: Empty scope returns full payload', () => {
    const payload = { a: 1, b: 2 };
    const result = ashExtractScopedFields(payload, []);
    expect(result).toEqual({ a: 1, b: 2 });
  });

  it('QA-SCOPE-002: Single top-level field', () => {
    const payload = { a: 1, b: 2, c: 3 };
    const result = ashExtractScopedFields(payload, ['b']);
    expect(result).toEqual({ b: 2 });
  });

  it('QA-SCOPE-003: Nested field with dot notation', () => {
    const payload = { user: { name: 'alice', age: 30 } };
    const result = ashExtractScopedFields(payload, ['user.name']);
    expect(result).toEqual({ user: { name: 'alice' } });
  });

  it('QA-SCOPE-004: Array field with bracket notation', () => {
    const payload = { items: ['a', 'b', 'c'] };
    const result = ashExtractScopedFields(payload, ['items[1]']);
    expect(result).toEqual({ items: [undefined, 'b'] });
  });

  it('QA-SCOPE-005: Missing field in lenient mode returns empty object', () => {
    const payload = { a: 1 };
    const result = ashExtractScopedFields(payload, ['nonexistent']);
    expect(result).toEqual({});
  });

  it('QA-SCOPE-006: Missing field in strict mode throws', () => {
    const payload = { a: 1 };
    expect(() => ashExtractScopedFieldsStrict(payload, ['nonexistent'])).toThrow(AshError);
  });

  it('QA-SCOPE-007: Strict mode error has correct code', () => {
    expect.assertions(1);
    try {
      ashExtractScopedFieldsStrict({ a: 1 }, ['missing']);
    } catch (e: unknown) {
      const err = e as AshError;
      expect(err.code).toBe(AshErrorCode.SCOPED_FIELD_MISSING);
    }
  });

  it('QA-SCOPE-008: Deeply nested field', () => {
    const payload = { a: { b: { c: { d: 42 } } } };
    const result = ashExtractScopedFields(payload, ['a.b.c.d']);
    expect(result).toEqual({ a: { b: { c: { d: 42 } } } });
  });

  it('QA-SCOPE-009: Multiple fields from same object', () => {
    const payload = { a: 1, b: 2, c: 3 };
    const result = ashExtractScopedFields(payload, ['a', 'c']);
    expect(result).toEqual({ a: 1, c: 3 });
  });

  it('QA-SCOPE-010: Null value extracted correctly', () => {
    const payload = { a: null, b: 2 };
    const result = ashExtractScopedFields(payload, ['a']);
    expect(result).toEqual({ a: null });
  });

  it('QA-SCOPE-011: Boolean value extracted correctly', () => {
    const payload = { active: true };
    const result = ashExtractScopedFields(payload, ['active']);
    expect(result).toEqual({ active: true });
  });

  it('QA-SCOPE-012: Empty string field name rejected', () => {
    expect(() => ashExtractScopedFields({ a: 1 }, [''])).toThrow(AshError);
  });
});

// ── Timestamp Validation Edge Cases ─────────────────────────────────

describe('QA: Timestamp validation edge cases', () => {
  it('QA-TS-001: Timestamp "0" is valid', () => {
    expect(ashValidateTimestampFormat('0')).toBe(0);
  });

  it('QA-TS-002: Timestamp "1" is valid', () => {
    expect(ashValidateTimestampFormat('1')).toBe(1);
  });

  it('QA-TS-003: Empty timestamp rejected', () => {
    expect(() => ashValidateTimestampFormat('')).toThrow(AshError);
  });

  it('QA-TS-004: Leading zero rejected (except "0" itself)', () => {
    expect(() => ashValidateTimestampFormat('01')).toThrow(AshError);
  });

  it('QA-TS-005: Non-digit characters rejected', () => {
    expect(() => ashValidateTimestampFormat('123abc')).toThrow(AshError);
  });

  it('QA-TS-006: Negative number rejected', () => {
    expect(() => ashValidateTimestampFormat('-1')).toThrow(AshError);
  });

  it('QA-TS-007: Decimal rejected', () => {
    expect(() => ashValidateTimestampFormat('1.5')).toThrow(AshError);
  });

  it('QA-TS-008: Max timestamp boundary', () => {
    expect(ashValidateTimestampFormat(String(MAX_TIMESTAMP))).toBe(MAX_TIMESTAMP);
  });

  it('QA-TS-009: Over max timestamp rejected', () => {
    expect(() => ashValidateTimestampFormat(String(MAX_TIMESTAMP + 1))).toThrow(AshError);
  });

  it('QA-TS-010: Whitespace rejected', () => {
    expect(() => ashValidateTimestampFormat(' 123')).toThrow(AshError);
  });

  it('QA-TS-011: Timestamp freshness validation works', () => {
    const now = Math.floor(Date.now() / 1000);
    expect(ashValidateTimestamp(String(now), 300, 30)).toBe(now);
  });

  it('QA-TS-012: Very old timestamp rejected by freshness check', () => {
    expect(() => ashValidateTimestamp('1000000000', 300, 30)).toThrow(AshError);
  });

  it('QA-TS-013: Future timestamp rejected by freshness check', () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    expect(() => ashValidateTimestamp(String(future), 300, 30)).toThrow(AshError);
  });
});

// ── Nonce Validation Edge Cases ─────────────────────────────────────

describe('QA: Nonce validation edge cases', () => {
  it('QA-NONCE-001: Minimum length nonce (32 hex chars)', () => {
    expect(() => ashValidateNonce('a'.repeat(32))).not.toThrow();
  });

  it('QA-NONCE-002: One below minimum length rejected', () => {
    expect(() => ashValidateNonce('a'.repeat(31))).toThrow(AshError);
  });

  it('QA-NONCE-003: Maximum length nonce (512 chars)', () => {
    expect(() => ashValidateNonce('a'.repeat(512))).not.toThrow();
  });

  it('QA-NONCE-004: One above maximum length rejected', () => {
    expect(() => ashValidateNonce('a'.repeat(513))).toThrow(AshError);
  });

  it('QA-NONCE-005: Mixed case hex accepted', () => {
    expect(() => ashValidateNonce('0123456789abcdefABCDEF0123456789')).not.toThrow();
  });

  it('QA-NONCE-006: Non-hex characters rejected', () => {
    expect(() => ashValidateNonce('g'.repeat(32))).toThrow(AshError);
  });

  it('QA-NONCE-007: Empty nonce rejected', () => {
    expect(() => ashValidateNonce('')).toThrow(AshError);
  });
});

// ── End-to-End Flow Tests ───────────────────────────────────────────

describe('QA: End-to-end flow', () => {
  it('QA-E2E-001: Full proof cycle (derive → build → verify)', () => {
    const binding = ashNormalizeBinding('POST', '/api/transfer', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const canonical = ashCanonicalizeJson('{"amount":100}');
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, binding, bodyHash);
    const valid = ashVerifyProof(NONCE, CTX, binding, TS, bodyHash, proof);
    expect(valid).toBe(true);
  });

  it('QA-E2E-002: Full scoped proof cycle', () => {
    const binding = ashNormalizeBinding('POST', '/api/transfer', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const payload = '{"amount":100,"recipient":"alice","memo":"test"}';
    const r = ashBuildProofScoped(secret, TS, binding, payload, ['amount', 'recipient']);
    const valid = ashVerifyProofScoped(
      NONCE, CTX, binding, TS, payload,
      ['amount', 'recipient'], r.scopeHash, r.proof,
    );
    expect(valid).toBe(true);
  });

  it('QA-E2E-003: Full unified proof cycle with scope and chain', () => {
    const binding = ashNormalizeBinding('POST', '/api/transfer', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const payload = '{"amount":100}';

    const r1 = ashBuildProofUnified(secret, '1700000000', binding, payload, ['amount'], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', binding, payload, ['amount'], r1.proof);

    const valid = ashVerifyProofUnified(
      NONCE, CTX, binding, '1700000100', payload, r2.proof,
      ['amount'], r2.scopeHash, r1.proof, r2.chainHash,
    );
    expect(valid).toBe(true);
  });

  it('QA-E2E-004: Full cycle with URL binding', () => {
    const binding = ashNormalizeBindingFromUrl('GET', '/api/users?page=1&sort=name');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const bodyHash = ashHashBody('');
    const proof = ashBuildProof(secret, TS, binding, bodyHash);
    const valid = ashVerifyProof(NONCE, CTX, binding, TS, bodyHash, proof);
    expect(valid).toBe(true);
  });

  it('QA-E2E-005: Empty payload handled correctly', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofUnified(secret, TS, BINDING, '', [], null);
    const valid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, TS, '', r.proof,
      [], '', null, '',
    );
    expect(valid).toBe(true);
  });

  it('QA-E2E-006: Whitespace-only payload handled as empty', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofUnified(secret, TS, BINDING, '   ', [], null);
    expect(r.proof.length).toBe(64);
  });
});

// ── Error Classification ────────────────────────────────────────────

describe('QA: Error classification', () => {
  it('QA-ERR-001: All 15 AshErrorCode values exist', () => {
    const codes = Object.values(AshErrorCode);
    expect(codes.length).toBe(15);
    expect(codes.every(c => c.startsWith('ASH_'))).toBe(true);
  });

  it('QA-ERR-002: Error factory methods produce correct codes', () => {
    expect(AshError.ctxNotFound().code).toBe(AshErrorCode.CTX_NOT_FOUND);
    expect(AshError.ctxExpired().code).toBe(AshErrorCode.CTX_EXPIRED);
    expect(AshError.ctxAlreadyUsed().code).toBe(AshErrorCode.CTX_ALREADY_USED);
    expect(AshError.proofInvalid().code).toBe(AshErrorCode.PROOF_INVALID);
    expect(AshError.proofMissing().code).toBe(AshErrorCode.PROOF_MISSING);
    expect(AshError.bindingMismatch().code).toBe(AshErrorCode.BINDING_MISMATCH);
    expect(AshError.canonicalizationError().code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
    expect(AshError.validationError('test').code).toBe(AshErrorCode.VALIDATION_ERROR);
    expect(AshError.timestampInvalid('test').code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    expect(AshError.scopedFieldMissing('f').code).toBe(AshErrorCode.SCOPED_FIELD_MISSING);
    expect(AshError.scopeMismatch('test').code).toBe(AshErrorCode.SCOPE_MISMATCH);
    expect(AshError.chainBroken('test').code).toBe(AshErrorCode.CHAIN_BROKEN);
    expect(AshError.internalError('test').code).toBe(AshErrorCode.INTERNAL_ERROR);
  });

  it('QA-ERR-003: HTTP status codes are in correct ranges', () => {
    expect(AshError.ctxNotFound().httpStatus).toBe(450);
    expect(AshError.ctxExpired().httpStatus).toBe(451);
    expect(AshError.ctxAlreadyUsed().httpStatus).toBe(452);
    expect(AshError.proofInvalid().httpStatus).toBe(460);
    expect(AshError.bindingMismatch().httpStatus).toBe(461);
    expect(AshError.scopeMismatch('t').httpStatus).toBe(473);
    expect(AshError.chainBroken('t').httpStatus).toBe(474);
    expect(AshError.scopedFieldMissing('t').httpStatus).toBe(475);
    expect(AshError.timestampInvalid('t').httpStatus).toBe(482);
    expect(AshError.proofMissing().httpStatus).toBe(483);
    expect(AshError.canonicalizationError().httpStatus).toBe(484);
    expect(AshError.validationError('t').httpStatus).toBe(485);
    expect(AshError.internalError('t').httpStatus).toBe(500);
  });

  it('QA-ERR-004: Retryable codes are correct', () => {
    expect(AshError.timestampInvalid('t').retryable).toBe(true);
    expect(AshError.internalError('t').retryable).toBe(true);
    expect(AshError.ctxAlreadyUsed().retryable).toBe(true);
    expect(AshError.proofInvalid().retryable).toBe(false);
    expect(AshError.validationError('t').retryable).toBe(false);
  });

  it('QA-ERR-005: AshError extends Error', () => {
    const err = AshError.proofInvalid();
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AshError);
  });
});

// ── Hash Consistency ────────────────────────────────────────────────

describe('QA: Hash consistency', () => {
  it('QA-HASH-001: Same input produces same hash (deterministic)', () => {
    const h1 = ashHashBody('test');
    const h2 = ashHashBody('test');
    expect(h1).toBe(h2);
  });

  it('QA-HASH-002: Empty string hash matches known SHA-256', () => {
    expect(ashHashBody('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('QA-HASH-003: Scope hash with single field', () => {
    const h = ashHashScope(['field1']);
    expect(h.length).toBe(64);
    expect(/^[0-9a-f]+$/.test(h)).toBe(true);
  });

  it('QA-HASH-004: Scope hash order independent', () => {
    const h1 = ashHashScope(['a', 'b', 'c']);
    const h2 = ashHashScope(['c', 'a', 'b']);
    expect(h1).toBe(h2);
  });

  it('QA-HASH-005: Proof hash is deterministic', () => {
    const proof = 'a'.repeat(64);
    expect(ashHashProof(proof)).toBe(ashHashProof(proof));
  });

  it('QA-HASH-006: Different proofs produce different chain hashes', () => {
    const h1 = ashHashProof('a'.repeat(64));
    const h2 = ashHashProof('b'.repeat(64));
    expect(h1).not.toBe(h2);
  });
});
