/**
 * ASH Node SDK v1.0.0 — Comprehensive Security & Edge Case Tests
 *
 * Advanced tests covering: protocol-level attacks, Unicode/encoding edge cases,
 * error path exhaustive testing, boundary conditions, cross-function integration,
 * canonicalization corner cases, and advanced cryptographic verification.
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import {
  ashCanonicalizeJson,
  ashCanonicalizeJsonValue,
  ashCanonicalizeQuery,
  ashNormalizeBinding,
  ashNormalizeBindingFromUrl,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashVerifyProofWithFreshness,
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
  ashValidateHash,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  AshError,
  AshErrorCode,
  MAX_PAYLOAD_SIZE,
  MAX_TIMESTAMP,
} from '../../src/index.js';

const NONCE = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const CTX = 'ctx_sec_test';
const BINDING = 'POST|/api/transfer|';
const TS = '1700000000';
const PAYLOAD = '{"amount":100,"recipient":"alice"}';
const VALID_BODY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// ════════════════════════════════════════════════════════════════════
// SECTION 1: UNICODE & ENCODING EDGE CASES
// ════════════════════════════════════════════════════════════════════

describe('SEC-UNICODE: Unicode edge cases in JSON canonicalization', () => {
  it('SEC-UNI-001: NFC normalization (combining characters)', () => {
    // é as e + combining acute accent → precomposed é
    const decomposed = '{"key":"caf\u0065\u0301"}';
    const precomposed = '{"key":"caf\u00e9"}';
    const c1 = ashCanonicalizeJson(decomposed);
    const c2 = ashCanonicalizeJson(precomposed);
    expect(c1).toBe(c2);
  });

  it('SEC-UNI-002: NFC normalization on keys', () => {
    const decomposed = '{"\u0065\u0301":1}';
    const precomposed = '{"\u00e9":1}';
    expect(ashCanonicalizeJson(decomposed)).toBe(ashCanonicalizeJson(precomposed));
  });

  it('SEC-UNI-003: Surrogate pairs preserved', () => {
    // Emoji: 😀 = U+1F600
    const input = '{"emoji":"\\uD83D\\uDE00"}';
    const result = ashCanonicalizeJson(input);
    expect(result).toContain('\uD83D\uDE00');
  });

  it('SEC-UNI-004: Zero-width characters preserved in values', () => {
    const input = '{"key":"hello\u200Bworld"}';
    const result = ashCanonicalizeJson(input);
    expect(result).toContain('\u200B');
  });

  it('SEC-UNI-005: BOM character in JSON string value', () => {
    const input = '{"key":"\uFEFFhello"}';
    const result = ashCanonicalizeJson(input);
    expect(result).toContain('\uFEFF');
  });

  it('SEC-UNI-006: RTL override character in string', () => {
    const input = '{"key":"hello\u202Eworld"}';
    const result = ashCanonicalizeJson(input);
    // Should preserve the character in the value
    expect(JSON.parse(result).key).toContain('\u202E');
  });

  it('SEC-UNI-007: Multi-codepoint emoji sequence', () => {
    const input = '{"flag":"🇺🇸"}';
    const result = ashCanonicalizeJson(input);
    const parsed = JSON.parse(result);
    expect(parsed.flag).toBe('🇺🇸');
  });

  it('SEC-UNI-008: Keys with accented chars sort by UTF-16 code units', () => {
    const result = ashCanonicalizeJson('{"ä":1,"a":2,"z":3}');
    const keys = Object.keys(JSON.parse(result));
    // 'a' (0x61) < 'z' (0x7A) < 'ä' (0xE4) in UTF-16
    expect(keys).toEqual(['a', 'z', 'ä']);
  });

  it('SEC-UNI-009: JSON string escaping of control characters', () => {
    const result = ashCanonicalizeJson('{"key":"line1\\nline2\\ttab"}');
    expect(result).toBe('{"key":"line1\\nline2\\ttab"}');
  });

  it('SEC-UNI-010: Empty string value', () => {
    expect(ashCanonicalizeJson('{"key":""}')).toBe('{"key":""}');
  });

  it('SEC-UNI-011: Unicode escape normalization', () => {
    // \u0041 = 'A'
    const result = ashCanonicalizeJson('{"\\u0041":1}');
    expect(result).toBe('{"A":1}');
  });

  it('SEC-UNI-012: Hangul composition (NFC)', () => {
    // Hangul syllable 가 = ᄀ + ᅡ (decomposed) → 가 (NFC)
    const decomposed = '{"key":"\u1100\u1161"}';
    const composed = '{"key":"\uAC00"}';
    expect(ashCanonicalizeJson(decomposed)).toBe(ashCanonicalizeJson(composed));
  });
});

describe('SEC-UNICODE: Unicode edge cases in query canonicalization', () => {
  it('SEC-QUNI-001: NFC normalized query keys', () => {
    const result1 = ashCanonicalizeQuery('caf\u0065\u0301=1');
    const result2 = ashCanonicalizeQuery('caf\u00e9=1');
    expect(result1).toBe(result2);
  });

  it('SEC-QUNI-002: NFC normalized query values', () => {
    const result1 = ashCanonicalizeQuery('key=caf\u0065\u0301');
    const result2 = ashCanonicalizeQuery('key=caf\u00e9');
    expect(result1).toBe(result2);
  });

  it('SEC-QUNI-003: Multi-byte UTF-8 characters encoded correctly', () => {
    const result = ashCanonicalizeQuery('key=\u00e9');
    // é = 0xC3 0xA9 in UTF-8
    expect(result).toContain('%C3%A9');
  });

  it('SEC-QUNI-004: Chinese characters in query', () => {
    const result = ashCanonicalizeQuery('name=测试');
    expect(result).toContain('%');
    // Should be percent-encoded UTF-8 bytes
    expect(result.startsWith('name=')).toBe(true);
  });

  it('SEC-QUNI-005: Arabic characters in query', () => {
    const result = ashCanonicalizeQuery('text=مرحبا');
    expect(result).toContain('%');
  });
});

describe('SEC-UNICODE: Unicode edge cases in binding normalization', () => {
  it('SEC-BUNI-001: Unicode path segments percent-encoded', () => {
    const result = ashNormalizeBinding('GET', '/api/données', '');
    expect(result).toContain('%');
    expect(result.startsWith('GET|')).toBe(true);
  });

  it('SEC-BUNI-002: Percent-encoded Unicode decoded then re-encoded', () => {
    // é = %C3%A9 or %c3%a9 — should normalize to uppercase
    const r1 = ashNormalizeBinding('GET', '/api/%c3%a9', '');
    const r2 = ashNormalizeBinding('GET', '/api/%C3%A9', '');
    expect(r1).toBe(r2);
  });

  it('SEC-BUNI-003: Mixed encoded/unencoded Unicode normalizes consistently', () => {
    const r1 = ashNormalizeBinding('GET', '/api/café', '');
    const r2 = ashNormalizeBinding('GET', '/api/caf%C3%A9', '');
    expect(r1).toBe(r2);
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 2: PROTOCOL-LEVEL ATTACK SCENARIOS
// ════════════════════════════════════════════════════════════════════

describe('SEC-ATTACK: Advanced protocol-level attacks', () => {
  it('SEC-ATK-001: Proof transplant attack — different endpoint same payload', () => {
    const secret1 = ashDeriveClientSecret(NONCE, CTX, 'POST|/api/transfer|');
    const bodyHash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    const proof = ashBuildProof(secret1, TS, 'POST|/api/transfer|', bodyHash);
    const result = ashVerifyProof(NONCE, CTX, 'POST|/api/admin|', TS, bodyHash, proof);
    expect(result).toBe(false);
  });

  it('SEC-ATK-002: Context reuse across endpoints', () => {
    const b1 = 'POST|/api/transfer|';
    const b2 = 'POST|/api/withdraw|';
    const secret1 = ashDeriveClientSecret(NONCE, CTX, b1);
    const secret2 = ashDeriveClientSecret(NONCE, CTX, b2);
    // Secrets are different because binding is part of derivation
    expect(secret1).not.toBe(secret2);
    // So a proof for one endpoint cannot be used for another
    const bodyHash = ashHashBody('{}');
    const proof = ashBuildProof(secret1, TS, b1, bodyHash);
    expect(ashVerifyProof(NONCE, CTX, b2, TS, bodyHash, proof)).toBe(false);
  });

  it('SEC-ATK-003: Timestamp extension attack — reuse proof with future timestamp', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const bodyHash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    const proof = ashBuildProof(secret, '1700000000', BINDING, bodyHash);
    // Try to extend the timestamp
    expect(ashVerifyProof(NONCE, CTX, BINDING, '1700000001', bodyHash, proof)).toBe(false);
    expect(ashVerifyProof(NONCE, CTX, BINDING, '1700001000', bodyHash, proof)).toBe(false);
  });

  it('SEC-ATK-004: Scope downgrade attack — narrow scope to exclude protected field', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    // Build proof with scope ['amount', 'recipient']
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount', 'recipient']);
    // Try to verify with narrower scope ['amount'] — should fail
    const scopeHash2 = ashHashScope(['amount']);
    const valid = ashVerifyProofScoped(NONCE, CTX, BINDING, TS, PAYLOAD, ['amount'], scopeHash2, r.proof);
    expect(valid).toBe(false);
  });

  it('SEC-ATK-005: Scope expansion attack — add field to scope', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r = ashBuildProofScoped(secret, TS, BINDING, PAYLOAD, ['amount']);
    const wider = ['amount', 'recipient'];
    const scopeHash2 = ashHashScope(wider);
    const valid = ashVerifyProofScoped(NONCE, CTX, BINDING, TS, PAYLOAD, wider, scopeHash2, r.proof);
    expect(valid).toBe(false);
  });

  it('SEC-ATK-006: Chain injection — insert proof into chain', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const r1 = ashBuildProofUnified(secret, '1700000000', BINDING, PAYLOAD, [], null);
    const r2 = ashBuildProofUnified(secret, '1700000100', BINDING, PAYLOAD, [], r1.proof);
    const r3 = ashBuildProofUnified(secret, '1700000200', BINDING, PAYLOAD, [], r2.proof);

    // Inject a fake proof between r1 and r3
    const fakeProof = 'deadbeef'.repeat(8);
    const valid = ashVerifyProofUnified(
      NONCE, CTX, BINDING, '1700000200', PAYLOAD, r3.proof,
      [], '', fakeProof, r3.chainHash,
    );
    expect(valid).toBe(false);
  });

  it('SEC-ATK-007: Method confusion — lowercase/uppercase bypass attempt', () => {
    const b1 = ashNormalizeBinding('GET', '/api/admin', '');
    const b2 = ashNormalizeBinding('get', '/api/admin', '');
    expect(b1).toBe(b2); // Both normalize to uppercase
    // Attempt with different method
    const b3 = ashNormalizeBinding('POST', '/api/admin', '');
    expect(b1).not.toBe(b3);
  });

  it('SEC-ATK-008: Path confusion — dot segment bypass', () => {
    const direct = ashNormalizeBinding('GET', '/admin', '');
    const traversal = ashNormalizeBinding('GET', '/api/../admin', '');
    expect(direct).toBe(traversal); // Same normalized path
  });

  it('SEC-ATK-009: Double encoding bypass attempt', () => {
    // %252e = %2e after first decode = . after second decode
    // But ASH only decodes once, so %252e stays as %2e character
    const r1 = ashNormalizeBinding('GET', '/api/%252e%252e/admin', '');
    const r2 = ashNormalizeBinding('GET', '/admin', '');
    // These should be different because %252e is not a directory traversal
    expect(r1).not.toBe(r2);
  });

  it('SEC-ATK-010: Body hash collision attempt (uppercase vs lowercase)', () => {
    const secret = ashDeriveClientSecret(NONCE, CTX, BINDING);
    const hash = ashHashBody(ashCanonicalizeJson(PAYLOAD));
    const upperHash = hash.toUpperCase();
    // Both should produce the same proof due to normalization
    const p1 = ashBuildProof(secret, TS, BINDING, hash);
    const p2 = ashBuildProof(secret, TS, BINDING, upperHash);
    expect(p1).toBe(p2);
  });

  it('SEC-ATK-011: Prefix/suffix attack on binding delimiter', () => {
    // Attempt to create binding collision via delimiter manipulation
    // "POST|/api" + "|" + "extra|/other" — but binding validation should prevent this
    const b1 = ashNormalizeBinding('POST', '/api', '');
    expect(b1).toBe('POST|/api|');
    // Different path
    const b2 = ashNormalizeBinding('POST', '/api/other', '');
    expect(b1).not.toBe(b2);
  });

  it('SEC-ATK-012: Nonce entropy exhaustion — minimum length nonce', () => {
    const minNonce = '0'.repeat(32);
    // Valid but weak — still must produce correct crypto
    const secret = ashDeriveClientSecret(minNonce, CTX, BINDING);
    expect(secret.length).toBe(64);
    const bodyHash = ashHashBody('{}');
    const proof = ashBuildProof(secret, TS, BINDING, bodyHash);
    expect(ashVerifyProof(minNonce, CTX, BINDING, TS, bodyHash, proof)).toBe(true);
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 3: ERROR PATH EXHAUSTIVE TESTING
// ════════════════════════════════════════════════════════════════════

describe('SEC-ERROR: Exhaustive error path coverage', () => {
  // ashValidateNonce errors
  it('SEC-ERR-NONCE-001: Empty nonce → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashValidateNonce(''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-NONCE-002: Too short nonce → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashValidateNonce('a'.repeat(31)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-NONCE-003: Too long nonce → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashValidateNonce('a'.repeat(513)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-NONCE-004: Non-hex nonce → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashValidateNonce('g'.repeat(32)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashValidateTimestampFormat errors
  it('SEC-ERR-TS-001: Empty timestamp → TIMESTAMP_INVALID', () => {
    expect.assertions(2);
    try { ashValidateTimestampFormat(''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
      expect((e as AshError).httpStatus).toBe(482);
    }
  });

  it('SEC-ERR-TS-002: Non-digit timestamp → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    try { ashValidateTimestampFormat('12.3'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  it('SEC-ERR-TS-003: Leading zeros → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    try { ashValidateTimestampFormat('01'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  it('SEC-ERR-TS-004: Over max → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    try { ashValidateTimestampFormat(String(MAX_TIMESTAMP + 1)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  it('SEC-ERR-TS-005: Negative → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    try { ashValidateTimestampFormat('-1'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  it('SEC-ERR-TS-006: With spaces → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    try { ashValidateTimestampFormat(' 123'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  it('SEC-ERR-TS-007: With plus sign → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    try { ashValidateTimestampFormat('+123'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  // ashValidateTimestamp freshness errors
  it('SEC-ERR-TS-008: Expired timestamp → TIMESTAMP_INVALID (retryable)', () => {
    expect.assertions(2);
    try { ashValidateTimestamp('1000000000', 300, 30); } catch (e) {
      const err = e as AshError;
      expect(err.code).toBe(AshErrorCode.TIMESTAMP_INVALID);
      expect(err.retryable).toBe(true);
    }
  });

  it('SEC-ERR-TS-009: Future timestamp → TIMESTAMP_INVALID', () => {
    expect.assertions(1);
    const future = Math.floor(Date.now() / 1000) + 3600;
    try { ashValidateTimestamp(String(future), 300, 30); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.TIMESTAMP_INVALID);
    }
  });

  // ashValidateHash errors
  it('SEC-ERR-HASH-001: Wrong length → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashValidateHash('abc', 'test'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-HASH-002: Non-hex chars → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashValidateHash('g'.repeat(64), 'test'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashNormalizeBinding errors
  it('SEC-ERR-BIND-001: Empty method → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('', '/api', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-002: Non-ASCII method → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GÉT', '/api', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-003: Pipe in method → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GET|X', '/api', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-004: Control char in method → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GET\x01', '/api', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-005: Path not starting with / → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GET', 'api', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-006: Null byte in path → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GET', '/api/%00', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-007: ? in decoded path → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GET', '/api/%3F', ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-BIND-008: Binding too long → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashNormalizeBinding('GET', '/api/' + 'a'.repeat(8200), ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashDeriveClientSecret errors
  it('SEC-ERR-SECRET-001: Empty context_id → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashDeriveClientSecret(NONCE, '', BINDING); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-SECRET-002: Too long context_id → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashDeriveClientSecret(NONCE, 'a'.repeat(257), BINDING); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-SECRET-003: Invalid chars in context_id → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashDeriveClientSecret(NONCE, 'ctx test', BINDING); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-SECRET-004: Empty binding → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashDeriveClientSecret(NONCE, CTX, ''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-SECRET-005: Binding too long → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashDeriveClientSecret(NONCE, CTX, 'x'.repeat(8193)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashBuildProof errors
  it('SEC-ERR-PROOF-001: Empty client_secret → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashBuildProof('', TS, BINDING, VALID_BODY_HASH); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-PROOF-002: Empty binding in buildProof → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashBuildProof('secret', TS, '', VALID_BODY_HASH); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-PROOF-003: Invalid body_hash → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashBuildProof('secret', TS, BINDING, 'short'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-PROOF-004: Binding too long in buildProof → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashBuildProof('secret', TS, 'x'.repeat(8193), VALID_BODY_HASH); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashHashProof errors
  it('SEC-ERR-HPROOF-001: Empty proof → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashHashProof(''); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashHashScope errors
  it('SEC-ERR-HSCOPE-001: Empty field name → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashHashScope(['']); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-HSCOPE-002: Field name too long → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashHashScope(['x'.repeat(65)]); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  it('SEC-ERR-HSCOPE-003: Field with delimiter char → VALIDATION_ERROR', () => {
    expect.assertions(1);
    try { ashHashScope(['field\x1Fname']); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.VALIDATION_ERROR);
    }
  });

  // ashCanonicalizeJson errors
  it('SEC-ERR-CANON-001: Invalid JSON → CANONICALIZATION_ERROR', () => {
    expect.assertions(2);
    try { ashCanonicalizeJson('{invalid}'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
      expect((e as AshError).httpStatus).toBe(484);
    }
  });

  it('SEC-ERR-CANON-002: Oversized JSON → CANONICALIZATION_ERROR', () => {
    expect.assertions(1);
    try { ashCanonicalizeJson('x'.repeat(MAX_PAYLOAD_SIZE + 1)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
    }
  });

  it('SEC-ERR-CANON-003: Too deep JSON → CANONICALIZATION_ERROR', () => {
    expect.assertions(1);
    const nested = '{"a":'.repeat(65) + '1' + '}'.repeat(65);
    try { ashCanonicalizeJson(nested); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
    }
  });

  // ashCanonicalizeQuery errors
  it('SEC-ERR-QCANON-001: Oversized query → CANONICALIZATION_ERROR', () => {
    expect.assertions(1);
    try { ashCanonicalizeQuery('a=' + 'x'.repeat(MAX_PAYLOAD_SIZE + 1)); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
    }
  });

  it('SEC-ERR-QCANON-002: Invalid percent encoding → CANONICALIZATION_ERROR', () => {
    expect.assertions(1);
    try { ashCanonicalizeQuery('key=%GG'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
    }
  });

  it('SEC-ERR-QCANON-003: Truncated percent encoding → CANONICALIZATION_ERROR', () => {
    expect.assertions(1);
    try { ashCanonicalizeQuery('key=abc%2'); } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CANONICALIZATION_ERROR);
    }
  });

  // ashVerifyProofScoped errors
  it('SEC-ERR-VSCOPED-001: scope_hash without scope → SCOPE_MISMATCH', () => {
    expect.assertions(2);
    try {
      ashVerifyProofScoped(NONCE, CTX, BINDING, TS, '{}', [], 'a'.repeat(64), 'a'.repeat(64));
    } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.SCOPE_MISMATCH);
      expect((e as AshError).httpStatus).toBe(473);
    }
  });

  it('SEC-ERR-VSCOPED-002: scope without scope_hash → SCOPE_MISMATCH', () => {
    expect.assertions(1);
    try {
      ashVerifyProofScoped(NONCE, CTX, BINDING, TS, '{}', ['field'], '', 'a'.repeat(64));
    } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.SCOPE_MISMATCH);
    }
  });

  // ashVerifyProofUnified errors
  it('SEC-ERR-VUNIFIED-001: chain_hash without previous_proof → CHAIN_BROKEN', () => {
    expect.assertions(2);
    try {
      ashVerifyProofUnified(NONCE, CTX, BINDING, TS, '{}', 'a'.repeat(64), [], '', null, 'a'.repeat(64));
    } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.CHAIN_BROKEN);
      expect((e as AshError).httpStatus).toBe(474);
    }
  });

  // ashExtractScopedFieldsStrict errors
  it('SEC-ERR-EXTRACT-001: Missing field in strict mode → SCOPED_FIELD_MISSING', () => {
    expect.assertions(2);
    try {
      ashExtractScopedFieldsStrict({ a: 1 }, ['missing_field']);
    } catch (e) {
      expect((e as AshError).code).toBe(AshErrorCode.SCOPED_FIELD_MISSING);
      expect((e as AshError).httpStatus).toBe(475);
    }
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 4: BOUNDARY CONDITIONS
// ════════════════════════════════════════════════════════════════════

describe('SEC-BOUNDARY: Boundary value testing', () => {
  it('SEC-BOUND-001: Nonce exactly at minimum (32 chars)', () => {
    expect(() => ashValidateNonce('a'.repeat(32))).not.toThrow();
  });

  it('SEC-BOUND-002: Nonce exactly at maximum (512 chars)', () => {
    expect(() => ashValidateNonce('a'.repeat(512))).not.toThrow();
  });

  it('SEC-BOUND-003: Context_id exactly at maximum (256 chars)', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'a'.repeat(256), BINDING)).not.toThrow();
  });

  it('SEC-BOUND-004: Context_id one over maximum (257 chars) rejected', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'a'.repeat(257), BINDING)).toThrow(AshError);
  });

  it('SEC-BOUND-005: Timestamp exactly at maximum', () => {
    expect(ashValidateTimestampFormat(String(MAX_TIMESTAMP))).toBe(MAX_TIMESTAMP);
  });

  it('SEC-BOUND-006: Timestamp one over maximum rejected', () => {
    expect(() => ashValidateTimestampFormat(String(MAX_TIMESTAMP + 1))).toThrow(AshError);
  });

  it('SEC-BOUND-007: Nesting depth exactly at limit (64)', () => {
    const nested = '{"a":'.repeat(63) + '1' + '}'.repeat(63);
    expect(() => ashCanonicalizeJson(nested)).not.toThrow();
  });

  it('SEC-BOUND-008: Nesting depth one over limit (65)', () => {
    const nested = '{"a":'.repeat(65) + '1' + '}'.repeat(65);
    expect(() => ashCanonicalizeJson(nested)).toThrow(AshError);
  });

  it('SEC-BOUND-009: Array nesting depth at limit', () => {
    const nested = '['.repeat(63) + '1' + ']'.repeat(63);
    expect(() => ashCanonicalizeJson(nested)).not.toThrow();
  });

  it('SEC-BOUND-010: Scope field name at maximum length (64 chars)', () => {
    expect(() => ashHashScope(['a'.repeat(64)])).not.toThrow();
  });

  it('SEC-BOUND-011: Scope field name over maximum (65 chars) rejected', () => {
    expect(() => ashHashScope(['a'.repeat(65)])).toThrow(AshError);
  });

  it('SEC-BOUND-012: Timestamp "0" is valid', () => {
    expect(ashValidateTimestampFormat('0')).toBe(0);
  });

  it('SEC-BOUND-013: Timestamp "1" is valid', () => {
    expect(ashValidateTimestampFormat('1')).toBe(1);
  });

  it('SEC-BOUND-014: Single character nonce rejected', () => {
    expect(() => ashValidateNonce('a')).toThrow(AshError);
  });

  it('SEC-BOUND-015: Single character context_id valid', () => {
    expect(() => ashDeriveClientSecret(NONCE, 'x', BINDING)).not.toThrow();
  });

  it('SEC-BOUND-016: Empty JSON object canonicalized', () => {
    expect(ashCanonicalizeJson('{}')).toBe('{}');
  });

  it('SEC-BOUND-017: Empty JSON array canonicalized', () => {
    expect(ashCanonicalizeJson('[]')).toBe('[]');
  });

  it('SEC-BOUND-018: Empty query string', () => {
    expect(ashCanonicalizeQuery('')).toBe('');
  });

  it('SEC-BOUND-019: Query with only ? and #', () => {
    expect(ashCanonicalizeQuery('?#')).toBe('');
  });

  it('SEC-BOUND-020: Query with only ?', () => {
    expect(ashCanonicalizeQuery('?')).toBe('');
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 5: CROSS-FUNCTION INTEGRATION
// ════════════════════════════════════════════════════════════════════

describe('SEC-INTEGRATION: Cross-function integration scenarios', () => {
  it('SEC-INT-001: Full round-trip with complex JSON payload', () => {
    const complexPayload = JSON.stringify({
      transaction: {
        amount: 99999.99,
        currency: 'USD',
        recipient: { name: 'Alice', account: '1234567890' },
        metadata: { tags: ['urgent', 'verified'], timestamp: 1700000000 },
      },
      idempotencyKey: 'abc123',
    });

    const binding = ashNormalizeBinding('POST', '/api/v2/transfers', 'dry_run=false');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const canonical = ashCanonicalizeJson(complexPayload);
    const bodyHash = ashHashBody(canonical);
    const proof = ashBuildProof(secret, TS, binding, bodyHash);
    expect(ashVerifyProof(NONCE, CTX, binding, TS, bodyHash, proof)).toBe(true);
  });

  it('SEC-INT-002: Full round-trip with scoped + chained proof', () => {
    const binding = ashNormalizeBinding('POST', '/api/transfer', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const payload1 = '{"step":"init","amount":100}';
    const payload2 = '{"step":"confirm","amount":100}';

    // Step 1: scoped + no chain
    const r1 = ashBuildProofUnified(secret, '1700000000', binding, payload1, ['amount'], null);
    expect(r1.chainHash).toBe('');
    expect(r1.scopeHash.length).toBe(64);

    // Step 2: scoped + chain
    const r2 = ashBuildProofUnified(secret, '1700000100', binding, payload2, ['amount'], r1.proof);
    expect(r2.chainHash.length).toBe(64);

    // Verify step 2
    const valid = ashVerifyProofUnified(
      NONCE, CTX, binding, '1700000100', payload2, r2.proof,
      ['amount'], r2.scopeHash, r1.proof, r2.chainHash,
    );
    expect(valid).toBe(true);
  });

  it('SEC-INT-003: Binding from URL with query parameters', () => {
    const fromUrl = ashNormalizeBindingFromUrl('GET', '/api/users?sort=name&page=1&filter=active#section');
    const manual = ashNormalizeBinding('GET', '/api/users', 'sort=name&page=1&filter=active');
    expect(fromUrl).toBe(manual);
  });

  it('SEC-INT-004: Verify proof with freshness — current timestamp', () => {
    const now = String(Math.floor(Date.now() / 1000));
    const binding = ashNormalizeBinding('POST', '/api', '');
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);
    const bodyHash = ashHashBody(ashCanonicalizeJson('{"test":true}'));
    const proof = ashBuildProof(secret, now, binding, bodyHash);
    const valid = ashVerifyProofWithFreshness(NONCE, CTX, binding, now, bodyHash, proof, 300, 30);
    expect(valid).toBe(true);
  });

  it('SEC-INT-005: Five-step chain maintains integrity', () => {
    const binding = 'POST|/api|';
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);

    let prevProof: string | null = null;
    const proofs: string[] = [];

    for (let i = 0; i < 5; i++) {
      const ts = String(1700000000 + i * 100);
      const p = JSON.stringify({ counter: i });
      const r = ashBuildProofUnified(secret, ts, binding, p, [], prevProof);
      proofs.push(r.proof);

      if (i > 0) {
        const valid = ashVerifyProofUnified(
          NONCE, CTX, binding, ts, p, r.proof,
          [], '', prevProof, r.chainHash,
        );
        expect(valid).toBe(true);
      }
      prevProof = r.proof;
    }

    // All proofs should be unique
    expect(new Set(proofs).size).toBe(5);
  });

  it('SEC-INT-006: Mixed scope fields with nested JSON', () => {
    const payload = {
      user: { name: 'Alice', email: 'alice@example.com', age: 30 },
      action: 'transfer',
      amount: 100,
    };
    const payloadStr = JSON.stringify(payload);
    const scope = ['user.name', 'amount'];
    const binding = 'POST|/api|';
    const secret = ashDeriveClientSecret(NONCE, CTX, binding);

    const r = ashBuildProofScoped(secret, TS, binding, payloadStr, scope);
    const valid = ashVerifyProofScoped(
      NONCE, CTX, binding, TS, payloadStr,
      scope, r.scopeHash, r.proof,
    );
    expect(valid).toBe(true);

    // Changing unscoped field should not affect proof
    const modified = JSON.stringify({
      ...payload,
      user: { ...payload.user, email: 'modified@example.com' },
    });
    const validModified = ashVerifyProofScoped(
      NONCE, CTX, binding, TS, modified,
      scope, r.scopeHash, r.proof,
    );
    expect(validModified).toBe(true); // email not in scope
  });

  it('SEC-INT-007: Extract then verify — strict vs lenient', () => {
    const payload = { a: 1, b: 2, c: 3 };

    // Lenient: missing field returns partial result
    const lenient = ashExtractScopedFields(payload, ['a', 'missing']);
    expect(lenient).toEqual({ a: 1 });

    // Strict: missing field throws
    expect(() => ashExtractScopedFieldsStrict(payload, ['a', 'missing'])).toThrow(AshError);
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 6: CANONICALIZATION CORNER CASES
// ════════════════════════════════════════════════════════════════════

describe('SEC-CANON: Advanced JSON canonicalization cases', () => {
  it('SEC-JCANON-001: -0 becomes 0', () => {
    expect(ashCanonicalizeJson('-0')).toBe('0');
    expect(ashCanonicalizeJson('-0.0')).toBe('0');
  });

  it('SEC-JCANON-002: Scientific notation normalized', () => {
    expect(ashCanonicalizeJson('1e2')).toBe('100');
    expect(ashCanonicalizeJson('1.5e1')).toBe('15');
    expect(ashCanonicalizeJson('1E2')).toBe('100');
  });

  it('SEC-JCANON-003: Very small float', () => {
    expect(ashCanonicalizeJson('0.000001')).toBe('0.000001');
  });

  it('SEC-JCANON-004: Integer vs float (1.0 → 1)', () => {
    expect(ashCanonicalizeJson('1.0')).toBe('1');
    expect(ashCanonicalizeJson('100.0')).toBe('100');
  });

  it('SEC-JCANON-005: Deeply nested but within limit', () => {
    let input = '1';
    for (let i = 0; i < 60; i++) {
      input = `{"a":${input}}`;
    }
    expect(() => ashCanonicalizeJson(input)).not.toThrow();
  });

  it('SEC-JCANON-006: Large number of keys in object', () => {
    const obj: Record<string, number> = {};
    for (let i = 0; i < 100; i++) {
      obj[`key_${String(i).padStart(3, '0')}`] = i;
    }
    const canonical = ashCanonicalizeJson(JSON.stringify(obj));
    const parsed = JSON.parse(canonical);
    const keys = Object.keys(parsed);
    // Verify sorted order
    for (let i = 1; i < keys.length; i++) {
      expect(keys[i] > keys[i - 1]).toBe(true);
    }
  });

  it('SEC-JCANON-007: Duplicate keys — last wins', () => {
    expect(ashCanonicalizeJson('{"a":1,"a":2}')).toBe('{"a":2}');
    expect(ashCanonicalizeJson('{"a":1,"a":2,"a":3}')).toBe('{"a":3}');
  });

  it('SEC-JCANON-008: Nested array with mixed types', () => {
    const result = ashCanonicalizeJson('[1,"two",true,null,[],{}]');
    expect(result).toBe('[1,"two",true,null,[],{}]');
  });

  it('SEC-JCANON-009: Object with boolean/null values', () => {
    const result = ashCanonicalizeJson('{"t":true,"f":false,"n":null}');
    expect(result).toBe('{"f":false,"n":null,"t":true}');
  });

  it('SEC-JCANON-010: String with all JSON escape sequences', () => {
    const input = '{"s":"\\"\\\\\\/\\b\\f\\n\\r\\t"}';
    const result = ashCanonicalizeJson(input);
    expect(() => JSON.parse(result)).not.toThrow();
  });

  it('SEC-JCANON-011: Empty string key', () => {
    const result = ashCanonicalizeJson('{"":1,"a":2}');
    const keys = Object.keys(JSON.parse(result));
    expect(keys[0]).toBe('');
    expect(keys[1]).toBe('a');
  });

  it('SEC-JCANON-012: NaN in JSON value rejected', () => {
    expect(() => ashCanonicalizeJsonValue(NaN)).toThrow(AshError);
  });

  it('SEC-JCANON-013: Infinity in JSON value rejected', () => {
    expect(() => ashCanonicalizeJsonValue(Infinity)).toThrow(AshError);
    expect(() => ashCanonicalizeJsonValue(-Infinity)).toThrow(AshError);
  });

  it('SEC-JCANON-014: undefined treated as null', () => {
    expect(ashCanonicalizeJsonValue(undefined)).toBe('null');
  });
});

describe('SEC-CANON: Advanced query canonicalization cases', () => {
  it('SEC-QCANON-001: Multiple duplicate keys sorted by value', () => {
    const result = ashCanonicalizeQuery('a=3&a=1&a=2');
    expect(result).toBe('a=1&a=2&a=3');
  });

  it('SEC-QCANON-002: Percent-encoded unreserved chars decoded', () => {
    // %41 = A (unreserved → decoded)
    const result = ashCanonicalizeQuery('key=%41');
    expect(result).toBe('key=A');
  });

  it('SEC-QCANON-003: Percent encoding uses uppercase hex', () => {
    const result = ashCanonicalizeQuery('key=%20');
    expect(result).toContain('%20');
    // No lowercase hex letters (a-f) in percent encoding
    expect(result).not.toMatch(/%.[a-f]|%[a-f]./);
  });

  it('SEC-QCANON-004: Empty key=value pairs', () => {
    const result = ashCanonicalizeQuery('=');
    expect(result).toBe('=');
  });

  it('SEC-QCANON-005: Multiple = signs in value', () => {
    const result = ashCanonicalizeQuery('key=a=b=c');
    expect(result).toContain('key=a%3Db%3Dc');
  });

  it('SEC-QCANON-006: Empty pairs between & are skipped', () => {
    const result = ashCanonicalizeQuery('a=1&&&&b=2');
    expect(result).toBe('a=1&b=2');
  });

  it('SEC-QCANON-007: Flag keys (no value) get empty value', () => {
    const result = ashCanonicalizeQuery('flag&key=val');
    expect(result).toBe('flag=&key=val');
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 7: SCOPE EXTRACTION EDGE CASES
// ════════════════════════════════════════════════════════════════════

describe('SEC-SCOPE: Advanced scope extraction scenarios', () => {
  it('SEC-SCOPE-001: Deeply nested extraction', () => {
    const payload = { a: { b: { c: { d: { e: 42 } } } } };
    const result = ashExtractScopedFields(payload, ['a.b.c.d.e']);
    expect(result).toEqual({ a: { b: { c: { d: { e: 42 } } } } });
  });

  it('SEC-SCOPE-002: Array index extraction', () => {
    const payload = { items: ['zero', 'one', 'two', 'three'] };
    const result = ashExtractScopedFields(payload, ['items[2]']);
    expect(result).toEqual({ items: [undefined, undefined, 'two'] });
  });

  it('SEC-SCOPE-003: Nested object within array', () => {
    const payload = { users: [{ name: 'Alice' }, { name: 'Bob' }] };
    const result = ashExtractScopedFields(payload, ['users[0].name']);
    expect(result).toEqual({ users: [{ name: 'Alice' }] });
  });

  it('SEC-SCOPE-004: Multiple fields from different levels', () => {
    const payload = {
      id: 1,
      user: { name: 'Alice', settings: { theme: 'dark' } },
      items: [10, 20, 30],
    };
    const result = ashExtractScopedFields(payload, ['id', 'user.name', 'items[1]']);
    expect(result).toEqual({
      id: 1,
      user: { name: 'Alice' },
      items: [undefined, 20],
    });
  });

  it('SEC-SCOPE-005: Missing nested field (lenient) returns empty', () => {
    const payload = { a: 1 };
    const result = ashExtractScopedFields(payload, ['x.y.z']);
    expect(result).toEqual({});
  });

  it('SEC-SCOPE-006: Missing array index (lenient) returns empty', () => {
    const payload = { items: [1] };
    const result = ashExtractScopedFields(payload, ['items[99]']);
    expect(result).toEqual({});
  });

  it('SEC-SCOPE-007: Null value extracted correctly', () => {
    const payload = { nullField: null };
    const result = ashExtractScopedFields(payload, ['nullField']);
    expect(result).toEqual({ nullField: null });
  });

  it('SEC-SCOPE-008: Boolean false extracted correctly', () => {
    const payload = { active: false };
    const result = ashExtractScopedFields(payload, ['active']);
    expect(result).toEqual({ active: false });
  });

  it('SEC-SCOPE-009: Zero value extracted correctly', () => {
    const payload = { count: 0 };
    const result = ashExtractScopedFields(payload, ['count']);
    expect(result).toEqual({ count: 0 });
  });

  it('SEC-SCOPE-010: Empty string value extracted correctly', () => {
    const payload = { name: '' };
    const result = ashExtractScopedFields(payload, ['name']);
    expect(result).toEqual({ name: '' });
  });

  it('SEC-SCOPE-011: Object value extracted entirely', () => {
    const payload = { config: { a: 1, b: 2 } };
    const result = ashExtractScopedFields(payload, ['config']);
    expect(result).toEqual({ config: { a: 1, b: 2 } });
  });

  it('SEC-SCOPE-012: Array value extracted entirely', () => {
    const payload = { tags: ['a', 'b', 'c'] };
    const result = ashExtractScopedFields(payload, ['tags']);
    expect(result).toEqual({ tags: ['a', 'b', 'c'] });
  });

  it('SEC-SCOPE-013: Empty scope returns full payload', () => {
    const payload = { a: 1, b: 2 };
    expect(ashExtractScopedFields(payload, [])).toEqual(payload);
  });

  it('SEC-SCOPE-014: Strict mode throws for first missing field', () => {
    const payload = { a: 1 };
    expect(() => ashExtractScopedFieldsStrict(payload, ['b'])).toThrow(AshError);
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 8: ERROR HTTP STATUS CODE VERIFICATION
// ════════════════════════════════════════════════════════════════════

describe('SEC-HTTP: Every error code maps to unique HTTP status', () => {
  it('SEC-HTTP-001: All 15 error codes have unique HTTP status codes', () => {
    const statusMap: Record<string, number> = {
      [AshErrorCode.CTX_NOT_FOUND]: 450,
      [AshErrorCode.CTX_EXPIRED]: 451,
      [AshErrorCode.CTX_ALREADY_USED]: 452,
      [AshErrorCode.PROOF_INVALID]: 460,
      [AshErrorCode.BINDING_MISMATCH]: 461,
      [AshErrorCode.SCOPE_MISMATCH]: 473,
      [AshErrorCode.CHAIN_BROKEN]: 474,
      [AshErrorCode.SCOPED_FIELD_MISSING]: 475,
      [AshErrorCode.TIMESTAMP_INVALID]: 482,
      [AshErrorCode.PROOF_MISSING]: 483,
      [AshErrorCode.CANONICALIZATION_ERROR]: 484,
      [AshErrorCode.VALIDATION_ERROR]: 485,
      [AshErrorCode.MODE_VIOLATION]: 486,
      [AshErrorCode.UNSUPPORTED_CONTENT_TYPE]: 415,
      [AshErrorCode.INTERNAL_ERROR]: 500,
    };

    // Verify uniqueness
    const statuses = Object.values(statusMap);
    expect(new Set(statuses).size).toBe(statuses.length);

    // Verify each code maps correctly
    for (const [code, status] of Object.entries(statusMap)) {
      const err = new AshError(code as AshErrorCode, 'test');
      expect(err.httpStatus).toBe(status);
    }
  });

  it('SEC-HTTP-002: Retryable codes are only TIMESTAMP_INVALID, INTERNAL_ERROR, CTX_ALREADY_USED', () => {
    const retryable = [
      AshErrorCode.TIMESTAMP_INVALID,
      AshErrorCode.INTERNAL_ERROR,
      AshErrorCode.CTX_ALREADY_USED,
    ];
    const nonRetryable = Object.values(AshErrorCode).filter(c => !retryable.includes(c));

    for (const code of retryable) {
      expect(new AshError(code, 'test').retryable).toBe(true);
    }
    for (const code of nonRetryable) {
      expect(new AshError(code, 'test').retryable).toBe(false);
    }
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 9: BINDING NORMALIZATION ADVANCED
// ════════════════════════════════════════════════════════════════════

describe('SEC-BIND: Advanced binding normalization', () => {
  it('SEC-ABIND-001: Multiple consecutive slashes collapsed', () => {
    expect(ashNormalizeBinding('GET', '///api///users///', '')).toBe('GET|/api/users|');
  });

  it('SEC-ABIND-002: . segments removed', () => {
    expect(ashNormalizeBinding('GET', '/./api/./users/.', '')).toBe('GET|/api/users|');
  });

  it('SEC-ABIND-003: .. segments resolved', () => {
    expect(ashNormalizeBinding('GET', '/api/v1/../v2/users', '')).toBe('GET|/api/v2/users|');
  });

  it('SEC-ABIND-004: .. beyond root resolves to root', () => {
    expect(ashNormalizeBinding('GET', '/../../../api', '')).toBe('GET|/api|');
  });

  it('SEC-ABIND-005: Complex path traversal', () => {
    expect(ashNormalizeBinding('GET', '/a/b/c/../../d/../e', '')).toBe('GET|/a/e|');
  });

  it('SEC-ABIND-006: Root path preserved', () => {
    expect(ashNormalizeBinding('GET', '/', '')).toBe('GET|/|');
  });

  it('SEC-ABIND-007: Root with trailing slash', () => {
    expect(ashNormalizeBinding('GET', '//', '')).toBe('GET|/|');
  });

  it('SEC-ABIND-008: All HTTP methods accepted', () => {
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];
    for (const m of methods) {
      expect(() => ashNormalizeBinding(m, '/', '')).not.toThrow();
    }
  });

  it('SEC-ABIND-009: Custom method accepted', () => {
    expect(() => ashNormalizeBinding('PURGE', '/api', '')).not.toThrow();
  });

  it('SEC-ABIND-010: Method whitespace trimmed', () => {
    expect(ashNormalizeBinding('  GET  ', '/api', '')).toBe('GET|/api|');
  });

  it('SEC-ABIND-011: Path whitespace trimmed', () => {
    expect(ashNormalizeBinding('GET', '  /api  ', '')).toBe('GET|/api|');
  });

  it('SEC-ABIND-012: Query whitespace trimmed', () => {
    expect(ashNormalizeBinding('GET', '/api', '  a=1  ')).toBe('GET|/api|a=1');
  });

  it('SEC-ABIND-013: Path with encoded space', () => {
    const result = ashNormalizeBinding('GET', '/api/hello%20world', '');
    expect(result).toContain('%20');
  });

  it('SEC-ABIND-014: Control chars in path (via encoding) rejected', () => {
    expect(() => ashNormalizeBinding('GET', '/api/%01', '')).toThrow(AshError);
    expect(() => ashNormalizeBinding('GET', '/api/%7F', '')).toThrow(AshError);
  });

  it('SEC-ABIND-015: DEL character (0x7F) in method rejected', () => {
    expect(() => ashNormalizeBinding('GET\x7F', '/api', '')).toThrow(AshError);
  });
});
