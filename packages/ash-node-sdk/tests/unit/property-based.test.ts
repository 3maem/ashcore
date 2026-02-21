/**
 * ASH Node SDK v1.0.0 — Property-Based / Fuzz Tests
 *
 * Uses fast-check to generate randomized inputs and verify protocol invariants.
 * Covers: canonicalization, hashing, proof generation/verification, binding,
 * scope, timing-safe comparison, and validation functions.
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
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
  ashTimingSafeEqual,
  ashValidateNonce,
  ashValidateTimestampFormat,
  ashValidateHash,
  AshError,
  MAX_TIMESTAMP,
} from '../../src/index.js';

// ── Arbitraries ──────────────────────────────────────────────────────

const hexChar = fc.mapToConstant(
  { num: 10, build: v => String.fromCharCode(0x30 + v) }, // 0-9
  { num: 6, build: v => String.fromCharCode(0x61 + v) },  // a-f
);

const validNonce = fc.string({ unit: hexChar, minLength: 32, maxLength: 128 });
const validContextId = fc.string({
  unit: fc.mapToConstant(
    { num: 26, build: v => String.fromCharCode(0x61 + v) }, // a-z
    { num: 26, build: v => String.fromCharCode(0x41 + v) }, // A-Z
    { num: 10, build: v => String.fromCharCode(0x30 + v) }, // 0-9
    { num: 3, build: v => ['_', '-', '.'][v] },
  ),
  minLength: 1, maxLength: 64,
});

const validTimestamp = fc.integer({ min: 0, max: MAX_TIMESTAMP }).map(String);

const validPath = fc.array(
  fc.string({ unit: fc.mapToConstant(
    { num: 26, build: v => String.fromCharCode(0x61 + v) },
    { num: 10, build: v => String.fromCharCode(0x30 + v) },
    { num: 2, build: v => ['-', '_'][v] },
  ), minLength: 1, maxLength: 16 }),
  { minLength: 0, maxLength: 5 },
).map(segments => '/' + segments.join('/'));

const httpMethod = fc.constantFrom('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS');

const simpleQueryPair = fc.tuple(
  fc.string({ unit: fc.mapToConstant(
    { num: 26, build: v => String.fromCharCode(0x61 + v) },
    { num: 10, build: v => String.fromCharCode(0x30 + v) },
  ), minLength: 1, maxLength: 10 }),
  fc.string({ unit: fc.mapToConstant(
    { num: 26, build: v => String.fromCharCode(0x61 + v) },
    { num: 10, build: v => String.fromCharCode(0x30 + v) },
  ), minLength: 0, maxLength: 10 }),
).map(([k, v]) => `${k}=${v}`);

const simpleQuery = fc.array(simpleQueryPair, { minLength: 0, maxLength: 5 }).map(pairs => pairs.join('&'));

const validBodyHash = fc.string({ unit: hexChar, minLength: 64, maxLength: 64 });

const validScopeField = fc.string({
  unit: fc.mapToConstant(
    { num: 26, build: v => String.fromCharCode(0x61 + v) },
    { num: 10, build: v => String.fromCharCode(0x30 + v) },
    { num: 1, build: () => '_' },
  ),
  minLength: 1, maxLength: 20,
});

const validScope = fc.array(validScopeField, { minLength: 0, maxLength: 10 });

const simpleJsonObject = fc.dictionary(
  fc.string({ unit: fc.mapToConstant(
    { num: 26, build: v => String.fromCharCode(0x61 + v) },
  ), minLength: 1, maxLength: 8 }),
  fc.oneof(
    fc.integer({ min: -1000, max: 1000 }),
    fc.string({ minLength: 0, maxLength: 20 }),
    fc.boolean(),
    fc.constant(null),
  ),
);

// ── Hash Output Invariants ──────────────────────────────────────────

describe('PROP: Hash output invariants', () => {
  it('PROP-HASH-001: ashHashBody always returns 64 lowercase hex chars', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 1000 }), (input) => {
        const hash = ashHashBody(input);
        expect(hash.length).toBe(64);
        expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-HASH-002: ashHashBody is deterministic', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 500 }), (input) => {
        expect(ashHashBody(input)).toBe(ashHashBody(input));
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-HASH-003: ashHashProof always returns 64 lowercase hex chars', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 1, maxLength: 200 }), (input) => {
        const hash = ashHashProof(input);
        expect(hash.length).toBe(64);
        expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-HASH-004: Different inputs produce different hashes (collision resistance)', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 200 }),
        fc.string({ minLength: 1, maxLength: 200 }),
        (a, b) => {
          fc.pre(a !== b);
          // SHA-256 collision probability is astronomically low
          expect(ashHashBody(a)).not.toBe(ashHashBody(b));
        },
      ),
      { numRuns: 300 },
    );
  });

  it('PROP-HASH-005: ashHashScope is order-independent', () => {
    fc.assert(
      fc.property(validScope, (scope) => {
        fc.pre(scope.length >= 2);
        const h1 = ashHashScope(scope);
        const reversed = [...scope].reverse();
        const h2 = ashHashScope(reversed);
        expect(h1).toBe(h2);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-HASH-006: ashHashScope is duplicate-insensitive', () => {
    fc.assert(
      fc.property(validScope, (scope) => {
        fc.pre(scope.length >= 1);
        const h1 = ashHashScope(scope);
        const doubled = [...scope, ...scope];
        const h2 = ashHashScope(doubled);
        expect(h1).toBe(h2);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-HASH-007: ashHashScope non-empty scope returns 64 hex chars', () => {
    fc.assert(
      fc.property(validScope, (scope) => {
        fc.pre(scope.length >= 1);
        const h = ashHashScope(scope);
        expect(h.length).toBe(64);
        expect(/^[0-9a-f]{64}$/.test(h)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-HASH-008: ashHashScope empty scope returns empty string', () => {
    expect(ashHashScope([])).toBe('');
  });
});

// ── Canonicalization Invariants ──────────────────────────────────────

describe('PROP: JSON canonicalization invariants', () => {
  it('PROP-CANON-001: Canonicalization is idempotent', () => {
    fc.assert(
      fc.property(simpleJsonObject, (obj) => {
        const input = JSON.stringify(obj);
        const first = ashCanonicalizeJson(input);
        const second = ashCanonicalizeJson(first);
        expect(first).toBe(second);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-CANON-002: Canonicalized output is valid JSON', () => {
    fc.assert(
      fc.property(simpleJsonObject, (obj) => {
        const input = JSON.stringify(obj);
        const canonical = ashCanonicalizeJson(input);
        expect(() => JSON.parse(canonical)).not.toThrow();
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-CANON-003: Canonicalized output has no unnecessary whitespace', () => {
    fc.assert(
      fc.property(simpleJsonObject, (obj) => {
        const pretty = JSON.stringify(obj, null, 2);
        const canonical = ashCanonicalizeJson(pretty);
        // Should not have newlines or multiple spaces between tokens
        expect(canonical).not.toMatch(/\n/);
        expect(canonical).not.toMatch(/\t/);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-CANON-004: ashCanonicalizeJson and ashCanonicalizeJsonValue agree', () => {
    fc.assert(
      fc.property(simpleJsonObject, (obj) => {
        const fromString = ashCanonicalizeJson(JSON.stringify(obj));
        const fromValue = ashCanonicalizeJsonValue(obj);
        expect(fromString).toBe(fromValue);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-CANON-005: Key order in output is deterministic (UTF-16 sorted)', () => {
    fc.assert(
      fc.property(simpleJsonObject, (obj) => {
        const canonical = ashCanonicalizeJson(JSON.stringify(obj));
        const parsed = JSON.parse(canonical);
        const keys = Object.keys(parsed);
        const sorted = [...keys].sort((a, b) => {
          for (let i = 0; i < Math.min(a.length, b.length); i++) {
            const diff = a.charCodeAt(i) - b.charCodeAt(i);
            if (diff !== 0) return diff;
          }
          return a.length - b.length;
        });
        expect(keys).toEqual(sorted);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-CANON-006: Different key orders produce same canonical form', () => {
    fc.assert(
      fc.property(
        fc.tuple(
          fc.string({ minLength: 1, maxLength: 5 }),
          fc.integer(),
          fc.string({ minLength: 1, maxLength: 5 }),
          fc.integer(),
        ),
        ([k1, v1, k2, v2]) => {
          fc.pre(k1 !== k2);
          const a = ashCanonicalizeJson(JSON.stringify({ [k1]: v1, [k2]: v2 }));
          const b = ashCanonicalizeJson(JSON.stringify({ [k2]: v2, [k1]: v1 }));
          expect(a).toBe(b);
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe('PROP: Query canonicalization invariants', () => {
  it('PROP-QCANON-001: Query canonicalization is idempotent', () => {
    fc.assert(
      fc.property(simpleQuery, (q) => {
        fc.pre(q.length > 0);
        const first = ashCanonicalizeQuery(q);
        const second = ashCanonicalizeQuery(first);
        expect(first).toBe(second);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-QCANON-002: Query and urlencoded agree on same input', () => {
    fc.assert(
      fc.property(simpleQuery, (q) => {
        expect(ashCanonicalizeQuery(q)).toBe(ashCanonicalizeUrlencoded(q));
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-QCANON-003: Leading ? is stripped', () => {
    fc.assert(
      fc.property(simpleQuery, (q) => {
        fc.pre(q.length > 0);
        const withQ = ashCanonicalizeQuery('?' + q);
        const withoutQ = ashCanonicalizeQuery(q);
        expect(withQ).toBe(withoutQ);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-QCANON-004: Fragment is always stripped', () => {
    fc.assert(
      fc.property(
        simpleQuery,
        fc.string({ minLength: 1, maxLength: 20 }),
        (q, frag) => {
          const withFrag = ashCanonicalizeQuery(q + '#' + frag);
          const withoutFrag = ashCanonicalizeQuery(q);
          expect(withFrag).toBe(withoutFrag);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('PROP-QCANON-005: Output parameter order is deterministic', () => {
    fc.assert(
      fc.property(simpleQuery, (q) => {
        fc.pre(q.length > 0);
        const canonical = ashCanonicalizeQuery(q);
        if (canonical.length === 0) return;
        const pairs = canonical.split('&');
        const keys = pairs.map(p => p.split('=')[0]);
        for (let i = 1; i < keys.length; i++) {
          expect(keys[i] >= keys[i - 1]).toBe(true);
        }
      }),
      { numRuns: 200 },
    );
  });
});

// ── Binding Normalization Invariants ─────────────────────────────────

describe('PROP: Binding normalization invariants', () => {
  it('PROP-BIND-001: Binding always has format METHOD|PATH|QUERY', () => {
    fc.assert(
      fc.property(httpMethod, validPath, simpleQuery, (method, path, query) => {
        const binding = ashNormalizeBinding(method, path, query);
        const parts = binding.split('|');
        expect(parts.length).toBe(3);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-BIND-002: Method is always uppercase in output', () => {
    fc.assert(
      fc.property(httpMethod, validPath, simpleQuery, (method, path, query) => {
        const binding = ashNormalizeBinding(method.toLowerCase(), path, query);
        const outputMethod = binding.split('|')[0];
        expect(outputMethod).toBe(outputMethod.toUpperCase());
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-BIND-003: Binding normalization is idempotent', () => {
    fc.assert(
      fc.property(httpMethod, validPath, simpleQuery, (method, path, query) => {
        const binding = ashNormalizeBinding(method, path, query);
        const [m, p, q] = binding.split('|');
        const binding2 = ashNormalizeBinding(m, p, q);
        expect(binding).toBe(binding2);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-BIND-004: Path always starts with / in output', () => {
    fc.assert(
      fc.property(httpMethod, validPath, (method, path) => {
        const binding = ashNormalizeBinding(method, path, '');
        const outputPath = binding.split('|')[1];
        expect(outputPath[0]).toBe('/');
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-BIND-005: Method case does not affect output', () => {
    fc.assert(
      fc.property(httpMethod, validPath, simpleQuery, (method, path, query) => {
        const b1 = ashNormalizeBinding(method.toUpperCase(), path, query);
        const b2 = ashNormalizeBinding(method.toLowerCase(), path, query);
        expect(b1).toBe(b2);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-BIND-006: ashNormalizeBindingFromUrl agrees with split approach', () => {
    fc.assert(
      fc.property(httpMethod, validPath, simpleQuery, (method, path, query) => {
        fc.pre(query.length > 0);
        const fullPath = path + '?' + query;
        const fromUrl = ashNormalizeBindingFromUrl(method, fullPath);
        const fromSplit = ashNormalizeBinding(method, path, query);
        expect(fromUrl).toBe(fromSplit);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Proof Generation/Verification Invariants ────────────────────────

describe('PROP: Proof generation/verification invariants', () => {
  it('PROP-PROOF-001: build → verify roundtrip always succeeds', () => {
    fc.assert(
      fc.property(validNonce, validContextId, httpMethod, validPath, validTimestamp, simpleJsonObject, (nonce, ctx, method, path, ts, payload) => {
        const binding = ashNormalizeBinding(method, path, '');
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const bodyHash = ashHashBody(ashCanonicalizeJson(JSON.stringify(payload)));
        const proof = ashBuildProof(secret, ts, binding, bodyHash);
        expect(ashVerifyProof(nonce, ctx, binding, ts, bodyHash, proof)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-002: Proof is always 64 lowercase hex chars', () => {
    fc.assert(
      fc.property(validNonce, validContextId, httpMethod, validPath, validTimestamp, (nonce, ctx, method, path, ts) => {
        const binding = ashNormalizeBinding(method, path, '');
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const bodyHash = ashHashBody('{}');
        const proof = ashBuildProof(secret, ts, binding, bodyHash);
        expect(proof.length).toBe(64);
        expect(/^[0-9a-f]{64}$/.test(proof)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-003: Client secret is always 64 lowercase hex chars', () => {
    fc.assert(
      fc.property(validNonce, validContextId, httpMethod, validPath, (nonce, ctx, method, path) => {
        const binding = ashNormalizeBinding(method, path, '');
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        expect(secret.length).toBe(64);
        expect(/^[0-9a-f]{64}$/.test(secret)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-004: Changing any input changes the proof', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, (nonce, ctx, ts) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const h1 = ashHashBody('{"a":1}');
        const h2 = ashHashBody('{"a":2}');
        const p1 = ashBuildProof(secret, ts, binding, h1);
        const p2 = ashBuildProof(secret, ts, binding, h2);
        expect(p1).not.toBe(p2);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-005: Nonce case normalization preserves verify', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, (nonce, ctx, ts) => {
        const binding = 'POST|/api|';
        const upper = nonce.toUpperCase();
        const lower = nonce.toLowerCase();
        const secretU = ashDeriveClientSecret(upper, ctx, binding);
        const secretL = ashDeriveClientSecret(lower, ctx, binding);
        expect(secretU).toBe(secretL);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-006: Wrong nonce always fails verify', () => {
    fc.assert(
      fc.property(
        validNonce,
        validNonce,
        validContextId,
        validTimestamp,
        (nonce1, nonce2, ctx, ts) => {
          fc.pre(nonce1.toLowerCase() !== nonce2.toLowerCase());
          const binding = 'POST|/api|';
          const secret = ashDeriveClientSecret(nonce1, ctx, binding);
          const bodyHash = ashHashBody('{}');
          const proof = ashBuildProof(secret, ts, binding, bodyHash);
          expect(ashVerifyProof(nonce2, ctx, binding, ts, bodyHash, proof)).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-007: Wrong context always fails verify', () => {
    fc.assert(
      fc.property(
        validNonce,
        validContextId,
        validContextId,
        validTimestamp,
        (nonce, ctx1, ctx2, ts) => {
          fc.pre(ctx1 !== ctx2);
          const binding = 'POST|/api|';
          const secret = ashDeriveClientSecret(nonce, ctx1, binding);
          const bodyHash = ashHashBody('{}');
          const proof = ashBuildProof(secret, ts, binding, bodyHash);
          expect(ashVerifyProof(nonce, ctx2, binding, ts, bodyHash, proof)).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('PROP-PROOF-008: Wrong timestamp always fails verify', () => {
    fc.assert(
      fc.property(
        validNonce,
        validContextId,
        fc.integer({ min: 0, max: MAX_TIMESTAMP - 1 }),
        (nonce, ctx, tsNum) => {
          const ts1 = String(tsNum);
          const ts2 = String(tsNum + 1);
          const binding = 'POST|/api|';
          const secret = ashDeriveClientSecret(nonce, ctx, binding);
          const bodyHash = ashHashBody('{}');
          const proof = ashBuildProof(secret, ts1, binding, bodyHash);
          expect(ashVerifyProof(nonce, ctx, binding, ts2, bodyHash, proof)).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ── Scoped Proof Invariants ─────────────────────────────────────────

describe('PROP: Scoped proof invariants', () => {
  it('PROP-SCOPED-001: Scoped build → verify roundtrip', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, (nonce, ctx, ts) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const payload = '{"amount":100,"recipient":"alice"}';
        const scope = ['amount'];
        const r = ashBuildProofScoped(secret, ts, binding, payload, scope);
        const valid = ashVerifyProofScoped(nonce, ctx, binding, ts, payload, scope, r.scopeHash, r.proof);
        expect(valid).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-SCOPED-002: Scope order independence in proofs', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, validScope, (nonce, ctx, ts, scope) => {
        fc.pre(scope.length >= 2);
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const payload = JSON.stringify(Object.fromEntries(scope.map(f => [f, 'val'])));
        const r1 = ashBuildProofScoped(secret, ts, binding, payload, scope);
        const reversed = [...scope].reverse();
        const r2 = ashBuildProofScoped(secret, ts, binding, payload, reversed);
        expect(r1.proof).toBe(r2.proof);
        expect(r1.scopeHash).toBe(r2.scopeHash);
      }),
      { numRuns: 50 },
    );
  });
});

// ── Unified Proof Invariants ────────────────────────────────────────

describe('PROP: Unified proof invariants', () => {
  it('PROP-UNIFIED-001: Unified build → verify roundtrip (no chain)', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, (nonce, ctx, ts) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const payload = '{"data":"test"}';
        const r = ashBuildProofUnified(secret, ts, binding, payload, [], null);
        const valid = ashVerifyProofUnified(nonce, ctx, binding, ts, payload, r.proof, [], '', null, '');
        expect(valid).toBe(true);
        expect(r.chainHash).toBe('');
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-UNIFIED-002: Unified build → verify with chain', () => {
    fc.assert(
      fc.property(validNonce, validContextId, (nonce, ctx) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const payload = '{"data":"test"}';
        const r1 = ashBuildProofUnified(secret, '1700000000', binding, payload, [], null);
        const r2 = ashBuildProofUnified(secret, '1700000100', binding, payload, [], r1.proof);
        const valid = ashVerifyProofUnified(
          nonce, ctx, binding, '1700000100', payload, r2.proof,
          [], '', r1.proof, r2.chainHash,
        );
        expect(valid).toBe(true);
        expect(r2.chainHash).toBe(ashHashProof(r1.proof));
      }),
      { numRuns: 50 },
    );
  });

  it('PROP-UNIFIED-003: Chain hash is always SHA256 of previous proof', () => {
    fc.assert(
      fc.property(validNonce, validContextId, (nonce, ctx) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const r1 = ashBuildProofUnified(secret, '1700000000', binding, '{}', [], null);
        const r2 = ashBuildProofUnified(secret, '1700000100', binding, '{}', [], r1.proof);
        expect(r2.chainHash).toBe(ashHashProof(r1.proof));
      }),
      { numRuns: 50 },
    );
  });
});

// ── Timing-Safe Comparison Invariants ───────────────────────────────

describe('PROP: Timing-safe comparison invariants', () => {
  it('PROP-TSE-001: Reflexive — x == x', () => {
    fc.assert(
      fc.property(fc.string({ minLength: 0, maxLength: 100 }), (s) => {
        expect(ashTimingSafeEqual(s, s)).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-TSE-002: Symmetric — (x == y) === (y == x)', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 100 }),
        fc.string({ minLength: 0, maxLength: 100 }),
        (a, b) => {
          expect(ashTimingSafeEqual(a, b)).toBe(ashTimingSafeEqual(b, a));
        },
      ),
      { numRuns: 200 },
    );
  });

  it('PROP-TSE-003: Different strings return false', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 100 }),
        (a, b) => {
          fc.pre(a !== b);
          expect(ashTimingSafeEqual(a, b)).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });
});

// ── Validation Invariants ───────────────────────────────────────────

describe('PROP: Validation invariants', () => {
  it('PROP-VAL-001: Valid nonce never throws', () => {
    fc.assert(
      fc.property(validNonce, (nonce) => {
        expect(() => ashValidateNonce(nonce)).not.toThrow();
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-VAL-002: Valid timestamp format returns parsed number', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: MAX_TIMESTAMP }), (ts) => {
        const result = ashValidateTimestampFormat(String(ts));
        expect(result).toBe(ts);
      }),
      { numRuns: 200 },
    );
  });

  it('PROP-VAL-003: Non-hex nonce always throws', () => {
    fc.assert(
      fc.property(
        fc.string({
          unit: fc.mapToConstant({ num: 26, build: v => String.fromCharCode(0x67 + v) }), // g-z
          minLength: 32, maxLength: 64,
        }),
        (badNonce) => {
          expect(() => ashValidateNonce(badNonce)).toThrow(AshError);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('PROP-VAL-004: Valid hash format never throws', () => {
    fc.assert(
      fc.property(validBodyHash, (hash) => {
        expect(() => ashValidateHash(hash, 'test')).not.toThrow();
      }),
      { numRuns: 100 },
    );
  });

  it('PROP-VAL-005: Wrong-length hash always throws', () => {
    fc.assert(
      fc.property(
        fc.string({ unit: hexChar, minLength: 1, maxLength: 63 }),
        (shortHash) => {
          expect(() => ashValidateHash(shortHash, 'test')).toThrow(AshError);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('PROP-VAL-006: Timestamp with leading zeros always rejected (except "0")', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 9999999 }), (n) => {
        const padded = '0' + String(n);
        expect(() => ashValidateTimestampFormat(padded)).toThrow(AshError);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Body Hash Normalization ─────────────────────────────────────────

describe('PROP: Body hash case normalization', () => {
  it('PROP-BHNORM-001: Uppercase body hash produces same proof as lowercase', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, (nonce, ctx, ts) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const bodyHash = ashHashBody('test');
        const upper = bodyHash.toUpperCase();
        const p1 = ashBuildProof(secret, ts, binding, bodyHash);
        const p2 = ashBuildProof(secret, ts, binding, upper);
        expect(p1).toBe(p2);
      }),
      { numRuns: 50 },
    );
  });

  it('PROP-BHNORM-002: Mixed-case body hash produces same proof', () => {
    fc.assert(
      fc.property(validNonce, validContextId, validTimestamp, (nonce, ctx, ts) => {
        const binding = 'POST|/api|';
        const secret = ashDeriveClientSecret(nonce, ctx, binding);
        const bodyHash = ashHashBody('test');
        // Mix case: alternating upper/lower
        const mixed = bodyHash.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('');
        const p1 = ashBuildProof(secret, ts, binding, bodyHash);
        const p2 = ashBuildProof(secret, ts, binding, mixed);
        expect(p1).toBe(p2);
      }),
      { numRuns: 50 },
    );
  });
});

// ── Error Type Invariants ───────────────────────────────────────────

describe('PROP: Error type invariants', () => {
  it('PROP-ERR-001: All thrown errors are AshError instances', () => {
    expect.assertions(44);
    const operations = [
      () => ashValidateNonce('short'),
      () => ashValidateTimestampFormat(''),
      () => ashValidateTimestampFormat('abc'),
      () => ashValidateHash('xyz', 'test'),
      () => ashDeriveClientSecret('short', 'ctx', 'POST|/|'),
      () => ashBuildProof('', '0', 'POST|/|', 'a'.repeat(64)),
      () => ashNormalizeBinding('', '/api', ''),
      () => ashNormalizeBinding('GET|X', '/api', ''),
      () => ashCanonicalizeJson('{invalid}'),
      () => ashHashProof(''),
      () => ashHashScope(['']),
    ];

    for (const op of operations) {
      try {
        op();
      } catch (e) {
        expect(e).toBeInstanceOf(AshError);
        const err = e as AshError;
        expect(err.code).toMatch(/^ASH_/);
        expect(typeof err.httpStatus).toBe('number');
        expect(typeof err.retryable).toBe('boolean');
      }
    }
  });
});
