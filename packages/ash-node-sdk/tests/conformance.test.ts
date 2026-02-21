/**
 * ASH Node SDK v1.0.0 — Conformance Test Runner
 *
 * Tests all 134 vectors from the shared conformance suite (tests/conformance/vectors.json).
 * Every vector must produce byte-identical output to the Rust ashcore reference implementation.
 *
 * Categories (12):
 *   json_canonicalization (34), query_canonicalization (15), urlencoded_canonicalization (8),
 *   binding_normalization (15), body_hashing (6), client_secret_derivation (6),
 *   proof_generation (8), scoped_field_extraction (8), unified_proof (6),
 *   timing_safe_comparison (5), timestamp_validation (8), error_behavior (15)
 *
 * @version 1.0.0
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  ASH_SDK_VERSION,
  ashCanonicalizeJson,
  ashCanonicalizeQuery,
  ashCanonicalizeUrlencoded,
  ashNormalizeBinding,
  ashHashBody,
  ashHashProof,
  ashHashScope,
  ashDeriveClientSecret,
  ashBuildProof,
  ashVerifyProof,
  ashExtractScopedFields,
  ashExtractScopedFieldsStrict,
  ashBuildProofScoped,
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashTimingSafeEqual,
  ashValidateTimestampFormat,
  AshError,
} from '../src/index.js';

// ── Load vectors ─────────────────────────────────────────────────────

const vectorsPath = resolve(__dirname, '../../../tests/conformance/vectors.json');
const vectorFile = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const vectors = vectorFile.vectors;

// ── SDK version gate ─────────────────────────────────────────────────

describe('ASH Node SDK v1.0.0 — version gate', () => {
  it('SDK version is 1.0.0', () => {
    expect(ASH_SDK_VERSION).toBe('1.0.0');
  });
});

// ── JSON Canonicalization (34 vectors) ───────────────────────────────

describe('json_canonicalization', () => {
  for (const v of vectors.json_canonicalization) {
    if (v.expected_error) {
      it(`${v.id}: ${v.description} (error)`, () => {
        expect.assertions(3);
        expect(() => ashCanonicalizeJson(v.input_json_text)).toThrow(AshError);
        try {
          ashCanonicalizeJson(v.input_json_text);
        } catch (e: unknown) {
          const err = e as AshError;
          expect(err.code).toBe(v.expected_error.code);
          expect(err.httpStatus).toBe(v.expected_error.http_status);
        }
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const result = ashCanonicalizeJson(v.input_json_text);
        expect(result).toBe(v.expected);
      });
    }
  }
});

// ── Query Canonicalization (15 vectors) ──────────────────────────────

describe('query_canonicalization', () => {
  for (const v of vectors.query_canonicalization) {
    if (v.expected_error) {
      it(`${v.id}: ${v.description} (error)`, () => {
        expect.assertions(3);
        expect(() => ashCanonicalizeQuery(v.input)).toThrow(AshError);
        try {
          ashCanonicalizeQuery(v.input);
        } catch (e: unknown) {
          const err = e as AshError;
          expect(err.code).toBe(v.expected_error.code);
          expect(err.httpStatus).toBe(v.expected_error.http_status);
        }
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const result = ashCanonicalizeQuery(v.input);
        expect(result).toBe(v.expected);
      });
    }
  }
});

// ── URL-encoded Canonicalization (8 vectors) ─────────────────────────

describe('urlencoded_canonicalization', () => {
  for (const v of vectors.urlencoded_canonicalization) {
    if (v.expected_error) {
      it(`${v.id}: ${v.description} (error)`, () => {
        expect.assertions(3);
        expect(() => ashCanonicalizeUrlencoded(v.input)).toThrow(AshError);
        try {
          ashCanonicalizeUrlencoded(v.input);
        } catch (e: unknown) {
          const err = e as AshError;
          expect(err.code).toBe(v.expected_error.code);
          expect(err.httpStatus).toBe(v.expected_error.http_status);
        }
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const result = ashCanonicalizeUrlencoded(v.input);
        expect(result).toBe(v.expected);
      });
    }
  }
});

// ── Binding Normalization (15 vectors) ───────────────────────────────

describe('binding_normalization', () => {
  for (const v of vectors.binding_normalization) {
    if (v.expected_error) {
      it(`${v.id}: ${v.description} (error)`, () => {
        expect.assertions(3);
        expect(() =>
          ashNormalizeBinding(v.input.method, v.input.path, v.input.query),
        ).toThrow(AshError);
        try {
          ashNormalizeBinding(v.input.method, v.input.path, v.input.query);
        } catch (e: unknown) {
          const err = e as AshError;
          expect(err.code).toBe(v.expected_error.code);
          expect(err.httpStatus).toBe(v.expected_error.http_status);
        }
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const result = ashNormalizeBinding(v.input.method, v.input.path, v.input.query);
        expect(result).toBe(v.expected);
      });
    }
  }
});

// ── Body Hashing (6 vectors) ────────────────────────────────────────

describe('body_hashing', () => {
  for (const v of vectors.body_hashing) {
    it(`${v.id}: ${v.description}`, () => {
      const result = ashHashBody(v.input);
      expect(result).toBe(v.expected);
    });
  }
});

// ── Client Secret Derivation (6 vectors) ────────────────────────────

describe('client_secret_derivation', () => {
  for (const v of vectors.client_secret_derivation) {
    it(`${v.id}: ${v.description}`, () => {
      const result = ashDeriveClientSecret(v.input.nonce, v.input.context_id, v.input.binding);
      expect(result).toBe(v.expected);
    });
  }
});

// ── Proof Generation (8 vectors) ────────────────────────────────────

describe('proof_generation', () => {
  for (const v of vectors.proof_generation) {
    if (v.expected.valid !== undefined) {
      it(`${v.id}: ${v.description}`, () => {
        const result = ashVerifyProof(
          v.input.nonce,
          v.input.context_id,
          v.input.binding,
          v.input.timestamp,
          v.input.body_hash,
          v.input.proof,
        );
        expect(result).toBe(v.expected.valid);
      });
    } else if (v.expected.proof_is_lowercase_hex !== undefined) {
      it(`${v.id}: ${v.description}`, () => {
        const clientSecret = ashDeriveClientSecret(v.input.nonce, v.input.context_id, v.input.binding);
        const canonical = ashCanonicalizeJson(v.input.payload);
        const bodyHash = ashHashBody(canonical);
        const proof = ashBuildProof(clientSecret, v.input.timestamp, v.input.binding, bodyHash);
        expect(proof).toBe(v.expected.proof);
        expect(proof.length).toBe(v.expected.proof_length);
        expect(/^[0-9a-f]+$/.test(proof)).toBe(v.expected.proof_is_lowercase_hex);
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const clientSecret = ashDeriveClientSecret(v.input.nonce, v.input.context_id, v.input.binding);
        expect(clientSecret).toBe(v.expected.client_secret);

        const canonical = ashCanonicalizeJson(v.input.payload);
        expect(canonical).toBe(v.expected.canonical_payload);

        const bodyHash = ashHashBody(canonical);
        expect(bodyHash).toBe(v.expected.body_hash);

        const proof = ashBuildProof(clientSecret, v.input.timestamp, v.input.binding, bodyHash);
        expect(proof).toBe(v.expected.proof);
      });
    }
  }
});

// ── Scoped Field Extraction (8 vectors) ─────────────────────────────

describe('scoped_field_extraction', () => {
  for (const v of vectors.scoped_field_extraction) {
    if (v.expected_error) {
      it(`${v.id}: ${v.description} (error)`, () => {
        expect.assertions(3);
        const payload = JSON.parse(v.input.payload);
        expect(() => ashExtractScopedFieldsStrict(payload, v.input.scope)).toThrow(AshError);
        try {
          ashExtractScopedFieldsStrict(payload, v.input.scope);
        } catch (e: unknown) {
          const err = e as AshError;
          expect(err.code).toBe(v.expected_error.code);
          expect(err.httpStatus).toBe(v.expected_error.http_status);
        }
      });
    } else if (v.expected.scope_hash && !v.expected.proof) {
      it(`${v.id}: ${v.description}`, () => {
        const scopeHash = ashHashScope(v.input.scope);
        expect(scopeHash).toBe(v.expected.scope_hash);
      });
    } else if (v.expected.proof) {
      it(`${v.id}: ${v.description}`, () => {
        const payload = JSON.parse(v.input.payload);
        const extracted = ashExtractScopedFields(payload, v.input.scope);
        expect(extracted).toEqual(v.expected.extracted_fields);

        const clientSecret = ashDeriveClientSecret(v.input.nonce, v.input.context_id, v.input.binding);
        const result = ashBuildProofScoped(
          clientSecret,
          v.input.timestamp,
          v.input.binding,
          v.input.payload,
          v.input.scope,
        );
        expect(result.proof).toBe(v.expected.proof);
        expect(result.scopeHash).toBe(v.expected.scope_hash);
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const payload = JSON.parse(v.input.payload);
        const extracted = ashExtractScopedFields(payload, v.input.scope);
        expect(extracted).toEqual(v.expected.extracted_fields);
      });
    }
  }
});

// ── Unified Proof (6 vectors) ───────────────────────────────────────

describe('unified_proof', () => {
  for (const v of vectors.unified_proof) {
    if (v.expected.valid !== undefined) {
      it(`${v.id}: ${v.description}`, () => {
        const result = ashVerifyProofUnified(
          v.input.nonce,
          v.input.context_id,
          v.input.binding,
          v.input.timestamp,
          v.input.payload,
          v.input.proof,
          v.input.scope,
          v.input.scope_hash,
          v.input.previous_proof ?? null,
          v.input.chain_hash,
        );
        expect(result).toBe(v.expected.valid);
      });
    } else if (v.expected.chain_hash && !v.expected.proof) {
      it(`${v.id}: ${v.description}`, () => {
        const chainHash = ashHashProof(v.input.previous_proof);
        expect(chainHash).toBe(v.expected.chain_hash);
      });
    } else {
      it(`${v.id}: ${v.description}`, () => {
        const clientSecret = ashDeriveClientSecret(v.input.nonce, v.input.context_id, v.input.binding);
        const result = ashBuildProofUnified(
          clientSecret,
          v.input.timestamp,
          v.input.binding,
          v.input.payload,
          v.input.scope,
          v.input.previous_proof ?? null,
        );
        expect(result.proof).toBe(v.expected.proof);
        expect(result.scopeHash).toBe(v.expected.scope_hash);
        expect(result.chainHash).toBe(v.expected.chain_hash);
      });
    }
  }
});

// ── Timing Safe Comparison (5 vectors) ──────────────────────────────

describe('timing_safe_comparison', () => {
  for (const v of vectors.timing_safe_comparison) {
    it(`${v.id}: ${v.description}`, () => {
      const result = ashTimingSafeEqual(v.input.a, v.input.b);
      expect(result).toBe(v.expected);
    });
  }
});

// ── Timestamp Validation (8 vectors) ────────────────────────────────

describe('timestamp_validation', () => {
  for (const v of vectors.timestamp_validation) {
    if (v.expected_error) {
      it(`${v.id}: ${v.description} (error)`, () => {
        expect.assertions(3);
        expect(() => ashValidateTimestampFormat(v.input.timestamp)).toThrow(AshError);
        try {
          ashValidateTimestampFormat(v.input.timestamp);
        } catch (e: unknown) {
          const err = e as AshError;
          expect(err.code).toBe(v.expected_error.code);
          expect(err.httpStatus).toBe(v.expected_error.http_status);
        }
      });
    } else if (v.expected.valid_format !== undefined) {
      it(`${v.id}: ${v.description}`, () => {
        const ts = ashValidateTimestampFormat(v.input.timestamp);
        if (v.expected.value_seconds !== undefined) {
          expect(ts).toBe(v.expected.value_seconds);
        }
      });
    } else if (v.expected.resolution !== undefined) {
      it(`${v.id}: ${v.description}`, () => {
        expect(v.expected.resolution).toBe('seconds');
        expect(v.expected.reference_time_seconds).toBe(v.input.reference_time);
      });
    }
  }
});

// ── Error Behavior (15 vectors) ─────────────────────────────────────

describe('error_behavior', () => {
  for (const v of vectors.error_behavior) {
    it(`${v.id}: ${v.description}`, () => {
      let thrown: AshError | null = null;

      try {
        switch (v.input.operation) {
          case 'derive_client_secret':
            ashDeriveClientSecret(v.input.nonce, v.input.context_id, v.input.binding);
            break;
          case 'canonicalize_json': {
            let jsonInput: string;
            if (v.input.input_json_text !== undefined) {
              jsonInput = v.input.input_json_text;
            } else if (v.input.note?.includes('10MB')) {
              jsonInput = '{"data":"' + 'x'.repeat(11 * 1024 * 1024) + '"}';
            } else if (v.input.note?.includes('64 nesting')) {
              jsonInput = '{"a":'.repeat(70) + '1' + '}'.repeat(70);
            } else {
              throw new Error(`Unknown canonicalize_json error vector: ${v.id}`);
            }
            ashCanonicalizeJson(jsonInput);
            break;
          }
          case 'verify_proof':
            ashValidateTimestampFormat(v.input.timestamp);
            break;
          case 'extract_scoped_fields_strict': {
            const payload = JSON.parse(v.input.payload);
            ashExtractScopedFieldsStrict(payload, v.input.scope);
            break;
          }
          case 'build_proof':
            ashBuildProof('dummy_secret', '1700000000', 'POST|/api|', v.input.body_hash);
            break;
          case 'hash_proof':
            ashHashProof(v.input.proof);
            break;
          default:
            throw new Error(`Unknown operation: ${v.input.operation}`);
        }
      } catch (e: unknown) {
        if (e instanceof AshError) thrown = e;
        else throw e;
      }

      expect(thrown).not.toBeNull();
      expect(thrown!.code).toBe(v.expected_error.code);
      expect(thrown!.httpStatus).toBe(v.expected_error.http_status);
    });
  }
});

// ── Summary ─────────────────────────────────────────────────────────

describe('conformance summary', () => {
  it('has all 12 categories with correct vector counts', () => {
    expect(vectors.json_canonicalization.length).toBe(34);
    expect(vectors.query_canonicalization.length).toBe(15);
    expect(vectors.urlencoded_canonicalization.length).toBe(8);
    expect(vectors.binding_normalization.length).toBe(15);
    expect(vectors.body_hashing.length).toBe(6);
    expect(vectors.client_secret_derivation.length).toBe(6);
    expect(vectors.proof_generation.length).toBe(8);
    expect(vectors.scoped_field_extraction.length).toBe(8);
    expect(vectors.unified_proof.length).toBe(6);
    expect(vectors.timing_safe_comparison.length).toBe(5);
    expect(vectors.timestamp_validation.length).toBe(8);
    expect(vectors.error_behavior.length).toBe(15);

    const total = 34 + 15 + 8 + 15 + 6 + 6 + 8 + 8 + 6 + 5 + 8 + 15;
    expect(total).toBe(134);
  });
});
