/**
 * ASH Node SDK — Phase 2: Scope Policy Registry Tests
 *
 * Coverage: PT (pattern injection, null bytes, traversal) / AQ (exact/wildcard/param,
 * no-match, clear, priority) / SA (validation limits, ordering) / FUZZ (random patterns)
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { AshScopePolicyRegistry } from '../../../src/scope-policy.js';

let registry: AshScopePolicyRegistry;

beforeEach(() => {
  registry = new AshScopePolicyRegistry();
});

// ── AQ: Registration & Has ─────────────────────────────────────────

describe('AQ: Scope policy — registration', () => {
  it('AQ-SP-001: register and has', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name', 'email'] });
    expect(registry.has('POST /api/users')).toBe(true);
    expect(registry.has('GET /api/users')).toBe(false);
  });

  it('AQ-SP-002: size reflects registrations', () => {
    expect(registry.size).toBe(0);
    registry.register({ pattern: 'POST /api/a', fields: [] });
    expect(registry.size).toBe(1);
    registry.register({ pattern: 'GET /api/b', fields: [] });
    expect(registry.size).toBe(2);
  });

  it('AQ-SP-003: clear removes all policies', () => {
    registry.register({ pattern: 'POST /api/a', fields: [] });
    registry.register({ pattern: 'GET /api/b', fields: [] });
    registry.clear();
    expect(registry.size).toBe(0);
    expect(registry.has('POST /api/a')).toBe(false);
  });
});

// ── AQ: Exact Match ────────────────────────────────────────────────

describe('AQ: Scope policy — exact match', () => {
  it('AQ-SP-EXACT-001: exact match returns policy and empty params', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'] });
    const result = registry.match('POST', '/api/users');
    expect(result).not.toBeNull();
    expect(result!.policy.fields).toEqual(['name']);
    expect(result!.params).toEqual({});
  });

  it('AQ-SP-EXACT-002: case-insensitive method matching', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'] });
    const result = registry.match('post', '/api/users');
    expect(result).not.toBeNull();
  });

  it('AQ-SP-EXACT-003: no match for wrong method', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'] });
    const result = registry.match('GET', '/api/users');
    expect(result).toBeNull();
  });

  it('AQ-SP-EXACT-004: no match for different path', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'] });
    const result = registry.match('POST', '/api/orders');
    expect(result).toBeNull();
  });

  it('AQ-SP-EXACT-005: no match when path has extra segments', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'] });
    const result = registry.match('POST', '/api/users/123');
    expect(result).toBeNull();
  });
});

// ── AQ: Param Match ────────────────────────────────────────────────

describe('AQ: Scope policy — param match', () => {
  it('AQ-SP-PARAM-001: param pattern extracts value', () => {
    registry.register({ pattern: 'GET /api/users/:id', fields: ['profile'] });
    const result = registry.match('GET', '/api/users/42');
    expect(result).not.toBeNull();
    expect(result!.params).toEqual({ id: '42' });
  });

  it('AQ-SP-PARAM-002: multiple params', () => {
    registry.register({ pattern: 'PUT /api/:org/users/:id', fields: ['role'] });
    const result = registry.match('PUT', '/api/acme/users/99');
    expect(result).not.toBeNull();
    expect(result!.params).toEqual({ org: 'acme', id: '99' });
  });

  it('AQ-SP-PARAM-003: param does not match empty segment', () => {
    registry.register({ pattern: 'GET /api/users/:id', fields: [] });
    // path /api/users/ has 2 non-empty segments: ["api", "users"]
    const result = registry.match('GET', '/api/users/');
    expect(result).toBeNull();
  });
});

// ── AQ: Wildcard Match ─────────────────────────────────────────────

describe('AQ: Scope policy — wildcard match', () => {
  it('AQ-SP-WILD-001: trailing wildcard matches any suffix', () => {
    registry.register({ pattern: 'GET /api/*', fields: ['data'] });
    expect(registry.match('GET', '/api/users')).not.toBeNull();
    expect(registry.match('GET', '/api/users/123')).not.toBeNull();
    expect(registry.match('GET', '/api/users/123/profile')).not.toBeNull();
  });

  it('AQ-SP-WILD-002: wildcard requires at least the prefix', () => {
    registry.register({ pattern: 'GET /api/*', fields: [] });
    expect(registry.match('GET', '/other')).toBeNull();
  });

  it('AQ-SP-WILD-003: wildcard matches exact prefix (zero extra segments)', () => {
    registry.register({ pattern: 'GET /api/*', fields: [] });
    // "/api" has 1 segment ["api"], wildcard pattern has 1 literal + 1 wildcard
    // policySegs: [{literal:"api"}, {wildcard}], pathSegs: ["api"]
    // checkLength = 1 (wildcard count - 1), pathSegs.length >= 0 → yes
    const result = registry.match('GET', '/api');
    // pathSegs.length (1) >= policySegs.length - 1 (1) → matches
    expect(result).not.toBeNull();
  });
});

// ── AQ: Match Priority ─────────────────────────────────────────────

describe('AQ: Scope policy — match priority', () => {
  it('AQ-SP-PRIO-001: exact > param > wildcard', () => {
    registry.register({ pattern: 'GET /api/*', fields: ['wild'] });
    registry.register({ pattern: 'GET /api/:id', fields: ['param'] });
    registry.register({ pattern: 'GET /api/special', fields: ['exact'] });

    const result = registry.match('GET', '/api/special');
    expect(result).not.toBeNull();
    expect(result!.policy.fields).toEqual(['exact']);
  });

  it('AQ-SP-PRIO-002: param wins over wildcard', () => {
    registry.register({ pattern: 'GET /api/*', fields: ['wild'] });
    registry.register({ pattern: 'GET /api/:id', fields: ['param'] });

    const result = registry.match('GET', '/api/123');
    expect(result).not.toBeNull();
    expect(result!.policy.fields).toEqual(['param']);
  });

  it('AQ-SP-PRIO-003: wildcard used when no other match', () => {
    registry.register({ pattern: 'GET /api/*', fields: ['wild'] });

    const result = registry.match('GET', '/api/x/y/z');
    expect(result).not.toBeNull();
    expect(result!.policy.fields).toEqual(['wild']);
  });
});

// ── AQ: No Match ───────────────────────────────────────────────────

describe('AQ: Scope policy — no match', () => {
  it('AQ-SP-NO-001: empty registry returns null', () => {
    expect(registry.match('GET', '/anything')).toBeNull();
  });

  it('AQ-SP-NO-002: completely different path', () => {
    registry.register({ pattern: 'POST /api/users', fields: [] });
    expect(registry.match('POST', '/other/path')).toBeNull();
  });
});

// ── PT: Pattern Injection ──────────────────────────────────────────

describe('PT: Scope policy — pattern validation', () => {
  it('PT-SP-001: rejects empty pattern', () => {
    expect(() => registry.register({ pattern: '', fields: [] })).toThrow();
  });

  it('PT-SP-002: rejects pattern exceeding 512 chars', () => {
    const long = 'GET /' + 'a'.repeat(510);
    expect(() => registry.register({ pattern: long, fields: [] })).toThrow();
  });

  it('PT-SP-003: rejects null bytes in pattern', () => {
    expect(() => registry.register({ pattern: 'GET /api/\x00users', fields: [] })).toThrow();
  });

  it('PT-SP-004: rejects control characters in pattern', () => {
    expect(() => registry.register({ pattern: 'GET /api/\x0Ausers', fields: [] })).toThrow();
  });

  it('PT-SP-005: rejects more than 8 wildcards', () => {
    const pattern = 'GET /' + Array(9).fill('*').join('/');
    expect(() => registry.register({ pattern, fields: [] })).toThrow();
  });

  it('PT-SP-006: rejects pattern without space separator', () => {
    expect(() => registry.register({ pattern: 'GET/api/users', fields: [] })).toThrow();
  });

  it('PT-SP-007: rejects path not starting with /', () => {
    expect(() => registry.register({ pattern: 'GET api/users', fields: [] })).toThrow();
  });
});

// ── SA: Required field ─────────────────────────────────────────────

describe('SA: Scope policy — required field', () => {
  it('SA-SP-001: policy.required is preserved', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'], required: true });
    const result = registry.match('POST', '/api/users');
    expect(result!.policy.required).toBe(true);
  });

  it('SA-SP-002: policy.required defaults to undefined', () => {
    registry.register({ pattern: 'POST /api/users', fields: ['name'] });
    const result = registry.match('POST', '/api/users');
    expect(result!.policy.required).toBeUndefined();
  });
});

// ── FUZZ: Random patterns ──────────────────────────────────────────

describe('FUZZ: Scope policy — stress', () => {
  it('FUZZ-SP-001: many registrations do not break matching', () => {
    for (let i = 0; i < 100; i++) {
      registry.register({ pattern: `GET /api/resource${i}`, fields: [`field${i}`] });
    }
    expect(registry.size).toBe(100);
    const result = registry.match('GET', '/api/resource50');
    expect(result).not.toBeNull();
    expect(result!.policy.fields).toEqual(['field50']);
  });

  it('FUZZ-SP-002: pattern with exactly 512 chars is accepted', () => {
    const path = '/' + 'a'.repeat(512 - 5); // "GET " = 4 chars + "/" = 5 overhead
    const pattern = `GET ${path}`;
    expect(pattern.length).toBe(512);
    expect(() => registry.register({ pattern, fields: [] })).not.toThrow();
  });

  it('FUZZ-SP-003: exactly 8 wildcards is accepted', () => {
    const pattern = 'GET /' + Array(8).fill('*').join('/');
    expect(() => registry.register({ pattern, fields: [] })).not.toThrow();
  });
});
