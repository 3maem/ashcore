# ASH Node SDK — Progress

## Phase 0: Housekeeping
- [x] Move existing SDKs to `packages/sdk-legacy/`
- [x] Create ROADMAP.md
- [x] Create PROGRESS.md

## Phase 1: Project Scaffold
- [x] `package.json` — `@3maem/ash-node-sdk`, zero runtime deps
- [x] `tsconfig.json` — strict mode, ES2022, bundler moduleResolution
- [x] `tsup.config.ts` — CJS + ESM + DTS, node18 target
- [x] `vitest.config.ts` — test runner
- [x] `LICENSE` — Apache-2.0

## Phase 2: Core Implementation (12 files)
- [x] `constants.ts` — protocol constants matching ashcore
- [x] `errors.ts` — AshError class, 15 error codes, HTTP status mapping
- [x] `types.ts` — AshMode, ScopedProofResult, UnifiedProofResult
- [x] `validate.ts` — nonce, timestamp format, timestamp freshness, hash validation
- [x] `compare.ts` — timing-safe string comparison
- [x] `hash.ts` — SHA-256 body/proof/scope hashing
- [x] `canonicalize.ts` — RFC 8785 JSON, query, urlencoded canonicalization
- [x] `binding.ts` — binding normalization (METHOD|PATH|QUERY)
- [x] `proof.ts` — client secret derivation, basic proof build/verify
- [x] `proof-scoped.ts` — scoped field extraction, scoped proof build/verify
- [x] `proof-unified.ts` — unified proof with scope + chain
- [x] `index.ts` — barrel export

## Phase 3: Testing
- [x] `conformance.test.ts` — 134/134 vectors (136 tests with meta)
- [x] `unit/pt-tests.test.ts` — 39 penetration tests
- [x] `unit/security-audit.test.ts` — 57 security audit tests
- [x] `unit/qa-tests.test.ts` — 98 QA tests
- [x] `unit/bugs-tests.test.ts` — 46 bug regression tests
- [x] `unit/logical-errors.test.ts` — 57 logical error tests

## Phase 3.1: Comprehensive Test Expansion
- [x] `unit/property-based.test.ts` — 50 property-based/fuzz tests (fast-check)
  - Hash output invariants, JSON/query/binding canonicalization properties
  - Proof roundtrip, scoped/unified invariants, timing-safe comparison
  - Validation boundary sweeps with custom arbitraries
- [x] `unit/comprehensive-security.test.ts` — 157 comprehensive security tests
  - Unicode edge cases (surrogates, BOM, RTL, zero-width, homoglyphs)
  - Protocol attack vectors (replay, timing, injection, traversal)
  - All 15 error codes with HTTP status verification
  - Boundary conditions, cross-function integration
  - Advanced canonicalization (JSON, query, binding, scope)

## Phase 4: Server Integration — Phase 2 (8 files)

### Sub-phase 2.1: Headers
- [x] `headers.ts` — header name constants (X_ASH_TIMESTAMP, X_ASH_NONCE, X_ASH_BODY_HASH, X_ASH_PROOF, X_ASH_CONTEXT_ID)
- [x] `headers.ts` — AshHeaderBundle type, ashExtractHeaders() with case-insensitive lookup, control char rejection, length enforcement
- [x] `tests/unit/phase2/headers.test.ts` — 35 tests (PT/AQ/SA/FUZZ)

### Sub-phase 2.2: Context Store
- [x] `context.ts` — AshContext type, AshContextStore interface
- [x] `context.ts` — AshMemoryStore class (Map-based, configurable TTL, auto-cleanup timer with unref)
- [x] `context.ts` — store(), get(), consume() (atomic one-time-use), cleanup(), destroy()
- [x] `tests/unit/phase2/context.test.ts` — 28 tests (PT/AQ/SA/FUZZ)

### Sub-phase 2.3: Scope Policy Registry
- [x] `scope-policy.ts` — ScopePolicy, ScopePolicyMatch types
- [x] `scope-policy.ts` — AshScopePolicyRegistry (register, match, has, clear) with exact/param/wildcard patterns
- [x] `scope-policy.ts` — Match priority: exact (3) > param (2) > wildcard (1)
- [x] `tests/unit/phase2/scope-policy.test.ts` — 31 tests (PT/AQ/SA/FUZZ)

### Sub-phase 2.4: Build & Verify Orchestrators
- [x] `build-request.ts` — ashBuildRequest() 7-step pipeline, auto-detect mode (basic/scoped/unified), result with destroy()
- [x] `verify-request.ts` — ashVerifyRequest() 9-step pipeline, errors returned as { ok: false, error } not thrown
- [x] Mode detection: scope-only → scoped, previousProof present → unified, neither → basic
- [x] `tests/unit/phase2/build-request.test.ts` — 24 tests (PT/AQ/SA/FUZZ)
- [x] `tests/unit/phase2/verify-request.test.ts` — 23 tests (PT/AQ/SA/FUZZ)

### Sub-phase 2.5: Express Middleware
- [x] `middleware/types.ts` — AshMiddlewareOptions, AshRequestMeta shared types
- [x] `middleware/express.ts` — ashExpressMiddleware() factory (consume context → verify → attach req.ash → next)
- [x] `middleware/express.ts` — custom onError handler, custom extractBody, scope registry integration
- [x] `tests/unit/phase2/middleware-express.test.ts` — 16 tests (PT/AQ/SA/FUZZ)

### Sub-phase 2.6: Fastify Plugin
- [x] `middleware/fastify.ts` — ashFastifyPlugin() async plugin (decorateRequest + onRequest hook)
- [x] `middleware/fastify.ts` — same verify flow and error format as Express
- [x] `tests/unit/phase2/middleware-fastify.test.ts` — 15 tests (PT/AQ/SA/FUZZ)

### Phase 2 Barrel Exports
- [x] `index.ts` — updated with all Phase 2 exports (headers, context, scope-policy, build-request, verify-request, middleware types, express, fastify)

## Phase 4.1: Comprehensive Phase 2 Testing
- [x] `tests/unit/phase2/comprehensive-phase2.test.ts` — 130 tests across 9 sections
  - Headers injection/smuggling, context store security, scope policy patterns
  - Build request determinism, verify request attack vectors
  - Express middleware security, Fastify plugin security
  - Cross-module integration (full E2E lifecycle)
  - FUZZ adversarial (random inputs across all modules)

## Phase 4.2: Production Readiness
- [x] `context-redis.ts` — AshRedisStore (Redis-backed AshContextStore, atomic Lua consume, TTL via EXPIRE)
- [x] `tests/unit/phase2/context-redis.test.ts` — 36 tests (PT/AQ/SA/FUZZ with mock Redis)
- [x] `examples/express-example.ts` — full client→server Express integration example
- [x] `examples/fastify-example.ts` — full client→server Fastify integration example (basic + scoped modes)
- [x] `README.md` — comprehensive API documentation, flow diagram, error table, quick start
- [x] `package.json` — v1.1.0, peerDependencies (express/fastify/ioredis), keywords, repository, prepublishOnly
- [x] `index.ts` — updated barrel export with AshRedisStore, RedisClient, AshRedisStoreOptions

## Phase 4.3: Comprehensive Production Testing
- [x] `tests/unit/phase2/comprehensive-production.test.ts` — 123 tests across 3 sections
  - Section 1: Redis Context Store — Deep Security (59 tests)
    - PT: Redis client failure modes, Lua script response manipulation, key injection, JSON deser attacks, MemoryStore parity
    - AQ: Constructor options, serialization correctness, consume atomicity, expiry edge cases
    - SA: Error message safety, HTTP status mapping, interface compliance, secret storage
    - FUZZ: Random UUIDs, Unicode IDs, concurrent consume, large payloads, malicious stored values
  - Section 2: E2E Integration — Full Lifecycle (40 tests)
    - Express + Fastify: basic mode, POST with body, replay detection, missing headers, tampered body
    - Scoped mode with ScopePolicyRegistry, custom onError/extractBody, query string handling
    - Redis store + middleware E2E, binding mismatch attacks, concurrent contexts, non-AshError handling
  - Section 3: Barrel Export & Package Correctness (24 tests)
    - All Layer 1 + Layer 2 exports verified, functional roundtrip from barrel
    - AshErrorCode completeness (15 codes, unique statuses, all factory methods)
    - Constants correctness, no internal leaks, package.json structure validation

## Phase 5: Developer Experience — Phase 3 (2 files)

### Debug Trace
- [x] `debug.ts` — ashBuildRequestDebug() (7-step traced build), ashVerifyRequestDebug() (9-step traced verify), ashFormatTrace()
- [x] `debug.ts` — TraceStep, BuildRequestDebugResult, VerifyRequestDebugResult types
- [x] `debug.ts` — Sensitive values REDACTED, identical proof output to non-debug functions
- [x] `tests/unit/phase3/debug.test.ts` — 58 tests (PT/AQ/SA/FUZZ)

### CLI Tool
- [x] `cli.ts` — 7 commands: build, verify, hash, derive, inspect, version, help
- [x] `cli.ts` — Node.js parseArgs (zero deps), --json flag, stdin body reading
- [x] `cli.ts` — Exit codes: 0 success, 1 invalid, 2 usage, 3 error
- [x] `tsup.config.ts` — dual build: library (CJS+ESM+DTS) + CLI (ESM with shebang)
- [x] `package.json` — v1.2.0, bin.ash field
- [x] `tests/unit/phase3/cli.test.ts` — 49 tests (PT/AQ/SA/FUZZ)

### Phase 3 Integration
- [x] `tests/unit/phase3/comprehensive-phase3.test.ts` — 31 tests (cross-cutting, interop, regression)
- [x] `index.ts` — updated with Phase 3 debug exports

## Verification
- [x] `npm run build` — CJS + ESM + DTS + CLI binary, zero errors
- [x] `npm run test` — 1373/1373 tests passing (23 test files)
- [x] `npm run typecheck` — zero TypeScript errors
- [x] `node dist/cli.js version` — prints @3maem/ash-node-sdk v1.2.0 (ASHv2.1)
