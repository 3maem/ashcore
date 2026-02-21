# Changelog

All notable changes to the `@3maem/ash-node-sdk` package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (2026-02-14)
- Removed legacy SDK references from `ROADMAP.md` (Phase 4: deleted Go/Python/PHP/WASM rebuild lines)
- Removed non-existent `ashInit()` from Express example (`examples/express-example.ts`)

## [1.2.0] - 2026-02-13

### Added — Phase 3: Developer Experience (2026-02-13)

2 new source files providing CLI tool and debug trace mode. Zero new runtime dependencies —
Node.js `parseArgs` is built-in since Node 18.3.

#### `src/debug.ts`
- `ashBuildRequestDebug()` — 7-step build pipeline with per-step timing, input/output trace,
  and error capture. Returns `BuildRequestDebugResult` extending `BuildRequestResult`
- `ashVerifyRequestDebug()` — 9-step verify pipeline with same trace pattern. Returns
  `VerifyRequestDebugResult` extending `VerifyResult`
- `ashFormatTrace()` — Pretty-print trace array for terminal/log output
- `TraceStep`, `BuildRequestDebugResult`, `VerifyRequestDebugResult` types
- Sensitive values (clientSecret, full proof/hash) REDACTED in trace output
- Identical proof output to non-debug functions (verified in tests)

#### `src/cli.ts`
- CLI entry point with 7 commands: `build`, `verify`, `hash`, `derive`, `inspect`, `version`, `help`
- Uses Node.js `parseArgs` (zero external dependencies)
- Exit codes: 0 (success), 1 (invalid proof), 2 (usage error), 3 (internal error)
- `--json` flag for machine-readable output on all commands
- `--help` on each subcommand
- Stdin body reading via `--body -`
- `inspect build` / `inspect verify` for debug trace visualization

#### `tsup.config.ts`
- Dual build config: library (CJS + ESM + DTS) + CLI (ESM with shebang banner)

#### `package.json` — v1.2.0
- Added `bin.ash` field pointing to `dist/cli.js`
- Bumped version to 1.2.0

#### `src/index.ts`
- Added Phase 3 debug exports: `ashBuildRequestDebug`, `ashVerifyRequestDebug`, `ashFormatTrace`
- Added Phase 3 types: `TraceStep`, `BuildRequestDebugResult`, `VerifyRequestDebugResult`

### Testing — Phase 3 (2026-02-13)

~138 new tests across 3 test files.

#### `tests/unit/phase3/debug.test.ts` (58 tests)
- PT: Secret leakage prevention, tampered input detection, error trace safety
- AQ: Step counts (7 build, 9 verify), mode detection, timing, formatting, auto-timestamp
- SA: REDACTED secrets, no full proof in trace, safe error messages, parity with non-debug
- FUZZ: Random nonces, unicode bodies, large payloads, roundtrip validation

#### `tests/unit/phase3/cli.test.ts` (49 tests)
- PT: Shell metacharacter injection, invalid hex, oversized args, pipe injection
- AQ: All commands (build, verify, hash, derive, inspect, version, help), roundtrips,
  scoped/unified modes, missing args, text/JSON output
- SA: No secrets in stderr, consistent exit codes, no stack traces
- FUZZ: Garbage args, empty strings, random roundtrips, long bodies

#### `tests/unit/phase3/comprehensive-phase3.test.ts` (31 tests)
- Debug↔CLI inspect consistency, SDK→CLI and CLI→SDK interop
- Hash/derive command parity with SDK functions
- Error code→exit code mapping, determinism, regression (Layer 1/2 unaffected)
- Concurrent CLI invocations, edge cases

### Testing — Comprehensive Production Readiness (2026-02-13)

123 new tests in `tests/unit/phase2/comprehensive-production.test.ts`, bringing total from
1112 to **1235 tests** (all passing, 20 test files).

#### Section 1: Redis Context Store — Deep Security (59 tests)
- **PT**: Redis client failure modes (GET/SET/EVAL/DEL network errors), Lua script response
  manipulation (null, numeric, empty, malformed JSON, missing fields), key injection attacks
  (CRLF, null bytes, prefix escape, wildcards), JSON deserialization attacks (`__proto__`
  pollution, constructor pollution, deep nesting), Redis vs MemoryStore error parity
- **AQ**: Constructor option variants (default/empty/custom prefix, small/large TTL),
  serialization correctness (all 7 fields, expiresAt calculation, EX argument), consume
  atomicity (Lua eval call verified, correct key, pre/post state), expiry edge cases
  (exact boundary, far future, negative, cleanup after expire)
- **SA**: Error message safety (no context ID, nonce, secret, or timestamps leaked), HTTP
  status code mapping (450/451/452), full AshContextStore interface compliance, secret data
  storage verification
- **FUZZ**: 100 random UUIDs, all printable ASCII, Unicode IDs, concurrent consume simulation
  (10 parallel — exactly 1 succeeds), large payloads (10KB nonce, 50KB binding), malicious
  stored values (non-JSON, JSON array, extra fields)

#### Section 2: E2E Integration — Full Lifecycle (40 tests)
- Full client→server lifecycle: context create → proof build → middleware verify → success
  (Express and Fastify, basic and scoped modes)
- POST with JSON body (pre-parsed and raw string), tampered body detection (→ 460)
- Replay attack detection (second request → 452, both Express and Fastify)
- Missing/invalid headers (no context ID → 483, partial headers → 483, unknown ID → 450)
- Scoped mode with ScopePolicyRegistry, custom onError (Express + Fastify), custom extractBody
- Query string handling (Express originalUrl, Fastify URL with hash/query)
- Redis store + Express middleware E2E (full flow + replay blocked)
- Binding mismatch attacks (wrong path → 460, wrong method → 460)
- Multiple concurrent contexts independently verified
- Non-AshError from store caught as 500, Fastify URL parsing edge cases

#### Section 3: Barrel Export & Package Correctness (24 tests)
- All Layer 1 exports verified (16 constants, errors, validation, canonicalization, hashing,
  binding, basic/scoped/unified proof — 10 sub-tests)
- All Layer 2 exports verified (header constants, ashExtractHeaders, AshMemoryStore,
  AshRedisStore, AshScopePolicyRegistry, build/verify orchestrators, middleware — 9 sub-tests)
- Functional correctness from barrel (AshRedisStore roundtrip, interface parity)
- AshErrorCode completeness (15 codes, unique HTTP statuses, all 13 factory methods)
- Constants correctness (SHA256_HEX_LENGTH=64, defaults)
- No internal leaks (no underscore-prefixed, no Lua scripts, no internal crypto)
- package.json validation (version 1.1.0, name, license, engine >=18, no runtime deps,
  peer deps all optional, files array, prepublishOnly, exports map, keywords)

### Added — Production Readiness (2026-02-13)

#### `src/context-redis.ts`
- `AshRedisStore` class — Redis-backed `AshContextStore` implementation
- Atomic consume via Lua scripting (get → check used → mark used in single Redis call)
- TTL via Redis `EXPIRE` (no manual cleanup needed)
- Configurable key prefix (default: `ash:ctx:`) and TTL (default: 300s)
- `RedisClient` interface for duck-typing (compatible with ioredis, node-redis, etc.)

#### `examples/express-example.ts`
- Complete Express client→server integration example
- Demonstrates: context creation → proof build → middleware verify → replay rejection

#### `examples/fastify-example.ts`
- Complete Fastify client→server integration example
- Demonstrates: basic mode (GET), scoped mode (POST with field extraction), scope registry

#### `README.md`
- Comprehensive API documentation for all Layer 1 and Layer 2 functions
- Client→server flow diagram
- Error code table with HTTP status mapping
- Quick start examples for Express and Fastify
- Redis store usage example

#### `package.json` — v1.1.0
- Bumped version to 1.1.0
- Added `peerDependencies` for Express (>=4), Fastify (>=4), ioredis (>=5) — all optional
- Added `keywords`, `repository` fields
- Added `prepublishOnly` script (build + typecheck + test)
- Added `README.md` to `files` array

### Added — Phase 2: Server Integration Layer (2026-02-13)

8 new source files providing Express/Fastify middleware, context lifecycle management, and request
orchestration. Zero new runtime dependencies — Express and Fastify are peer deps via duck-typing.

#### `src/headers.ts`
- `X_ASH_TIMESTAMP`, `X_ASH_NONCE`, `X_ASH_BODY_HASH`, `X_ASH_PROOF`, `X_ASH_CONTEXT_ID` constants
- `AshHeaderBundle` type and `ashExtractHeaders()` with case-insensitive lookup, multi-value
  array concatenation, control character rejection, and length enforcement

#### `src/context.ts`
- `AshContext` type, `AshContextStore` interface for pluggable backends
- `AshMemoryStore` class — Map-based in-memory store with configurable TTL, auto-cleanup timer
  (unref'd), atomic `consume()` with one-time-use guarantee (`CTX_NOT_FOUND` / `CTX_EXPIRED` /
  `CTX_ALREADY_USED`), and `destroy()` for graceful shutdown

#### `src/scope-policy.ts`
- `ScopePolicy`, `ScopePolicyMatch` types
- `AshScopePolicyRegistry` class — register/match/has/clear with three pattern types:
  exact (`POST /api/users`), param (`POST /api/users/:id`), wildcard (`GET /api/*`)
- Match priority: exact (3) > param (2) > wildcard (1)
- Validation: max 512 chars, max 8 wildcards, null byte + control char rejection

#### `src/build-request.ts`
- `ashBuildRequest()` — 7-step build orchestrator (validate → normalize → hash → derive → proof → result)
- Auto-detect mode: scope-only → scoped, previousProof → unified, neither → basic
- Result includes `destroy()` that zeros sensitive closure variables

#### `src/verify-request.ts`
- `ashVerifyRequest()` — 9-step verify orchestrator (extract → validate → normalize → hash → compare → verify → result)
- Errors returned as `{ ok: false, error }`, never thrown
- Non-AshError exceptions wrapped in `AshError.internalError()`

#### `src/middleware/types.ts`
- `AshMiddlewareOptions` — store, scopeRegistry, maxAgeSeconds, clockSkewSeconds, onError, extractBody
- `AshRequestMeta` — verified, contextId, mode, timestamp, binding

#### `src/middleware/express.ts`
- `ashExpressMiddleware(options)` — Express middleware factory
- Flow: extract context ID → consume from store → verify request → attach `req.ash` → `next()`
- Custom error handler via `onError`, custom body extraction via `extractBody`

#### `src/middleware/fastify.ts`
- `ashFastifyPlugin(fastify, options)` — Fastify async plugin
- `decorateRequest('ash', null)` + `addHook('onRequest', handler)`
- Same verify flow and JSON error format as Express middleware

#### `src/index.ts`
- Updated barrel export with all Phase 2 public API

### Testing — Phase 2 (2026-02-13)

302 new tests across 8 test files.

#### `tests/unit/phase2/headers.test.ts` (35 tests)
- PT: header injection, control characters, oversized values
- AQ: missing/empty/multi-value headers, case insensitivity
- SA: constant correctness, completeness
- FUZZ: random header names/values, Unicode

#### `tests/unit/phase2/context.test.ts` (28 tests)
- PT: double consume, expired reuse, ID guessing
- AQ: TTL boundary, lifecycle, cleanup timing, destroy
- SA: one-time guarantee, no secret in errors, memory cleanup
- FUZZ: random IDs, rapid create/expire

#### `tests/unit/phase2/scope-policy.test.ts` (31 tests)
- PT: pattern injection, null bytes, traversal
- AQ: exact/wildcard/param matching, no-match, clear, priority
- SA: validation limits, ordering
- FUZZ: random patterns, many registrations

#### `tests/unit/phase2/build-request.test.ts` (24 tests)
- PT: tampered inputs, mode confusion
- AQ: all 3 modes, empty body, edge timestamps
- SA: step ordering, destroy zeroing
- FUZZ: random inputs

#### `tests/unit/phase2/verify-request.test.ts` (23 tests)
- PT: tampered body, wrong binding, expired timestamp, forged proof
- AQ: all 3 modes, missing fields, edge timestamps
- SA: error per step, result format
- FUZZ: partial valid inputs

#### `tests/unit/phase2/middleware-express.test.ts` (16 tests)
- PT: bypass attempts, missing headers
- AQ: all options, custom error handler, body modes
- SA: error format, no secret leak, status codes
- FUZZ: random request objects

#### `tests/unit/phase2/middleware-fastify.test.ts` (15 tests)
- PT: same as Express
- AQ: plugin registration, decoration, hook ordering
- SA: same as Express
- FUZZ: random request objects

#### `tests/unit/phase2/comprehensive-phase2.test.ts` (130 tests)
Cross-cutting comprehensive security tests for all Phase 2 modules:
- Headers injection/smuggling (Unicode, encoding, multi-value attacks)
- Context store security (race conditions, TTL boundary, ID enumeration)
- Scope policy pattern attacks (traversal, injection, wildcard abuse)
- Build request determinism and mode detection
- Verify request attack vectors (replay, tamper, timing)
- Express middleware security (bypass, error handling, body extraction)
- Fastify plugin security (same as Express)
- Cross-module integration (full E2E lifecycle)
- FUZZ adversarial (random inputs across all modules)

### Testing (Comprehensive Security & Property-Based — 2026-02-12)

Added 207 new tests across two test files, bringing total test count from 433 to **640 tests**
(all passing, 0 failures).

#### `tests/unit/property-based.test.ts` (50 tests)
Property-based/fuzz tests using fast-check for all SDK invariants:
- **Hash output invariants** — SHA-256 length/format, determinism, avalanche effect
- **JSON canonicalization properties** — Idempotence, key sorting, whitespace removal, -0→0,
  deep nesting stability, Unicode NFC normalization
- **Query canonicalization** — Idempotence, key sorting, percent encoding, plus-as-literal,
  fragment stripping, empty key/value handling
- **Binding normalization** — Format `METHOD|PATH|QUERY`, path traversal resolution, method
  case sensitivity, double-slash collapse
- **Proof roundtrip** — Build+verify cycle with arbitrary valid inputs
- **Scoped proof invariants** — Scope hash determinism, field order independence, scope
  included in HMAC message
- **Unified proof invariants** — Chain hash derivation, scoped+chained combinations
- **Timing-safe comparison** — Equality reflexivity, inequality detection, length mismatch
- **Validation boundaries** — Nonce length sweep (0-600), timestamp format, context ID rules
- Custom arbitraries: valid nonces, context IDs, timestamps, paths, methods, queries, body
  hashes, and scope fields

#### `tests/unit/comprehensive-security.test.ts` (157 tests)
Security-focused tests covering attack vectors and edge cases:
- **Unicode edge cases** — Surrogate pairs, combining marks, BOM, RTL override, zero-width
  joiners, homoglyph confusion, fullwidth injection, Unicode whitespace
- **Protocol attack vectors** — Replay attacks, timing analysis, proof component injection,
  path traversal, query parameter pollution, method override, header injection
- **Exhaustive error paths** — All 15 `AshErrorCode` values with correct HTTP status codes
  (450-486, 415, 500), error message content, unique status verification
- **Boundary conditions** — Nonce at min/max (32/512 hex chars), empty body hash, binding
  length limits, timestamp extremes (Y2K38, year 3000)
- **Cross-function integration** — Proof→verify pipeline, scoped proof with extraction,
  unified proof chain consistency, body hash in proof binding
- **Advanced canonicalization** — JSON (nested objects, arrays, special floats, emoji keys,
  null/boolean), query (encoded delimiters, Unicode values, empty params), binding (all methods,
  complex paths, encoded queries), scope (field deduplication, nested paths, array notation)
- **HTTP status code verification** — All 15 error codes map to correct unique HTTP statuses

## [1.0.0] - 2026-02-12

### Added
- Initial release of `@3maem/ash-node-sdk` v1.0.0
- Fresh rebuild of ASH Node.js SDK — zero external dependencies
- 134/134 conformance vectors passing
- 433 tests (all passing)
- Pure ESM + CJS dual build via tsup
- Complete ASH protocol implementation:
  - HMAC-SHA256 proof generation and verification
  - RFC 8785 JSON canonicalization (JCS)
  - Query string canonicalization with percent encoding
  - Request binding normalization (`METHOD|PATH|QUERY`)
  - Scoped proof support with field extraction
  - Unified proof support with request chaining
  - Timing-safe constant-time comparison
  - CSPRNG nonce generation
  - Input validation (nonce, timestamp, context ID)
  - 15 typed error codes with HTTP status mapping
