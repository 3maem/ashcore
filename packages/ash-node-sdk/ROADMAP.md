# ASH Node SDK — Roadmap

## Phase 1: Layer 1 — Pure Crypto (v1.0.0) [COMPLETE]

Zero-dependency TypeScript library with byte-identical output to Rust ashcore.

- 12 source files (constants, errors, types, validate, compare, hash, canonicalize, binding, proof, proof-scoped, proof-unified, index)
- 134/134 conformance vectors passing
- 640 total tests (conformance + PT + security audit + QA + bugs + logical errors + property-based + comprehensive security)
- CJS + ESM + DTS output via tsup

### Phase 1.1: Comprehensive Test Expansion [COMPLETE]

- Property-based tests (50 tests) — fast-check fuzz testing for all invariants
- Comprehensive security tests (157 tests) — Unicode edges, protocol attacks, error paths, boundary conditions
- Total: 433 → 640 tests, all passing

## Phase 2: Layer 2 — Server Integration (v1.1.0) [COMPLETE]

Express/Fastify middleware, context lifecycle management, and request orchestration.
Zero new runtime dependencies — Express and Fastify are peer deps via duck-typing.

- 9 new source files (headers, context, context-redis, scope-policy, build-request, verify-request, middleware/types, middleware/express, middleware/fastify)
- 302 new tests across 8 test files + 253 comprehensive tests (1235 total, 20 test files)
- Redis context store adapter (`AshRedisStore`) with atomic Lua consume
- Integration examples (Express + Fastify)
- README with full API documentation
- CJS + ESM + DTS output, 88.8 KB packed

### Sub-phase 2.1: Headers Module [COMPLETE]
- `headers.ts` — `X_ASH_*` header name constants, `AshHeaderBundle` type, `ashExtractHeaders()`
- Case-insensitive lookup, multi-value array concatenation, control char rejection, length enforcement

### Sub-phase 2.2: Context Store [COMPLETE]
- `context.ts` — `AshContext` type, `AshContextStore` interface, `AshMemoryStore` class
- Map-based in-memory store with configurable TTL, auto-cleanup via `setInterval` (unref'd)
- Atomic consume with one-time-use guarantee (CTX_NOT_FOUND / CTX_EXPIRED / CTX_ALREADY_USED)

### Sub-phase 2.3: Scope Policy Registry [COMPLETE]
- `scope-policy.ts` — `ScopePolicy`, `ScopePolicyMatch`, `AshScopePolicyRegistry` class
- Pattern types: exact (`POST /api/users`), param (`POST /api/users/:id`), wildcard (`GET /api/*`)
- Match priority: exact > param > wildcard
- Validation: max 512 chars, max 8 wildcards, null byte + control char rejection

### Sub-phase 2.4: Build & Verify Orchestrators [COMPLETE]
- `build-request.ts` — `ashBuildRequest()` 7-step pipeline (validate → normalize → hash → derive → proof → result with destroy())
- `verify-request.ts` — `ashVerifyRequest()` 9-step pipeline (extract → validate → normalize → hash → compare → verify → result)
- Auto-detect mode: scope-only → scoped, previousProof → unified, neither → basic
- Verify returns `{ ok, error?, meta? }` — errors caught per step, never thrown

### Sub-phase 2.5: Express Middleware [COMPLETE]
- `middleware/express.ts` — `ashExpressMiddleware(options)` factory
- Flow: extract context ID → consume from store → verify request → attach `req.ash` meta → next()
- Custom error handler via `onError`, custom body extraction via `extractBody`
- JSON error response: `{ error, message, status }`

### Sub-phase 2.6: Fastify Plugin [COMPLETE]
- `middleware/fastify.ts` — `ashFastifyPlugin(fastify, options)` async plugin
- `decorateRequest('ash', null)` + `addHook('onRequest', handler)`
- Same verify flow and error format as Express middleware

### Phase 2.7: Production Readiness [COMPLETE]
- `context-redis.ts` — `AshRedisStore` (Redis-backed `AshContextStore`, atomic Lua consume, TTL via EXPIRE)
- `examples/express-example.ts` — full client→server Express integration example
- `examples/fastify-example.ts` — full client→server Fastify integration example (basic + scoped)
- `README.md` — comprehensive API documentation, flow diagram, error table
- `package.json` — v1.1.0, peerDependencies, keywords, prepublishOnly script
- 36 new Redis store tests (PT/AQ/SA/FUZZ)

### Phase 2.8: Comprehensive Production Testing [COMPLETE]
- `comprehensive-production.test.ts` — 123 tests across 3 sections
- Section 1: Redis store deep security (59 tests) — client failures, Lua manipulation, key injection, JSON deser attacks, MemoryStore parity
- Section 2: E2E integration lifecycle (40 tests) — Express + Fastify full flows, replay detection, tamper detection, scoped mode, Redis+middleware E2E
- Section 3: Barrel export & package correctness (24 tests) — all exports verified, AshErrorCode completeness, package.json validation
- Total: 1235 tests across 20 test files, all passing

## Phase 3: Developer Experience (v1.2.0) [COMPLETE]

CLI tool and debug trace mode for proof generation, verification, and debugging.
Zero new runtime dependencies — Node.js `parseArgs` is built-in since Node 18.3.

- 2 new source files (`debug.ts`, `cli.ts`)
- CLI with 7 commands: `build`, `verify`, `hash`, `derive`, `inspect`, `version`, `help`
- Debug trace functions: `ashBuildRequestDebug()`, `ashVerifyRequestDebug()`, `ashFormatTrace()`
- ~138 new tests across 3 test files (debug, CLI, comprehensive cross-cutting)
- Sensitive data REDACTED in all trace output
- Exit codes: 0 (success), 1 (invalid proof), 2 (usage error), 3 (internal error)

### Phase 3.1: Migration Guide [TODO]
- Migration guide from legacy SDK

### Phase 3.2: Repository Cleanup [COMPLETE]
- Removed all legacy SDK references (Go, Python, PHP, WASM) across 28 files
- CI workflows, docs, templates, config, scripts all updated for Rust + Node.js only
- Zero legacy references remaining (verified by exhaustive grep)

## Phase 4: Ecosystem

### Phase 4.1: Publish to npm [TODO]
- Publish `@3maem/ash-node-sdk` to npm
- Verify package contents, exports map, peer deps

### Phase 4.2: Publish ashcore to crates.io [TODO]
- `cargo publish` for `ashcore`
- Verify crate metadata, features, dependencies

### Phase 4.3: Cross-SDK Integration Test Harness [TODO]
- Automated cross-SDK conformance verification
