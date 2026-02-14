# ASH Project — Progress

Last updated: 2026-02-14

## Current State

| Package | Version | Tests | Status |
|---------|---------|-------|--------|
| `ashcore` (Rust) | 1.0.0 | 2,086 | Production-ready |
| `ash-node-sdk` (Node.js) | 1.2.0 | 1,492 | Production-ready |
| **Total** | | **3,578** | |

134/134 conformance vectors passing on both SDKs.

## Active Packages

### `packages/ashcore` — Rust Reference Implementation
- ASH v2.3.5 protocol implementation
- RFC 8785 JSON canonicalization (JCS)
- HMAC-SHA256 proof generation and verification
- Scoped, unified, and chained proof modes
- Deep security audit complete (3 HIGH, 11 MEDIUM, 8 LOW — all fixed)
- Verification review complete (no new issues)

### `packages/ash-node-sdk` — Node.js SDK
- Byte-identical output to Rust ashcore
- Zero runtime dependencies
- **Layer 1**: Pure crypto (proof, hash, canonicalize, binding, validate)
- **Layer 2**: Server integration (Express/Fastify middleware, context stores, scope policies)
- **Layer 3**: Developer experience (CLI tool, debug trace mode)
- CJS + ESM + DTS output via tsup

## Completed Milestones

### Node SDK v1.2.0 — Phase 3: Developer Experience (2026-02-13)
- CLI with 7 commands: `build`, `verify`, `hash`, `derive`, `inspect`, `version`, `help`
- Debug trace: `ashBuildRequestDebug()`, `ashVerifyRequestDebug()`, `ashFormatTrace()`
- Sensitive data REDACTED in all trace output

### Node SDK v1.1.0 — Phase 2: Server Integration (2026-02-13)
- Express + Fastify middleware with duck-typed peer deps
- `AshMemoryStore` (in-memory) and `AshRedisStore` (Redis-backed) context stores
- `AshScopePolicyRegistry` with exact/param/wildcard pattern matching
- `ashBuildRequest()` and `ashVerifyRequest()` orchestrators

### Node SDK v1.0.0 — Phase 1: Pure Crypto (2026-02-12)
- 12 source files, 134/134 conformance vectors
- Property-based + comprehensive security test expansion (640 tests)

### Repository Cleanup (2026-02-14)
- Removed all legacy SDK references (Go, Python, PHP, WASM) across 28 files
- CI workflows, docs, templates, config, scripts updated for Rust + Node.js only
- Zero legacy references remaining (verified by exhaustive grep)

### ashcore Deep Audit + Verification Review (2026-02-12)
- Line-by-line audit of all 15 source files (~9,800 lines)
- 22 findings fixed (3 HIGH, 11 MEDIUM, 8 LOW)
- Second-pass verification confirmed all fixes correct

## Next Steps

### 1. Publish `@3maem/ash-node-sdk` to npm [TODO]
- npm publish for `@3maem/ash-node-sdk` v1.2.0
- Verify package contents, exports map, peer deps

### 2. Publish `ashcore` to crates.io [TODO]
- `cargo publish` for `ashcore` v1.0.0
- Verify crate metadata, features, dependencies

### 3. Migration Guide [TODO]
- Migration guide from legacy `ash-node-sdk` (v2.3.x) to new SDK (v1.x)

### 4. Cross-SDK Integration Test Harness [TODO]
- Automated cross-SDK conformance verification

## Repository Structure

```
ash-main/
  packages/
    ashcore/          — Rust reference implementation
    ash-node-sdk/     — Node.js SDK (v1.2.0)
    sdk-legacy/       — Old SDKs (archived, not maintained)
  examples/
    express/          — Express integration example
  tests/
    conformance/      — Cross-SDK conformance vectors (134)
  docs/
    reference/        — API docs (api-rust.md, api-node.md, error-codes.md, middleware.md)
    security/         — Threat model, security checklist
  .github/
    workflows/        — CI: rust.yml, node.yml, conformance-guard.yml, publish-*, release.yml
```
