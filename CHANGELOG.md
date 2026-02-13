# Changelog

All notable changes to the ASH SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Testing

#### Comprehensive Test Expansion (2026-02-12)
Added 321 new tests across both packages, bringing total test counts to **2,035** (ashcore)
and **640** (ash-node-sdk). All tests passing with zero regressions.

- **ashcore** (`tests/protocol_invariants_comprehensive.rs`): 114 new protocol invariant tests
  across 14 modules — proof mutation (every byte of every component), timing-safe byte matrix,
  scoped Unicode interaction (NFC/NFD, CJK, emoji, RTL), binding/query cross-tests, error mode
  analysis, state machine compliance (5-step chains), no-panic verification (garbage/null inputs),
  cross-function integration (uniqueness, idempotence, determinism), JSON canonicalization advanced
  (-0, scientific notation, deep nesting, duplicate keys), binding normalization advanced,
  hash properties, validation edge cases, error code classification (unique HTTP statuses),
  and concurrent safety (10-20 threads).

- **ash-node-sdk** (`tests/unit/property-based.test.ts`): 50 new property-based tests using
  fast-check — hash output invariants, JSON/query/binding canonicalization properties, proof
  roundtrip verification, scoped/unified proof invariants, timing-safe comparison, and validation
  boundary sweeps with custom arbitraries.

- **ash-node-sdk** (`tests/unit/comprehensive-security.test.ts`): 157 new security tests —
  Unicode edge cases (surrogate pairs, combining marks, BOM, RTL override, zero-width), protocol
  attack vectors (replay, timing, injection, path traversal), exhaustive error paths (all 15 error
  codes with correct HTTP statuses), boundary conditions, cross-function integration, and advanced
  canonicalization coverage.

### Added
- **`packages/ash-wasm-sdk`**: Stub package (`Cargo.toml` + `src/lib.rs`) to unblock workspace
  compilation. Implementation pending.

### Security

#### ashcore Verification Review (2026-02-12)
Second-pass line-by-line review of all 15 source files (~9,800 lines) in `ashcore/src`.
No new issues found. All prior audit fixes verified correct. Code confirmed production-ready.

#### ashcore Deep Audit (2026-02-12)
Line-by-line audit of all 15 source files in `ashcore/src`. Fixed 3 HIGH, 11 MEDIUM,
8 LOW findings. 1,919 tests pass, zero regressions. See `packages/ashcore/CHANGELOG.md`
for full details.

- **HIGH** H1: RFC 8785 float formatting — custom ES6-compliant JCS serializer replaces `serde_json::to_string()`
- **HIGH** H2: `canonical_payload` leaked in `BuildProofInput` Debug output — now redacted
- **HIGH** H3: Missing scoped/unified verify orchestrators — added `verify_incoming_request_scoped()` and `verify_incoming_request_unified()`
- **MEDIUM** M1–M11: UTF-16 key sort, `UnifiedProofResult` zeroization, panic-safe `Zeroizing` wrappers, IPv4-mapped IPv6 normalization, wildcard match arm safety, poison recovery, JSON node count guard, comma-concatenated header detection, XOR accumulation in timing normalization, SEC-013 inverse check

#### Previous
- **HIGH** BUG-087: Reject null bytes in percent-decoded paths — `%00` passes through decode and could cause C-string truncation in downstream systems
- **HIGH** BUG-088: Reject control characters (< 0x20, 0x7F) in percent-decoded paths — encoded forms like `%0A` could enable log injection or header splitting
- **MEDIUM** BUG-089: Redact `nonce` in `BuildProofInput` Debug output — prevents accidental key material exposure in logs
- **MEDIUM** BUG-090: Redact `expected_proof` and `actual_proof` in `VerifyInput` Debug output — prevents proof leakage in logs
- **MEDIUM** BUG-091: Redact `nonce` and `proof` in `HeaderBundle` Debug output — prevents credential exposure in middleware logs
- **MEDIUM** BUG-092: Redact `nonce` and `previous_proof` in `BuildRequestInput` Debug output
- **MEDIUM** BUG-093: Reject whitespace-only required headers — `"   "` trimmed to `""` now returns `HdrMissing` instead of passing empty value downstream
- **MEDIUM** BUG-094: Apply NFC normalization to Device, Session, Tenant, and Custom binding types — previously only User was normalized, causing cross-platform binding mismatches on macOS (NFD) vs Linux (NFC)
- **LOW** BUG-095: Fix off-by-one in JSON recursion depth check — `depth > 64` allowed 65 levels (0..=64); changed to `depth >= 64` for exactly 64 levels (0..63)
- **LOW** BUG-096: Add query parameter count limit (1024) — prevents DoS via sort amplification with millions of parameters; applied to both `ash_canonicalize_query` and `ash_canonicalize_urlencoded`
- **LOW** BUG-097: Zeroize `scope_hash` and `chain_hash` in `BuildRequestResult::drop()` — these are derived from client secret and could aid proof reconstruction
- **LOW** BUG-098: Reject null bytes in scope policy binding patterns — prevents regex truncation and overly permissive matching
- **LOW** BUG-099: Reject empty field names and field names with control characters in scope policy registration — prevents log injection and no-op field extraction

### Resolved Known Limitations
- **H-3 (UTF-16 sort order)**: **FIXED.** JSON key sorting now uses UTF-16 code unit order per RFC 8785 Section 3.2.3 via `cmp_utf16_code_units()`. Previously used Rust's native UTF-8 byte order which diverged for supplementary characters (U+10000+).
- **H-4 (float delegation to serde_json)**: **FIXED.** Custom JCS serializer (`jcs_serialize_value`) with ES6-compliant float formatting via `es6_format_number()` using the `ryu` crate. Correctly outputs `1e+21` instead of ryu's `1e21`.

- **MEDIUM**: Fixed WASM scope CSV parsing not trimming whitespace — `"field1, field2"` produced `" field2"` causing scope hash mismatch
- **MEDIUM**: Fixed Go regex cache (`sync.Map`) growing unbounded — DoS via many unique binding patterns; added `maxRegexCacheSize` (1000) with atomic counter and full-clear eviction
- **MEDIUM**: Fixed PHP `canonicalizePayload()` missing JSON depth limit — `json_decode` without depth parameter bypassed the 64-depth limit enforced by `Canonicalize::ashParseJson()`
- **MEDIUM**: Fixed Python `ash_build_proof_unified()` not validating timestamp format — allowed malformed (non-digit, leading-zero) timestamps; now calls `ash_validate_timestamp_format()` matching `ash_build_proof_hmac()`

### Fixed
- Fixed WASM `.unwrap()` on `serde_json::to_string()` — replaced with `.expect()` for clearer panic messages under memory pressure
- Fixed Rust compiler warnings for unused `MIN_NONCE_HEX_CHARS` and `MAX_NONCE_LENGTH` constants in `proof.rs` — added `#[allow(dead_code)]` (canonical copies in `validate.rs`)
- Fixed Node.js vitest config excluding `src/**/*.test.ts` — 26 test files (1100+ tests) were not being run; changed `include` to cover both `tests/` and `src/` directories


