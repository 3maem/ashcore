# Changelog

All notable changes to the `ashcore` package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed (2026-02-14)
- Updated `lib.rs` crate-level documentation: replaced "WASM Compatible" feature with
  "Zero Dependencies" to reflect current architecture (WASM SDK was removed)

### Security (Verification Review — 2026-02-12)

Second-pass line-by-line review of all 15 source files (~9,800 lines) in `ashcore/src`.
No new bugs, security issues, or logic errors found. All prior audit fixes (3 HIGH,
11 MEDIUM, 8 LOW) verified correct. Confirmed: input validation at all boundaries,
constant-time comparison integrity, secret zeroization on all exit paths, Debug
redaction coverage, UTF-16 key ordering per RFC 8785, and ES6 float formatting.

### Security (Deep Audit — 2026-02-12)

Line-by-line audit of all 15 source files in `ashcore/src` identified and fixed
3 HIGH, 11 MEDIUM, and 8 LOW findings. 1,919 tests pass with zero regressions.

#### HIGH

- **H1 — RFC 8785 float formatting** (`canonicalize.rs`): `serde_json::to_string()`
  delegates float formatting to ryu, which produces `1e21` for exponential notation.
  RFC 8785 Section 7.2.2 mandates ES6 `Number.prototype.toString()` which requires
  `1e+21` (explicit `+` sign). Implemented custom `jcs_serialize_value()` /
  `jcs_write_value()` / `es6_format_number()` using the `ryu` crate with exponent
  fixup. Integer types are checked first (`as_i64` / `as_u64`) to preserve precision
  for values > 2^53. Added `ryu` as explicit workspace dependency.

- **H2 — Payload leaked in Debug** (`types.rs`): `BuildProofInput`'s derived `Debug`
  impl printed `canonical_payload` in full. In panic backtraces or error logs, this
  could expose the entire request body. Now redacted as `[REDACTED]`. Also added
  `skip_deserializing` to `StoredContext.nonce` to prevent nonce injection via
  deserialization.

- **H3 — Verify orchestrator gap** (`verify.rs`): `build_request_proof()` supports
  basic, scoped, and unified proof modes, but `verify_incoming_request()` only handled
  basic proofs. Added `verify_incoming_request_scoped()` and
  `verify_incoming_request_unified()` orchestrators with full header extraction,
  timestamp/nonce validation, binding normalization, body hash comparison, and
  scope/chain verification. Exported from `lib.rs`.

#### MEDIUM

- **M1 — UTF-16 key sort order** (`canonicalize.rs`): RFC 8785 Section 3.2.3 requires
  JSON object keys sorted by UTF-16 code unit order. Rust's default string comparison
  uses UTF-8 byte order, which differs for supplementary characters (U+10000+).
  Implemented `cmp_utf16_code_units()` using `str::encode_utf16()` iterators.
  **Removes the H-3 Known Limitation from root CHANGELOG.**

- **M2 — UnifiedProofResult not zeroized** (`proof.rs`): `UnifiedProofResult` contains
  `proof` and `chain_hash` fields derived from the client secret. Added `Drop` impl
  that zeroizes both fields on drop. Build.rs updated to use `std::mem::take()` to
  extract values before drop.

- **M3 — Nonce zeroization gap** (`proof.rs`): In `ash_derive_client_secret()`, the
  lowercased nonce (`nonce_key`) was not zeroized on panic paths. Wrapped in
  `Zeroizing::new()` for automatic cleanup. Also wrapped the HMAC message in
  `Zeroizing`.

- **M4 — Client secret panic-safety** (`proof.rs`, `build.rs`, `verify.rs`): All
  `client_secret` and `expected_proof` variables across 6 functions now use
  `Zeroizing<String>` wrappers instead of manual `.zeroize()` calls. Manual zeroize
  is skipped on panic unwind; `Zeroizing` runs in `Drop` which executes on all exit
  paths.

- **M5 — IPv4-mapped IPv6** (`binding.rs`): `::ffff:192.168.1.1` and `192.168.1.1`
  are the same address but produced different bindings. Added
  `Ipv6Addr::to_ipv4_mapped()` normalization to collapse IPv4-mapped IPv6 to plain
  IPv4.

- **M6 — Wildcard match arm** (`binding.rs`): The `_` catch-all in
  `ash_normalize_binding_value()` bypassed NFC normalization for Device/Session/
  Tenant/Custom types. Replaced with explicit variant listing so new `BindingType`
  variants trigger a compiler error. Removed unreachable dead code block with
  `#[allow(unreachable_code)]`.

- **M7 — Poison recovery clears registry** (`scope_policies.rs`): When recovering
  from a poisoned `RwLock` write guard, the registry is now cleared rather than
  leaving it in a potentially corrupt state from a panicked prior write.

- **M8 — JSON node count estimator** (`canonicalize.rs`): Added
  `count_json_nodes()` pre-canonicalization check to reject payloads with excessive
  node counts before entering the recursive canonicalization loop.

- **M9 — Comma-concatenated headers** (`headers.rs`): Some HTTP frameworks merge
  duplicate headers with commas per RFC 7230 Section 3.2.2. A single header value
  containing commas for `x-ash-ts`, `x-ash-nonce`, `x-ash-proof`, or
  `x-ash-body-hash` now returns `HdrMultiValue` error, preventing bypass of the
  multi-value check.

- **M10 — AND convergence in dummy loop** (`compare.rs`): The timing-normalization
  dummy loop in the oversized-input rejection path used AND accumulation
  (`sink = sink & ...`), which converges to 0 after the first mismatch, creating
  a detectable fixed-point pattern. Changed to XOR accumulation.

- **M11 — SEC-013 inverse check** (`proof.rs`): `ash_verify_proof_scoped()` and
  `ash_verify_proof_unified()` checked that `scope_hash` is empty when `scope` is
  empty, but not the inverse. A non-empty `scope` with empty `scope_hash` now returns
  `Err(ScopeMismatch)` instead of silently comparing against an empty hash.

#### LOW

- **L7** (`build.rs`): `BuildRequestResult::Drop` now also zeroizes `binding` and
  `timestamp` — binding is an input to secret derivation.

- **L9** (`headers.rs`): Added `MAX_HEADER_VALUE_LENGTH` (4096 bytes) check in
  `get_one()` to reject oversized header values before processing.

- **L12** (`types.rs`): Added `skip_deserializing` to `StoredContext.nonce` to
  prevent nonce injection via JSON deserialization.

- **L14** (`canonicalize.rs`): `ash_canonicalize_urlencoded()` now strips fragment
  (`#...`) and leading `?` from input before parsing.

- **L15** (`compare.rs`): Dummy comparison loop now accesses real input data
  (`std::hint::black_box(a[idx])`) to match cache/memory access patterns of the
  normal comparison path, reducing timing distinguishability.

- **L16/L17** (`scope_policies.rs`): Pattern strings and binding values with control
  characters (bytes < 0x20 or 0x7F) are now rejected during scope policy matching.

### Fixed
- **BUG-069** (Security): Optimizer could eliminate timing-safe dummy work in
  `ash_timing_safe_equal()` — When inputs exceed `MAX_COMPARE_LENGTH`, the rejection path
  performs `FIXED_ITERATIONS` of dummy constant-time work to prevent timing side-channels.
  The accumulator variable was prefixed with `_`, allowing LLVM to optimize it away entirely.
  Now uses `std::hint::black_box(sink)` to force the optimizer to preserve the work.

- **BUG-070** (Security): `StoredContext.nonce` was serializable via `skip_serializing_if` —
  The `Option::is_none` guard meant `Some(nonce)` values were included in JSON output. Changed
  to unconditional `#[serde(skip_serializing)]` so the nonce is never emitted regardless of
  presence. Deserialization preserved via `#[serde(default)]`.

- **BUG-071** (Correctness): `had_query` flag in `ash_normalize_binding_enriched()` was
  computed from raw input (`!query.trim().is_empty()`) instead of the canonical output
  (`!parsed.canonical_query.is_empty()`). A query string that normalizes to empty (e.g.,
  `"?#fragment"`) would set `had_query: true` despite the canonical query being empty.

- **BUG-072** (Correctness): `get_optional_one()` in `headers.rs` returned `Some("")` for
  whitespace-only header values instead of `None`. Callers expecting `None` for absent/empty
  headers would incorrectly treat whitespace-only values as present.

- **BUG-073** (Correctness): `CtxAlreadyUsed` error code was not marked retryable despite its
  doc comment stating "consider retry with a new context" for distributed systems. In multi-node
  deployments, replication lag can cause false positives — now returns `true` from `retryable()`.

- **BUG-074** (Security): Method validation in `ash_normalize_binding()` did not reject the
  pipe character `|`, which is the binding format delimiter (`METHOD|PATH|QUERY`). A method
  containing `|` could inject extra binding segments, potentially causing the verifier to parse
  a different path/query than intended. Now rejects methods containing `|`.

- **BUG-075** (Security): Method validation did not reject control characters (bytes < 0x20 or
  0x7F). Control characters in HTTP methods are invalid per RFC 7230 and could cause parsing
  ambiguities between client and server binding construction. Now rejected early.

- **BUG-076** (Correctness): Total binding length was not validated after format construction in
  `ash_normalize_binding()`. A long path + query could produce a binding exceeding
  `MAX_BINDING_VALUE_LENGTH` (8192 bytes). Now checked after `format!("{}|{}|{}", ...)`.

- **BUG-077** (Design): Removed semicolon `;` from the safe character set in
  `ash_percent_encode_path()`. Semicolons are used as path parameter delimiters in some
  frameworks (e.g., matrix parameters in JAX-RS), so percent-encoding them ensures consistent
  canonical form across all server stacks.

- **BUG-078** (Security): `DEFAULT_CLOCK_SKEW_SECONDS` reduced from 60 to 30 seconds. A 60s
  window is unnecessarily wide for modern systems with NTP synchronization and increases the
  replay attack window. 30s provides adequate tolerance while halving the exposure.

- **BUG-079** (Security): Expected proof strings were not zeroized after verification in
  `ash_verify_proof()`, `ash_verify_proof_with_freshness()`, `ash_verify_proof_scoped()`,
  `ash_verify_proof_unified()`, and `verify_incoming_request()`. The computed HMAC proof
  (equivalent to a MAC tag) persisted in memory after comparison. Now zeroized immediately
  after `ash_timing_safe_equal()`.

- **BUG-080** (Security): HMAC message strings were not zeroized after use in
  `ash_build_proof_scoped()` and `ash_build_proof_unified()`. The concatenated message
  (`timestamp|binding|body_hash|scope_hash`) containing sensitive binding and hash data
  persisted in memory. Now zeroized immediately after `mac.update()`.

- **BUG-081** (Security): `ash_build_proof_scoped()` and `ash_build_proof_unified()` did not
  validate timestamp format, unlike their basic counterpart `ash_build_proof()` (BUG-057).
  Clients could build scoped/unified proofs with malformed timestamps and receive no early
  error. Now calls `ash_validate_timestamp_format()`.

- **BUG-082** (Security): `ash_build_proof_scoped()` and `ash_build_proof_unified()` did not
  enforce `MAX_HASH_PAYLOAD_SIZE` on the JSON body before parsing/hashing. An attacker could
  send arbitrarily large JSON payloads to trigger CPU-bound DoS during canonicalization. Now
  checks size before `ash_canonicalize_json()`.

- **BUG-083** (Correctness): Redundant `.to_ascii_lowercase()` call on `ash_hash_body()` result
  in `ash_build_proof_scoped()` and `ash_build_proof_unified()`. The SHA-256 hex output from
  `ash_hash_body()` is already lowercase — the extra call was harmless but misleading, suggesting
  the hash function might return mixed-case output.

- **BUG-084** (Correctness): `ash_extract_scoped_fields_internal()` did not validate field names
  before processing. Empty field names and names containing the reserved delimiter character
  (U+001F) could cause incorrect scope hash computation. Now rejects both with clear errors.

- **BUG-085** (Security): `BuildRequestResult` struct did not zeroize sensitive fields on drop.
  The `proof`, `body_hash`, and `nonce` fields persisted in memory after the struct was dropped.
  Added manual `Drop` implementation that zeroizes all three fields.

- **BUG-086** (Correctness): `ScopePolicyRegistry::get_all()` returned `BTreeMap<String, Vec<String>>`
  which sorts keys alphabetically, losing registration order. Since "first registered pattern wins"
  (BUG-006/BUG-067), this made it impossible to inspect actual priority. Changed to return
  `Vec<(String, Vec<String>)>` preserving insertion order. Updated `ash_get_all_scope_policies()`
  and deprecated `get_all_scope_policies()` to match.

### Added (API)
- **`verify_incoming_request_scoped()`** (`verify.rs`): High-level scoped request verification
  orchestrator. Same pipeline as `verify_incoming_request()` with additional scope hash
  validation and scoped proof comparison.
- **`verify_incoming_request_unified()`** (`verify.rs`): High-level unified request verification
  orchestrator. Handles scoped proofs, chained proofs, or both.
- **`VerifyScopedInput`** / **`VerifyUnifiedInput`** (`verify.rs`): Input structs for the new
  verification orchestrators.
- **`ash_timing_safe_equal_fixed_length()`** (`compare.rs`): Exported previously internal
  fixed-length constant-time comparison function. Useful for callers who know both inputs are
  the same length and want to skip the length-normalization overhead.

### Changed
- **`ScopePolicyRegistry::get_all()`**: Return type changed from `BTreeMap<String, Vec<String>>`
  to `Vec<(String, Vec<String>)>` (BUG-086). This is a breaking change for callers that relied
  on `BTreeMap` methods.
- **Testkit** (`testkit.rs`): Added dispatch handlers for `scoped_field_extraction` and
  `unified_proof` conformance vector categories.
- Total test count increased from ~1,772 to **2,035 tests** (all passing, 0 failures)
- **Dependencies**: Added `ryu` crate (v1.0) for ES6-compliant float formatting in JCS serializer

### Testing (Comprehensive Protocol Invariants — 2026-02-12)

Added `tests/protocol_invariants_comprehensive.rs` — 114 new tests across 14 modules,
filling coverage gaps identified by systematic analysis of the existing 32-file test suite.

1. **`exhaustive_proof_mutation`** — Mutate every byte of every component, verify failure
2. **`timing_safe_byte_matrix`** — All 64 byte positions tested for timing consistency
3. **`scoped_unicode_interaction`** — NFC/NFD equivalence, CJK, emoji, RTL, mixed-script
4. **`binding_query_cross_tests`** — Injection via encoded delimiters, fragment stripping
5. **`error_mode_analysis`** — All failures return `Ok(false)`, no distinguishable errors
6. **`state_machine_compliance`** — 5-step chains, scoped+chained unified lifecycle
7. **`no_panic_verification`** — Garbage inputs, empty everything, null bytes, oversized
8. **`cross_function_integration`** — Uniqueness, idempotence, determinism guarantees
9. **`json_canon_advanced`** — -0→0, scientific notation, deep nesting, duplicate keys
10. **`binding_normalization_advanced`** — All methods, case, control chars, null bytes
11. **`hash_properties`** — SHA-256 correctness (NIST vectors), ASCII hex, empty rejection
12. **`validation_edge_cases`** — Nonce boundaries (31/32/512/513), timestamp, context ID
13. **`error_code_classification`** — All codes present, unique HTTP statuses, retryable
14. **`concurrent_safety`** — 10-20 threads for proof gen, hash, canonicalization, verify

### Fixed (Documentation)
- Removed orphaned doc comment `/// Maximum HMAC key length in bytes.` from `proof.rs` that
  was left behind when the associated constant was removed in a prior refactor.
- Fixed deprecated doc reference from `generate_nonce()` to `ash_generate_nonce()` in proof
  module documentation.
- Added doc note to `verify_incoming_request()` clarifying it only handles basic (non-scoped,
  non-unified) proofs.
- Added explanatory comment for null-byte placeholder values in `scope_policies.rs`.

- **BUG-060** (Security): HMAC message not zeroized in `ash_build_proof()` — The `message`
  string (`timestamp|binding|body_hash`) is now zeroized immediately after `mac.update()`.
  Previously, the concatenated proof derivation input persisted in memory after use.

- **BUG-061** (Security): `ash_hash_body()` only enforced size limit via `debug_assert!` —
  In release builds, inputs exceeding 10MB (`MAX_HASH_PAYLOAD_SIZE`) were hashed without
  any limit, enabling CPU-bound DoS. Now returns the SHA-256 of an empty string for oversized
  input in release builds (the proof will fail verification, alerting the caller). For explicit
  error handling, use `ash_hash_body_checked()`.

- **BUG-062** (Security): Random buffer in `ash_generate_nonce()` now uses `Zeroizing<Vec<u8>>`
  wrapper for automatic cleanup on all exit paths. Previously, manual `buf.zeroize()` only
  executed on the success path — if `getrandom` returned an error, the partially-filled buffer
  was not zeroized.

- **BUG-063** (Correctness): IPv6 addresses in `ash_normalize_binding_value()` are now parsed
  and re-serialized to canonical form via `IpAddr::to_string()`. Previously, the raw trimmed
  input was returned, so `2001:0db8::1` and `2001:db8::1` would produce different binding
  values despite being the same address, causing client-server mismatches.

- **BUG-064** (Security): Timing leak in `ash_timing_safe_equal()` for oversized inputs —
  The rejection path now performs dummy constant-time work (FIXED_ITERATIONS iterations) before
  returning `false`. Previously, oversized inputs returned immediately without any work, allowing
  an attacker to distinguish "input too large" from "input compared and mismatched" via timing.

- **BUG-065** (Correctness): Off-by-one in `ash_percent_encode_path()` length check — The size
  check was performed BEFORE writing each character, so a multi-byte UTF-8 character (encoded
  as `%XX%XX%XX`) could push the result up to 9 bytes past `MAX_ENCODED_PATH_LENGTH` after
  passing the pre-write check. Now checked AFTER each character write.

- **BUG-066** (Code Quality): Duplicate header extraction logic between `headers::get_one()`
  and `verify::extract_single_header()` — Made `get_one()` `pub(crate)` and replaced the
  duplicate in `verify.rs`. Both functions had identical BUG-051 logic; now there is a single
  source of truth.

- **BUG-067** (API): `ScopePolicyRegistry::register_many()` uses `BTreeMap` which iterates in
  alphabetical order, not insertion order. Since "first registered pattern wins" (BUG-006), this
  silently reorders pattern priority. Added `register_many_ordered(&[(&str, &[&str])])` method
  and global `ash_register_scope_policies_ordered()` function that preserve caller-specified order.

- **BUG-068** (Modernization): Replaced `lazy_static` with `std::sync::LazyLock` (stable since
  Rust 1.80) for the global scope policy registry and compiled regex patterns in
  `ash_build_safe_regex()`. Removed `lazy_static` dependency from `Cargo.toml`.

- **Test Binding Format** (`types.rs`): Updated `StoredContext` test fixtures from old binding
  format `"POST /api"` to current format `"POST|/api|"`.

- **Documentation** (`errors.rs`): Added distributed systems note to `CtxAlreadyUsed` variant
  explaining that in multi-node deployments, this error may be returned due to replication lag
  rather than an actual replay attack.

### Added (API)
- **`ash_register_scope_policies_ordered()`** (`scope_policies.rs`): New global function for
  registering multiple scope policies in caller-specified order. Essential when pattern priority
  matters (specific patterns must be registered before general wildcards).
- **`ScopePolicyRegistry::register_many_ordered()`**: Instance method counterpart.
  Both exported via `config/mod.rs`.

### Changed
- **Build**: Removed `cdylib` from `crate-type` in `Cargo.toml` — `ashcore` is consumed as
  `rlib` by all dependents. The `cdylib` output was unused and added unnecessary build overhead.
- **Dependencies**: Removed `lazy_static` dependency (replaced by `std::sync::LazyLock`).
- Total test count increased from ~1,768 to **1,771 tests** (all passing, 134/134 conformance vectors)

---

### Added
- **Deep Audit Test Suite** - Added 309 new tests in `tests/deep_audit_tests.rs` (24 modules):
  - Boundary conditions: nonces (31-513 chars), timestamps (Y2K38, year 3000), context IDs (256/257), bindings
  - Canonicalization: JSON (keys, numbers, depth 64/65, size, emoji, NFC), query strings, URL-encoded
  - Proof pipelines: derivation, building, verification, avalanche effect, collision resistance (1,000 hashes)
  - Scoped proofs: roundtrip, strict mode, deduplication, order independence, depth limits
  - Unified/chained proofs: basic, scoped, chained, combined, build_request_proof modes
  - Timing-safe comparison: boundary sizes, no-early-exit timing consistency
  - Binding value normalization: all BindingTypes (IP, User, Device, etc.), NFC, control chars
  - Header extraction: required/optional, case insensitivity, multi-value, control chars
  - Full verify_incoming_request pipeline: valid, tampered body, wrong endpoint
  - Scope policy registry: wildcards, exact vs wildcard priority, Express params, escapes
  - Error types: unique HTTP status codes, serde roundtrip, retryable classification
  - Enriched API: body hash, binding, parse binding, consistency checks
  - Security attacks: SQL injection, path traversal, null bytes, replay, spoofing, DoS
  - Fuzz testing: 5,800+ iterations (2,000 derive_secret + 1,000 JSON + 1,000 query + 500 proof + 300 scoped + 1,000 timing)
  - Performance stress: 10K throughput, 1,000 scope policies, large payloads, 10K hash uniqueness
  - Nonce generation: uniqueness, hex validity, context ID generation
  - Regression tests: BUG-001 through BUG-043, SEC-008/011/014/018/AUDIT-007

- **Comprehensive Test Coverage Expansion** - Added 189 new tests across three test files:
  - `tests/attack_scenarios.rs` (39 tests) - Security attack vector testing:
    - Injection attacks (SQL, command, path traversal, header injection)
    - Encoding attacks (invalid UTF-8, overlong encoding, double encoding, BOM injection)
    - JSON attacks (billion laughs, deep nesting, duplicate keys, parser confusion)
    - Integer overflow attempts (timestamp, array index)
    - Replay attacks (timestamp replay, proof replay across contexts/bindings)
    - Timing attacks (comparison timing, early exit prevention)
    - DoS attacks (slowloris, CPU/memory exhaustion)
    - Spoofing attacks (binding, case, hex case)
    - Side-channel attacks (error message leakage, timing protection)
    - Regex attacks (ReDoS pattern detection)
  - `tests/comprehensive_edge_cases.rs` (120 tests) - Complete edge case coverage:
    - JSON canonicalization edge cases (empty, nesting, emoji, numbers)
    - Query string edge cases (empty, whitespace, special chars)
    - Binding normalization edge cases (methods, paths, encoding)
    - Nonce validation boundaries (all lengths 0-513)
    - Context ID validation (empty, max length, special chars)
    - Timestamp edge cases (year 2038, max values, negative, decimals)
    - Proof generation edge cases (empty inputs, determinism)
    - Scope handling (empty, single/multiple fields, nested paths, array indices)
    - Timing-safe comparison (empty strings, different lengths, max size)
    - Verification edge cases (valid/tampered proofs)
    - Mass fuzzing (3,000+ iterations for nonce, binding, JSON, query)
    - Concurrency stress tests
  - `tests/extreme_boundary_tests.rs` (30 tests) - Extreme boundary testing:
    - String length boundaries (context ID, binding, query)
    - Numeric boundaries (nonce 0-600 hex chars, timestamps, body hash)
    - JSON depth boundaries (nesting limits, array/object nesting)
    - Array index boundaries (0, 1, 9999, 10000, 10001)
    - Scope boundaries (field counts 0-200, name lengths, total length)
    - Pattern matching boundaries (length 0-600, wildcards 0-10)
    - Timestamp age boundaries (negative, max valid, max invalid)
    - Unicode boundaries (all planes, emoji, RTL, combining chars)
    - Memory stress tests (large allocations, many small allocations)
    - Determinism tests (1,000 iteration consistency)

### Fixed
- **Documentation** (`lib.rs`): Fixed awkward sentence fragment in crate-level documentation.
  Changed "This crate uses `#![forbid(unsafe_code)]` to guarantee 100% safe Rust. that ensures..."
  to proper grammar with "while ensuring..."

- **Input Validation** (`lib.rs`): Added explicit ASCII method validation to `ash_normalize_binding_from_url()`.
  Previously this function only validated input size but not method format, delegating to
  `ash_normalize_binding()` which could produce less clear error messages. Now validates
  method is non-empty and ASCII-only before path processing.

- **Path Encoding Safety** (`lib.rs`): Added `MAX_ENCODED_PATH_LENGTH` constant (24KB) and
  size check in `ash_percent_encode_path()` for defense in depth against memory exhaustion.
  This complements existing binding length validation in secret derivation.

- **Array Index Parsing** (`proof.rs`): Updated comment in `ash_parse_all_array_indices()`
  to accurately describe behavior when trailing text follows array notation (e.g., `"items[0]extra"`).
  The function correctly returns empty indices for malformed paths, causing safe fallback
  to non-array field access.

- **BUG-051** (Security): Header control character bypass via trimming — `get_one()` and
  `get_optional_one()` in `headers.rs` (and `extract_single_header()` in `verify.rs`)
  now check for control characters on the **raw** header value BEFORE calling `.trim()`.
  Previously, trailing `\r\n` was silently stripped by `.trim()`, causing the subsequent
  control character check to pass on the already-trimmed value. This masked potential
  CRLF injection at header value boundaries.
- **BUG-052** (Validation): NFC normalization length bypass in `binding.rs` — `User`
  binding type now re-validates length after Unicode NFC normalization. Previously, a
  value exactly at `MAX_BINDING_VALUE_LENGTH` could expand after NFC normalization and
  exceed the limit without being caught.
- **BUG-053** (Security): Silent truncation in `ash_percent_encode_path()` — Now returns
  `Result` and errors when encoded path exceeds `MAX_ENCODED_PATH_LENGTH` instead of
  silently truncating. Silent truncation could allow two different paths to produce the
  same encoded output, enabling binding collision attacks.
- **BUG-054** (Correctness): Fragment not stripped from path in `ash_normalize_binding_from_url()`.
  In HTTP, fragments (`#...`) are never sent to the server, so `/api/users#section` and
  `/api/users` must produce the same binding. Previously, fragments in the path component
  (without a query string) were preserved, causing client-server binding mismatches.
- **BUG-055** (Debug): `VerifyMeta.canonical_query` in `verify.rs` now reports the actual
  canonical query extracted from the binding, not the raw unsorted input query.
- **BUG-056** (Security): Nonce key material (`nonce_owned`) in `ash_derive_client_secret()`
  and random buffer in `ash_generate_nonce()` are now zeroized after use to prevent
  key material from persisting in memory.
- **BUG-057** (Correctness): `ash_build_proof()` now validates timestamp format via
  `ash_validate_timestamp_format()`. Previously, only the verify side validated timestamps,
  so clients could build proofs with malformed timestamps (e.g., "abc", "0123") and get
  no early feedback.
- **BUG-058** (Security): Added `ash_hash_body_checked()` for size-validated body hashing.
  `ash_hash_body()` now includes a `debug_assert` for size limits. Prevents CPU-bound DoS
  when called independently with uncanonicalized input from untrusted sources.
- **BUG-059** (Security): `ContextPublicInfo` and `StoredContext` now use custom `Debug`
  implementations that redact the `nonce` field to prevent accidental exposure in logs.

### Added (API)
- **`ash_hash_body_checked()`** (`proof.rs`): New public function for size-validated body hashing.
  Returns `Result<String, AshError>` and rejects payloads exceeding 10MB (`MAX_HASH_PAYLOAD_SIZE`).
  Exported from `lib.rs` alongside existing `ash_hash_body()`.

### Changed
- Total test count increased from ~1,134 to **1,768 tests** (all passing)
- **Build/Cleanup**: Removed commented-out benchmark configuration from `Cargo.toml`
  (criterion dependency and bench entries for future use)
- **Documentation** (`types.rs`): Clarified `StoredContext::is_expired()` boundary behavior —
  the context is considered expired AT the expiration time (`now_ms >= expires_at`), not only after it.

### Added (Test Coverage)
- **Boundary Tests** - Added 9 new boundary validation tests:
  - `test_binding_length_validated_in_secret_derivation` — Tests MAX_BINDING_LENGTH enforcement
  - `test_normalize_binding_from_url_rejects_unicode_method` — Tests method ASCII validation
  - `test_normalize_binding_from_url_rejects_empty_method` — Tests method non-empty validation
  - `test_normalize_binding_unicode_path_encoding` — Tests Unicode path percent-encoding
  - `test_context_id_unicode_rejected` — Tests Unicode rejection in context IDs
  - `test_scope_max_path_depth` — Tests MAX_SCOPE_PATH_DEPTH handling (32 levels)
  - `test_scope_max_array_index` — Tests array index limit behavior (10,000)
  - `test_scope_max_fields_limit` — Tests MAX_SCOPE_FIELDS enforcement (100 fields)
  - `test_scope_max_array_allocation` — Tests MAX_TOTAL_ARRAY_ALLOCATION limits (10,000 elements)
- **Fragment Stripping Tests** (`lib.rs`) - Added 3 new tests for BUG-054:
  - `test_normalize_binding_from_url_strips_fragment_from_path` — Fragment removed from path-only URL
  - `test_normalize_binding_from_url_strips_fragment_with_query` — Fragment removed when query present
  - `test_normalize_binding_from_url_fragment_only` — Path with only `#` treated as clean path

### Fixed (Test Corrections)
- **`deep_audit_tests.rs`**: `build_proof_body_hash_case_normalized` — Replaced non-numeric
  timestamp `"ts"` with valid `"1700000000"`. Previously passed because `ash_build_proof()`
  did not validate timestamp format; now required after BUG-057 fix.
- **`security_assurance.rs`**: `test_build_proof_deterministic` — Changed millisecond timestamp
  `"1704067200000"` to seconds `"1704067200"`. The millisecond value exceeded `MAX_TIMESTAMP`
  (year 3000 in seconds), which is now enforced on the build side after BUG-057.

## [1.0.0] - 2025-01-01

### Added
- Initial release of ASH v1.0.0
- ASH (Application Security Hash) library implementation
- RFC 8785 compliant JSON canonicalization
- Request integrity verification with server-signed seals
- Anti-replay protection via timestamp validation
- Zero client secrets architecture
- Comprehensive conformance test suite (134 vectors)
- Cross-platform compatibility tests
- Cryptographic property tests (avalanche, collision resistance, entropy)
- Security audit tests (OWASP Top 10 coverage)
- Performance benchmarks
- Cross-platform compatibility

### Security
- Timing-safe comparison for all sensitive operations
- Constant-time proof verification
- Protection against replay attacks
- Binding integrity enforcement
- Scope field isolation
