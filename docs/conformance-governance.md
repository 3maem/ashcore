# ASH Conformance Governance

## Purpose

This document defines the rules that govern the ASH conformance suite. These rules are non-negotiable. They exist to prevent behavioral divergence across SDKs and to ensure that the conformance vectors remain a single source of truth.

## Definitions

- **Conformance vectors**: The set of test vectors in `tests/conformance/vectors.json` with hardcoded expected outputs generated from the Rust reference implementation.
- **Behavioral change**: Any change that alters the output of a conformance-tested operation given the same input. This includes changes to canonical output, hash input format, error codes, HTTP status codes, and enforcement limits.
- **ash_version**: The version string in `vectors.json` that binds vectors to a specific Rust core behavior.

## Rules

### 1. Version Bump Trigger

Any behavioral change requires an `ash_version` increment. Examples:

- Canonical JSON output changes for any input
- Query/path/binding normalization output changes
- HMAC message format changes (new delimiters, new fields, domain prefixes)
- Error code or HTTP status code changes
- Enforcement limit changes (max depth, max payload size, etc.)
- Hash algorithm changes

Non-behavioral changes do NOT require a version bump:

- Internal refactors that preserve identical outputs
- Performance optimizations
- Code cleanup, documentation, or comment changes
- Adding new test coverage for existing behavior

### 2. Regeneration Process

When a version bump occurs:

1. Increment `ash_version` in the vector generator
2. Regenerate `vectors.json` from the Rust reference implementation (`cargo run --bin generate_vectors`)
3. Run all SDK conformance runners — every SDK must pass all vectors
4. All runners green — merge allowed
5. Any runner red — merge blocked until the SDK is fixed

No exceptions. No "we'll fix it later" merges.

### 3. Vector Immutability

Once vectors for a given `ash_version` are published (tagged in a release), they are immutable. They must not be modified, reordered, or removed.

To change expected behavior, create new vectors under a new `ash_version`.

### 4. Vector ID Stability

Vector IDs (e.g., `json-001`, `error-005`) are permanent. An ID must never be reused across versions to refer to different behavior. If a vector is retired, its ID is retired with it.

### 5. Reference Implementation

The Rust crate (`packages/ashcore`) is the reference implementation. All expected outputs in `vectors.json` are generated from Rust. When Rust behavior and another SDK disagree, Rust is correct and the other SDK must be fixed.

This does not mean Rust is permanently privileged — it means there is exactly one source of truth at any given time, and today that source is the Rust crate.

### 6. New Vector Addition

New vectors may be added without a version bump **only if** they test existing behavior that was previously untested. The expected output must match what the current Rust crate already produces.

Adding vectors that test new behavior (new operations, new edge cases introduced by code changes) requires a version bump.

### 7. SDK Conformance Runners

Every SDK must maintain a conformance runner that:

- Reads `tests/conformance/vectors.json`
- Tests every vector against the SDK's implementation
- Asserts exact match on expected outputs (byte-identical)
- Asserts exact match on error `code` and `http_status` for error vectors

Current runners:

| SDK | Runner |
|-----|--------|
| Rust | `packages/ashcore/tests/conformance_suite.rs` |
| Node.js | `packages/ash-node-sdk/tests/conformance.test.ts` |

### 8. Exceptions

There are no exceptions to rules 1-4. If a situation arises that seems to require an exception, it means the rules need to be updated — not bypassed. Rule changes require explicit discussion and documentation in this file with a clear rationale.

## Version History

| Date | Change |
|------|--------|
| 2026-02-07 | Initial governance document — ash_version 1.0.0, 134 vectors |
| 2026-02-13 | Updated for v1.0.0 — 2 active SDKs (Rust, Node.js), removed legacy SDK runners |
