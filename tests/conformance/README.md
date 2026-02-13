# ASH Conformance Suite

## Scope

These vectors define expected behavior but do not constitute a formal protocol specification. They are an engineering tool for validating cross-SDK consistency.

## Purpose

`vectors.json` contains **hardcoded expected outputs** generated from the Rust core (the reference implementation). Every vector has an `id`, `description`, `input`, and `expected` with concrete values -- no formulas, no placeholders.

**All expected outputs must match byte-for-byte across all implementations.** Any deviation from the Rust reference output is treated as an SDK defect.

## How to Use

1. Parse `vectors.json` in your SDK's test framework
2. For each vector, run the corresponding operation against your SDK
3. Compare the output to the `expected` value
4. Any mismatch is a conformance failure

### Vector Categories

| Category | What it tests |
|----------|---------------|
| `json_canonicalization` | RFC 8785 JCS canonical JSON |
| `query_canonicalization` | Query string sorting, plus-sign handling |
| `urlencoded_canonicalization` | URL-encoded form data normalization |
| `binding_normalization` | METHOD\|PATH\|QUERY format normalization |
| `body_hashing` | SHA-256 of canonical payloads |
| `client_secret_derivation` | HMAC-SHA256 secret from nonce + context + binding |
| `proof_generation` | End-to-end proof generation and verification |
| `scoped_field_extraction` | Field extraction with dot/bracket notation |
| `unified_proof` | Combined scope + chain proof generation |
| `timing_safe_comparison` | Constant-time comparison correctness |
| `error_behavior` | Error codes and HTTP status for invalid inputs |
| `timestamp_validation` | Timestamp format and freshness rules |

### Vector Structure

**Success vectors:**
```json
{
  "id": "json-001",
  "description": "Basic key sorting",
  "input_json_text": "{\"z\":1,\"a\":2}",
  "expected": "{\"a\":2,\"z\":1}"
}
```

**Error vectors:**
```json
{
  "id": "error-001",
  "description": "Empty nonce rejected",
  "input": { "operation": "derive_client_secret", "nonce": "" },
  "expected_error": { "code": "ASH_VALIDATION_ERROR", "http_status": 485 }
}
```

### Error Matching Rules

- **Normative (must match exactly):** `code` string and `http_status` integer
- **Normative (shape):** error response MUST include keys `{ code, http_status, message }`
- **Non-normative:** content of `message` -- SDKs may use language-appropriate wording

## Versioning

- `vectors.json` is locked to `ash_version: "2.3.5"` and a specific Rust core commit
- Once published, vectors for a given `ash_version` are immutable
- Regeneration requires an `ash_version` increment
- Vector IDs are stable and must not be reused across versions

## Distribution Model

ASH is distributed as SDK libraries, not as a service. The conformance suite validates that distributed SDKs produce identical outputs to the reference. CI validates against locked vectors -- it does not generate them.

## Scope Boundary

Conformance vectors define observable behavior for SDK interoperability and do not define network protocol semantics. Internal implementation details are not constrained by this suite.

## Determinism Rules

- **Encoding:** UTF-8, no BOM, no locale dependency
- **Unicode:** NFC normalization before canonicalization
- **Key sorting:** Per JCS (RFC 8785), codepoint lexicographic order
- **Timestamps:** Seconds only (not milliseconds), digits only, no leading zeros
- **Plus sign:** Literal (never space), encoded as `%2B`
- **Hex output:** Lowercase for hashes/proofs, uppercase for percent-encoding
- **JSON duplicate keys:** `last_wins` semantics

## Parser Requirement

SDKs MUST use a JSON parser that implements `last_wins` for duplicate keys. Parsers that reject duplicates or use `first_wins` are non-conformant.

## Security Notes

- `path_percent_decode` is `decode_all` (including reserved chars like `%2F` -> `/`). This is the locked v2.3.5 behavior, flagged for security review in a future version.
- Current v2.x HMAC inputs do not include domain prefixes beyond delimiter usage. Introducing explicit domain prefixes (e.g., `ASH|proof|`) is a breaking behavioral change requiring a major version bump and regenerated vectors.

## Regenerating Vectors

```bash
cargo run --bin generate_vectors
```

**When to regenerate:**
- Breaking canonicalization change
- Hash input format change
- Protocol-level change (new proof formula, new delimiter)

**When NOT to regenerate:**
- Internal refactors that don't change outputs
- Performance optimizations
- Code cleanup or documentation changes

## SDK Runners

| SDK | Command | Runner File |
|-----|---------|-------------|
| **Rust** | `cargo test --test conformance_suite` | `packages/ashcore/tests/conformance_suite.rs` |
| **Node.js** | `npm test` (in ash-node-sdk) | `packages/ash-node-sdk/tests/conformance.test.ts` |
| **Python** | `pytest tests/test_conformance.py` | `packages/ash-python-sdk/tests/test_conformance.py` |
| **Go** | `go test -run TestConformanceSuite` | `packages/ash-go-sdk/conformance_suite_test.go` |
| **PHP** | `composer test` (in ash-php-sdk) | `packages/ash-php-sdk/tests/ConformanceSuiteTest.php` |
| **WASM** (Rust-native) | `cargo test -p ash-wasm-sdk --test conformance_suite` | `packages/ash-wasm-sdk/tests/conformance_suite.rs` |
| **WASM** (JS-in-Node) | `node packages/ash-wasm-sdk/tests/conformance_wasm.mjs` | `packages/ash-wasm-sdk/tests/conformance_wasm.mjs` |

## SDK-Specific Notes

### Go

- **`AshNormalizeBinding`** is the legacy API. It may auto-fix invalid inputs (e.g., prepending `/` to paths without a leading slash) for backward compatibility.
- **`AshNormalizeBindingStrict`** is the conformance-aligned API. It returns `(string, error)` and rejects invalid inputs (empty method, missing leading slash, non-ASCII method).
- The conformance runner uses `AshNormalizeBindingStrict` for binding normalization vectors.
- Similarly, `AshBuildProofHMACValidated`, `AshHashProofValidated`, and `AshExtractScopedFieldsStrict` are the validating variants used by the conformance runner. The non-validating originals remain for backward compatibility.

### PHP

- **`Canonicalize::ashNormalizeBinding`** is the legacy API. It auto-fixes invalid inputs (e.g., prepending `/`) for backward compatibility.
- **`Canonicalize::ashNormalizeBindingStrict`** is the conformance-aligned API. It throws `ValidationException` for invalid inputs (empty method, missing leading slash, non-ASCII method).
- **`Canonicalize::ashParseJson`** is the conformance entry point for JSON canonicalization. It takes raw JSON text, enforces size (10 MB) and depth (64) limits, and returns canonical output.
- **`Proof::ashBuildProofHmacValidated`**, **`Proof::ashHashProofValidated`**, and **`Proof::ashExtractScopedFieldsStrict`** are the validating variants used by the conformance runner.
- The conformance runner uses strict/validated APIs for all error behavior vectors.

### WASM

- The WASM crate (`ash-wasm-sdk`) provides two API layers:
  - **`native` module:** Pure Rust API returning `Result<T, AshError>`, testable on all platforms
  - **`wasm_bindgen` exports:** Thin JsValue wrappers around the native module for JS consumption
- **Rust-native testing** uses `cargo test` against the `rlib` target via `ash_wasm::native::*` (no wasm-pack needed).
- **Coverage:** 134/134 vectors tested Rust-native (100%). All categories including errors, scoped, and unified.
- WASM exports return structured error objects `{ code, http_status, message }` matching the conformance error spec.
- New WASM exports: `ashHashScope`, `ashExtractScopedFields`, `ashExtractScopedFieldsStrict`.
- Scoped/unified proof exports return proper JS objects (`{ proof, scopeHash }` / `{ proof, scopeHash, chainHash }`).
