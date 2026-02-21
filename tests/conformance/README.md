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

- `vectors.json` is locked to `ash_version: "1.0.0"` and a specific Rust core commit
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

- `path_percent_decode` is `decode_all` (including reserved chars like `%2F` -> `/`). This is the locked behavior, flagged for security review in a future version.
- Current HMAC inputs do not include domain prefixes beyond delimiter usage. Introducing explicit domain prefixes (e.g., `ASH|proof|`) is a breaking behavioral change requiring a major version bump and regenerated vectors.

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
