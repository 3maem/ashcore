# Legacy Test Vectors — NOT AUTHORITATIVE

These files are **deprecated** and retained for reference only.

The authoritative conformance suite is at `tests/conformance/vectors.json`.

## What's here

- `vectors/conformance-v2.3.1.json` — Old v2.3.1 vector file (incomplete expected values, placeholder proofs)
- `cross-sdk/test-vectors.json` — Old cross-SDK vectors (placeholder expected values like `"a1b2c3d4..."`)
- `cross-sdk/run_tests.*` — Old per-language runners (js, py, go, php, rs)
- `conformance_v231.rs` — Old Rust runner for conformance-v2.3.1.json
- `cross_sdk_test_vectors.rs` — Old Rust runner with hardcoded vectors
- `cross_sdk_test_vectors_tests_wasm.rs` — Old WASM runner
- `cross_sdk_test_vectors_test.go` — Old Go runner

## Why deprecated

1. Old vectors lacked hardcoded expected values for proofs (used formulas/placeholders)
2. Known contradictions between the two files (plus-sign handling, SHA hash values)
3. Incomplete coverage (no IEEE-754 edge cases, no error behavior, no timestamp validation)
4. No version binding metadata

## What to use instead

```bash
# Run the authoritative conformance suite
cargo test --test conformance_suite

# See the authoritative vectors
cat tests/conformance/vectors.json
```

## Do NOT re-enable in CI

These runners are disabled. CI runs only `tests/conformance/` vectors.
