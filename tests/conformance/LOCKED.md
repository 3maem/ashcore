# Vectors are locked

`vectors.json` is immutable for `ash_version: "1.0.0"`.

CI validates against these locked vectors. It does not generate them.

Any change to `vectors.json` in a normal CI run MUST fail the build.

To regenerate vectors:
1. Increment `ash_version` in the vectors file metadata
2. Run `cargo run --bin generate_vectors`
3. Update all SDK conformance tests
4. Submit as an explicit behavioral change PR
