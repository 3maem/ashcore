# Core API Phase 2 — Enriched API Layer

## Summary

Phase 2 adds metadata-rich variants of existing Core functions. No behavioral changes.
Each enriched function wraps its base counterpart — same validation, same errors, richer return types.

## New Public APIs

### `ash_canonicalize_query_enriched(input) -> Result<CanonicalQueryResult, AshError>`

Wraps `ash_canonicalize_query`. Returns:

| Field | Type | Description |
|-------|------|-------------|
| `canonical` | `String` | The canonical query (same as base) |
| `pairs_count` | `usize` | Number of key=value pairs |
| `had_fragment` | `bool` | Whether input had `#...` (stripped) |
| `had_leading_question_mark` | `bool` | Whether input had leading `?` |
| `unique_keys` | `usize` | Number of distinct keys |

### `ash_hash_body_enriched(canonical_body) -> BodyHashResult`

Wraps `ash_hash_body`. Returns:

| Field | Type | Description |
|-------|------|-------------|
| `hash` | `String` | SHA-256 hex (same as base) |
| `input_bytes` | `usize` | Size of input in bytes |
| `is_empty` | `bool` | Whether input was empty |

### `ash_normalize_binding_enriched(method, path, query) -> Result<NormalizedBinding, AshError>`

Wraps `ash_normalize_binding`. Returns:

| Field | Type | Description |
|-------|------|-------------|
| `binding` | `String` | Full binding (same as base) |
| `method` | `String` | Uppercased method |
| `path` | `String` | Normalized path |
| `canonical_query` | `String` | Sorted query |
| `had_query` | `bool` | Whether input query was non-empty |

### `ash_parse_binding(binding) -> Result<NormalizedBinding, AshError>`

Parses an existing `METHOD|PATH|QUERY` binding string into structured parts.
Useful for inspecting bindings from `build_request_proof` or `verify_incoming_request`.

## Conformance Impact

**None.** All 134 vectors pass unchanged. No behavioral changes.

## Files Changed

| File | Change |
|------|--------|
| `src/enriched.rs` | **New** — enriched types and functions |
| `src/lib.rs` | Module declaration and exports |

## Design Principle

- Enriched functions call the base function internally (no logic duplication)
- Metadata is computed from the result, not by reimplementing the algorithm
- All types derive `Debug`, `Clone`, `PartialEq`, `Eq`
