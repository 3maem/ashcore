# SDK Migration Guide (Thin Wrapper Pattern)

This guide shows how to migrate client SDKs to use Core high-level orchestration.

## Goal

Replace local glue chains like:

- canonicalize_query -> normalize_binding -> hash_body -> derive_secret -> build_proof
- plus local timestamp/nonce generation
- plus local error mapping

...with a single Core call:

- `build_request_proof(...)`

This keeps all SDKs behavior-identical and conformance-safe.

---

## Required Inputs

A client SDK provides:

- `method`
- `path`
- `raw_query`
- `body` (raw bytes to be sent)
- proof mode settings (basic / scoped / chained / unified)
- any required binding inputs (per protocol)

The Core returns:

- `headers_to_set` (ts, nonce, body-hash, proof, optional context id)
- plus optional debug meta in debug builds

---

## Core Call

Pseudocode:

```text
out = build_request_proof({
  method, path, raw_query, body, mode, bindings, ...
})

for (k, v) in out.headers_to_set:
  request.set_header(k, v)

send(request)
```

---

## Important Rules

- **Do not** canonicalize query in the SDK.
- **Do not** compute body hash in the SDK.
- **Do not** generate timestamps/nonces differently.
- **Do not** re-map Core errors.

SDKs must be wrappers around Core, not independent implementations.

---

## Testing

New SDKs should:

1. Implement the Testkit `AshAdapter`
2. Run the conformance vectors
3. Confirm byte-for-byte proof output and identical error wiring
