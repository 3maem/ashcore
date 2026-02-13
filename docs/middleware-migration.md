# Middleware Migration Guide (Thin Wrapper Pattern)

This guide shows how to migrate existing ASH middlewares to the **thin wrapper** pattern.

## Goal

Replace local re-implementation of:
- header parsing (case-insensitive lookup, multi-value handling)
- timestamp / nonce validation sequencing
- error mapping and precedence
- body hash mismatch checks
- proof verification glue

...with a single Core call:

- `verify_incoming_request(...)`

This eliminates cross-framework divergence and keeps wire behavior conformance-locked.

---

## Required Inputs

A middleware must provide the Core with:

- `method`: HTTP method (e.g., "POST")
- `path`: URL path (e.g., "/api/pay")
- `raw_query`: query string (without `?`, or tolerate leading `?`)
- `body`: raw request bytes (exact bytes received)
- `headers`: an adapter implementing `HeaderMapView`
- `now_unix`: current unix seconds
- `max_skew_secs`: allowed clock skew

> **Warning: Raw Body Bytes Required**
>
> Every thin middleware must pass raw bytes. If a framework auto-parses JSON
> and re-serializes, you **must** configure "raw body capture" to get the
> original bytes. Passing re-serialized JSON will produce a different body
> hash and fail verification.

---

## Core Call

Pseudocode:

```text
res = verify_incoming_request({
  method, path, raw_query, body,
  headers, now_unix, max_skew_secs
})

if res.ok:
  next()
else:
  err = res.error
  status = err.http_status
  payload = { code: err.code, message: err.message }
  if err.retryable(): set Retry-After header (optional)
  respond(status, payload)
```

---

## Important Rules (Do Not Break Conformance)

- **Do not** parse/normalize headers locally.
- **Do not** validate timestamp/nonce locally.
- **Do not** canonicalize query locally.
- **Do not** compute body hash locally (unless you pass raw bytes and let Core do it).
- **Do not** remap error codes/statuses. Pass-through Core wire fields only.

---

## Retry-After (Optional but Recommended)

If the error is retryable (timestamp drift, internal errors), set:

```
Retry-After: 0
```

(or a short delay)

This is safe and improves client behavior.

---

## Minimal Adapter: HeaderMapView

Each framework must implement a small adapter exposing:

- case-insensitive `get_all_ci(name)` returning all header values

Examples are provided in `examples/` for popular frameworks.
