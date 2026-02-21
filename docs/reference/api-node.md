# ASH Node.js SDK — API Reference

**Package:** `@3maem/ash-node-sdk`
**Version:** v1.0.0-beta

> **⚠️ Beta Notice:** This is v1.0.0-beta. Feature-complete but may undergo internal refinements. Not recommended for production-critical environments yet.

## Installation

```bash
npm install @3maem/ash-node-sdk
```

**Requirements:** Node.js 18.0.0 or later. Zero runtime dependencies.

---

## Constants

```typescript
import {
  ASH_SDK_VERSION,          // '1.0.0'
  DEFAULT_MAX_TIMESTAMP_AGE_SECONDS, // 300
  DEFAULT_CLOCK_SKEW_SECONDS,        // 30
} from '@3maem/ash-node-sdk';
```

---

## Canonicalization

### ashCanonicalizeJson

```typescript
function ashCanonicalizeJson(input: string): string
```

Canonicalizes a JSON string per RFC 8785 (JCS). Keys sorted by UTF-16 code unit order, whitespace removed, ES6 float formatting.

```typescript
import { ashCanonicalizeJson } from '@3maem/ash-node-sdk';

const canonical = ashCanonicalizeJson('{"z":1,"a":2}');
// '{"a":2,"z":1}'
```

### ashCanonicalizeJsonValue

```typescript
function ashCanonicalizeJsonValue(value: unknown): string
```

Canonicalizes a parsed JavaScript value (object, array, primitive) to canonical JSON string.

### ashCanonicalizeQuery

```typescript
function ashCanonicalizeQuery(query: string): string
```

Canonicalizes a URL query string. Parameters sorted by key (byte order), percent-encoded, `+` treated as literal plus (not space).

### ashCanonicalizeUrlencoded

```typescript
function ashCanonicalizeUrlencoded(input: string): string
```

Canonicalizes `application/x-www-form-urlencoded` form data.

---

## Binding

### ashNormalizeBinding

```typescript
function ashNormalizeBinding(method: string, path: string, query: string): string
```

Normalizes a binding string to canonical form: `METHOD|PATH|CANONICAL_QUERY`.

```typescript
import { ashNormalizeBinding } from '@3maem/ash-node-sdk';

const binding = ashNormalizeBinding('post', '/api//test/', '');
// 'POST|/api/test|'

const withQuery = ashNormalizeBinding('GET', '/api/users', 'page=1&sort=name');
// 'GET|/api/users|page=1&sort=name'
```

### ashNormalizeBindingFromUrl

```typescript
function ashNormalizeBindingFromUrl(method: string, fullPath: string): string
```

Convenience wrapper that splits a full URL path (with query string) and delegates to `ashNormalizeBinding`.

---

## Hashing

| Function | Description |
|----------|-------------|
| `ashHashBody(canonicalBody)` | SHA-256 hash of canonical body (lowercase hex) |
| `ashHashProof(proof)` | SHA-256 of proof hex string (for chaining) |
| `ashHashScope(scope)` | SHA-256 of sorted, deduplicated scope fields joined by U+001F |

---

## Proof — Basic

### ashDeriveClientSecret

```typescript
function ashDeriveClientSecret(nonce: string, contextId: string, binding: string): string
```

Derives client secret: `HMAC-SHA256(key=nonce_lowercase_ascii, data=contextId|binding)`.

### ashBuildProof

```typescript
function ashBuildProof(
  clientSecret: string,
  timestamp: string,
  binding: string,
  bodyHash: string,
): string
```

Builds HMAC-SHA256 proof: `HMAC-SHA256(key=clientSecret, data=timestamp|binding|bodyHash)`.

### ashVerifyProof

```typescript
function ashVerifyProof(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string,
): boolean
```

Re-derives secret, rebuilds proof, constant-time compares. Returns `true` if valid.

### ashVerifyProofWithFreshness

```typescript
function ashVerifyProofWithFreshness(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  bodyHash: string,
  clientProof: string,
  maxAgeSeconds: number,
  clockSkewSeconds: number,
): boolean
```

Same as `ashVerifyProof` but also validates timestamp freshness.

---

## Proof — Scoped

### ashExtractScopedFields / ashExtractScopedFieldsStrict

```typescript
function ashExtractScopedFields(payload: unknown, scope: string[]): unknown
function ashExtractScopedFieldsStrict(payload: unknown, scope: string[]): unknown
```

Extract scoped fields from a parsed payload. Lenient mode ignores missing fields; strict mode throws `ASH_SCOPED_FIELD_MISSING`.

### ashBuildProofScoped

```typescript
function ashBuildProofScoped(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: string,
  scope: string[],
): ScopedProofResult  // { proof: string, scopeHash: string }
```

### ashVerifyProofScoped

```typescript
function ashVerifyProofScoped(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: string,
  scope: string[],
  scopeHash: string,
  clientProof: string,
): boolean
```

---

## Proof — Unified

### ashBuildProofUnified

```typescript
function ashBuildProofUnified(
  clientSecret: string,
  timestamp: string,
  binding: string,
  payload: string,
  scope: string[],
  previousProof?: string | null,
): UnifiedProofResult  // { proof: string, scopeHash: string, chainHash: string }
```

Supports optional scoping and chaining in a single call.

### ashVerifyProofUnified

```typescript
function ashVerifyProofUnified(
  nonce: string,
  contextId: string,
  binding: string,
  timestamp: string,
  payload: string,
  clientProof: string,
  scope: string[],
  scopeHash: string,
  previousProof: string | null | undefined,
  chainHash: string,
): boolean
```

---

## Comparison

### ashTimingSafeEqual

```typescript
function ashTimingSafeEqual(a: string, b: string): boolean
```

Constant-time string comparison to prevent timing attacks.

---

## Validation

| Function | Description |
|----------|-------------|
| `ashValidateNonce(nonce)` | Validates hex format, 32-512 chars |
| `ashValidateTimestampFormat(ts)` | Validates digits-only, no leading zeros |
| `ashValidateTimestamp(ts, maxAge, skew)` | Format + freshness check |
| `ashValidateHash(hash, label)` | Validates 64-char hex SHA-256 |

---

## Build / Verify Orchestrators

### ashBuildRequest

```typescript
function ashBuildRequest(input: BuildRequestInput): BuildRequestResult
```

7-step orchestrator: validate nonce, validate/generate timestamp, normalize binding, hash body, derive secret, build proof, return result with `destroy()`.

```typescript
interface BuildRequestInput {
  nonce: string;
  contextId: string;
  method: string;
  path: string;
  rawQuery?: string;
  body?: string;
  timestamp?: string;
  scope?: string[];
  previousProof?: string;
}

interface BuildRequestResult {
  proof: string;
  bodyHash: string;
  binding: string;
  timestamp: string;
  nonce: string;
  scopeHash?: string;
  chainHash?: string;
  destroy(): void;
}
```

### ashVerifyRequest

```typescript
function ashVerifyRequest(input: VerifyRequestInput): VerifyResult
```

9-step orchestrator: extract headers, validate timestamp, validate nonce, normalize binding, hash body, compare body hash, derive secret, build proof, compare proof.

```typescript
interface VerifyRequestInput {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  rawQuery?: string;
  body?: string;
  nonce: string;
  contextId: string;
  scope?: string[];
  previousProof?: string;
  maxAgeSeconds?: number;
  clockSkewSeconds?: number;
}

interface VerifyResult {
  ok: boolean;
  error?: AshError;
  meta?: {
    mode: 'basic' | 'scoped' | 'unified';
    timestamp: number;
    binding: string;
  };
}
```

---

## Headers

### ashExtractHeaders

```typescript
function ashExtractHeaders(
  headers: Record<string, string | string[] | undefined>,
): AshHeaderBundle
```

Case-insensitive extraction and validation of all 5 required ASH headers. Throws `ASH_PROOF_MISSING` if any header is absent.

### Header Constants

| Constant | Value |
|----------|-------|
| `X_ASH_TIMESTAMP` | `x-ash-ts` |
| `X_ASH_NONCE` | `x-ash-nonce` |
| `X_ASH_BODY_HASH` | `x-ash-body-hash` |
| `X_ASH_PROOF` | `x-ash-proof` |
| `X_ASH_CONTEXT_ID` | `x-ash-context-id` |

---

## Context Stores

### AshMemoryStore

In-memory store for development and testing.

```typescript
import { AshMemoryStore } from '@3maem/ash-node-sdk';
const store = new AshMemoryStore();
```

### AshRedisStore

Production-ready store with atomic operations.

```typescript
import { AshRedisStore } from '@3maem/ash-node-sdk';
const store = new AshRedisStore({ client: redisClient });
```

---

## Scope Policy

### AshScopePolicyRegistry

```typescript
import { AshScopePolicyRegistry } from '@3maem/ash-node-sdk';
const registry = new AshScopePolicyRegistry();
```

Registers scope policies per endpoint with exact, param, and wildcard pattern matching.

---

## Express Middleware

```typescript
import { ashExpressMiddleware, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

app.use(ashExpressMiddleware({ store }));
```

---

## Fastify Plugin

```typescript
import { ashFastifyPlugin, AshMemoryStore } from '@3maem/ash-node-sdk';

const store = new AshMemoryStore();

fastify.register(ashFastifyPlugin, { store });
```

---

## Debug Trace

```typescript
import {
  ashBuildRequestDebug,
  ashVerifyRequestDebug,
  ashFormatTrace,
} from '@3maem/ash-node-sdk';

const result = ashBuildRequestDebug(input);
console.log(ashFormatTrace(result.trace));
```

Step-by-step tracing with timing, inputs, and outputs. Sensitive values (clientSecret) are REDACTED.

---

## Errors

```typescript
import { AshError, AshErrorCode } from '@3maem/ash-node-sdk';
```

See [Error Codes Reference](error-codes.md) for the full list.

---

## Input Validation Rules

| Parameter | Rule |
|-----------|------|
| `nonce` | 32-512 hex characters |
| `contextId` | 1-256 chars, `[A-Za-z0-9_\-.]` only |
| `binding` | Max 8,192 bytes |
| `timestamp` | Digits only, no leading zeros |
| `bodyHash` | Exactly 64 hex chars (SHA-256) |

---

## License

Apache License 2.0

See [LICENSE](../../LICENSE) for full terms.
