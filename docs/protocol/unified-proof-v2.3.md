# ASH Unified Proof API (v2.3)

**Version:** 2.3.4

## Overview

The Unified Proof API combines context scoping and request chaining into a single, flexible function. This simplifies the API while supporting all use cases.

## Formula

```
scopeHash  = scope.length > 0 ? SHA256(scope.join(",")) : ""
bodyHash   = SHA256(canonicalize(scopedPayload))
chainHash  = previousProof ? SHA256(previousProof) : ""
proof      = HMAC-SHA256(clientSecret, timestamp|binding|bodyHash|scopeHash|chainHash)
```

## Function Signatures

### Build Proof (Client-side)

| SDK | Function |
|-----|----------|
| Rust | `build_proof_v21_unified(client_secret, timestamp, binding, payload, scope, previous_proof)` |
| WASM | `ashBuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof)` |
| TypeScript | `ashBuildProofUnified(clientSecret, timestamp, binding, payload, scope?, previousProof?)` |
| PHP | `Proof::buildUnified($clientSecret, $timestamp, $binding, $payload, $scope, $previousProof)` |
| Python | `build_proof_unified(client_secret, timestamp, binding, payload, scope, previous_proof)` |
| Go | `BuildProofUnified(clientSecret, timestamp, binding, payload, scope, previousProof)` |

### Verify Proof (Server-side)

| SDK | Function |
|-----|----------|
| Rust | `verify_proof_v21_unified(nonce, context_id, binding, timestamp, payload, client_proof, scope, scope_hash, previous_proof, chain_hash)` |
| WASM | `ashVerifyProofUnified(...)` |
| TypeScript | `ashVerifyProofUnified(...)` |
| PHP | `Proof::verifyUnified(...)` |
| Python | `verify_proof_unified(...)` |
| Go | `VerifyProofUnified(...)` |

## Usage Modes

| Mode | scope | previousProof | Use Case |
|------|-------|---------------|----------|
| Basic | `[]` | `null` | Standard request protection |
| Scoped | `['field1', 'field2']` | `null` | Protect specific fields only |
| Chained | `[]` | `"abc123..."` | Multi-step workflow protection |
| Full | `['field1']` | `"abc123..."` | Both features combined |

## Code Examples

### TypeScript/Node.js

```typescript
import {
  ashBuildProofUnified,
  ashVerifyProofUnified,
  ashHashProof
} from '@3maem/ash-node-sdk';

// Basic usage (no scoping, no chaining)
const result = ashBuildProofUnified(
  clientSecret,
  timestamp,
  binding,
  payload
);

// With scoping (protect specific fields)
const scopedResult = ashBuildProofUnified(
  clientSecret,
  timestamp,
  binding,
  payload,
  ['amount', 'recipient']  // Only protect these fields
);

// With chaining (link to previous request)
const chainedResult = ashBuildProofUnified(
  clientSecret,
  timestamp,
  binding,
  payload,
  [],                      // No scoping
  previousProof            // Link to previous proof
);

// Full (scoping + chaining)
const fullResult = ashBuildProofUnified(
  clientSecret,
  timestamp,
  binding,
  payload,
  ['amount'],              // Scoping
  previousProof            // Chaining
);
```

### PHP

```php
use Ash\Core\Proof;

// Basic usage
$result = Proof::buildUnified($clientSecret, $timestamp, $binding, $payload);

// With scoping
$result = Proof::buildUnified(
    $clientSecret,
    $timestamp,
    $binding,
    $payload,
    scope: ['amount', 'recipient']
);

// With chaining
$result = Proof::buildUnified(
    $clientSecret,
    $timestamp,
    $binding,
    $payload,
    previousProof: $lastProof
);

// Full (scoping + chaining)
$result = Proof::buildUnified(
    $clientSecret,
    $timestamp,
    $binding,
    $payload,
    scope: ['amount'],
    previousProof: $lastProof
);
```

### Python

```python
from ash.core import build_proof_unified, verify_proof_unified, hash_proof

# Basic usage
result = build_proof_unified(client_secret, timestamp, binding, payload)

# With scoping
result = build_proof_unified(
    client_secret, timestamp, binding, payload,
    scope=['amount', 'recipient']
)

# With chaining
result = build_proof_unified(
    client_secret, timestamp, binding, payload,
    previous_proof=last_proof
)

# Full (scoping + chaining)
result = build_proof_unified(
    client_secret, timestamp, binding, payload,
    scope=['amount'],
    previous_proof=last_proof
)
```

### Rust

```rust
use ashcore::{build_proof_v21_unified, verify_proof_v21_unified, hash_proof};

// Basic usage
let result = build_proof_v21_unified(
    &client_secret,
    &timestamp,
    &binding,
    &payload,
    &[],   // No scoping
    None,  // No chaining
)?;

// With scoping
let result = build_proof_v21_unified(
    &client_secret,
    &timestamp,
    &binding,
    &payload,
    &["amount", "recipient"],
    None,
)?;

// With chaining
let result = build_proof_v21_unified(
    &client_secret,
    &timestamp,
    &binding,
    &payload,
    &[],
    Some(&previous_proof),
)?;
```

## Return Value

All build functions return:

```json
{
  "proof": "a1b2c3d4...",      // The cryptographic proof (64 hex chars)
  "scopeHash": "e5f6g7h8...",  // SHA256 of scope fields (empty if no scoping)
  "chainHash": "i9j0k1l2..."   // SHA256 of previous proof (empty if no chaining)
}
```

## HTTP Headers

| Header | Description | When Used |
|--------|-------------|-----------|
| `X-ASH-Proof` | The cryptographic proof | Always |
| `X-ASH-Timestamp` | Request timestamp (ms) | Always |
| `X-ASH-Scope-Hash` | Hash of scope fields | When scoping |
| `X-ASH-Scope` | Comma-separated scope fields | When scoping |
| `X-ASH-Chain-Hash` | Hash of previous proof | When chaining |

## Error Codes

| Code | Description |
|------|-------------|
| `ASH_INTEGRITY_FAILED` | Proof verification failed |
| `ASH_SCOPE_MISMATCH` | Scope hash doesn't match expected |
| `ASH_CHAIN_BROKEN` | Chain hash doesn't match expected |

## Security Properties

1. **Backward Compatible**: Empty scope and null previousProof produce standard v2.1 behavior
2. **Selective Protection**: Only scoped fields affect the proof
3. **Workflow Integrity**: Chain hash cryptographically links requests
4. **Timing-Safe**: All comparisons use constant-time algorithms

## Migration from v2.1/v2.2

The unified function replaces:
- `buildProofV21()` → `buildProofUnified()` with empty scope and no previousProof
- `buildProofV21Scoped()` → `buildProofUnified()` with scope parameter
- New chaining capability via previousProof parameter

Existing code continues to work - the unified function is additive.
