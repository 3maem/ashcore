# Migration Guide: Pre-2.3.4 to 2.3.x

This guide helps you migrate from ASH versions prior to 2.3.4 to the current 2.3.x release.

---

## Breaking Changes

### Function Naming Convention

All functions now follow the `ash_` prefix convention.

| Old Name | New Name |
|----------|----------|
| `buildProofV21` | `ashBuildProofHmac` |
| `verifyProofV21` | `ashVerifyProof` |
| `buildProofV21Scoped` | `ashBuildProofScoped` |
| `verifyProofV21Scoped` | `ashVerifyProofScoped` |
| `hashBody` | `ashHashBody` |
| `deriveClientSecret` | `ashDeriveClientSecret` |

### Deprecated Functions

The following functions are deprecated but still available for backward compatibility:

- `BuildProofV21` → Use `AshBuildProofHMAC`
- `VerifyProofV21` → Use `AshVerifyProof`
- `buildProof` → Use `ashBuildProof`
- `verifyProof` → Use `ashVerifyProof`

---

## Migration Steps

### Step 1: Update Dependencies

#### Node.js

```bash
npm install @3maem/ash-node-sdk@latest
```

#### Python

```bash
pip install --upgrade ash-python-sdk
```

#### Go

```bash
go get -u github.com/3maem/ash-go-sdk
```

#### PHP

```bash
composer update 3maem/ash-php-sdk
```

---

### Step 2: Update Function Calls

Replace deprecated function names with the new naming convention.

#### Before (Node.js)

```typescript
import { buildProofV21, verifyProofV21 } from '@3maem/ash-node-sdk';

const proof = buildProofV21(secret, timestamp, binding, bodyHash);
```

#### After (Node.js)

```typescript
import { ashBuildProofHmac, ashVerifyProof } from '@3maem/ash-node-sdk';

const proof = ashBuildProofHmac(secret, timestamp, binding, bodyHash);
```

---

### Step 3: Update Error Handling

Error codes are now standardized across all SDKs:

| Code | Description |
|------|-------------|
| `ASH_CTX_NOT_FOUND` | Context not found |
| `ASH_CTX_EXPIRED` | Context expired |
| `ASH_CTX_ALREADY_USED` | Context already used (replay) |
| `ASH_BINDING_MISMATCH` | Endpoint binding mismatch |
| `ASH_PROOF_INVALID` | Proof verification failed |

---

### Step 4: Test Your Integration

Run your test suite to verify everything works correctly:

```bash
# Node.js
npm test

# Python
pytest

# Go
go test ./...

# PHP
composer test
```

---

## Backward Compatibility

Version 2.3.x maintains backward compatibility with deprecated functions.

However, we recommend migrating to the new naming convention as deprecated functions may be removed in future major versions.

---

## Need Help?

If you encounter issues during migration:

- Open an issue on GitHub
- Contact: support@ash-sdk.com
