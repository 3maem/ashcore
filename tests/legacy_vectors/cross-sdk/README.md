# Cross-SDK Test Vectors

This directory contains test vectors for verifying ASH SDK interoperability across all language implementations.

## Purpose

These test vectors ensure that:
1. All SDKs produce **identical outputs** for the same inputs
2. Canonicalization is deterministic across platforms
3. Proof generation and verification are compatible
4. Error conditions are handled consistently

## Test Vector File

**`test-vectors.json`** contains test cases for:

| Category | Description |
|----------|-------------|
| `canonicalization` | JSON canonicalization (RFC 8785 JCS) |
| `urlencoded_canonicalization` | URL-encoded form data canonicalization |
| `binding_normalization` | HTTP method + path + query normalization |
| `hash_body` | SHA-256 body hashing |
| `derive_client_secret` | v2.1 client secret derivation |
| `proof_generation_v21` | v2.1 HMAC-SHA256 proof generation |
| `timing_safe_equal` | Constant-time comparison |
| `scoped_fields_v22` | v2.2 field scoping |
| `error_conditions` | Error handling |

## Usage

### Running Tests

Each SDK should implement a test runner that:
1. Loads `test-vectors.json`
2. Runs each test vector through the corresponding SDK function
3. Compares output with expected value
4. Reports pass/fail for each test

### Example Implementation (Python)

```python
import json
from ash.core import canonicalize_json

def run_canonicalization_tests():
    with open('test-vectors.json') as f:
        vectors = json.load(f)

    for test in vectors['canonicalization']['vectors']:
        result = canonicalize_json(test['input'])
        if result == test['expected']:
            print(f"✓ {test['id']}: {test['description']}")
        else:
            print(f"✗ {test['id']}: Expected {test['expected']}, got {result}")

run_canonicalization_tests()
```

### Example Implementation (Node.js)

```typescript
import { ashCanonicalizeJson } from '@3maem/ash-node-sdk';
import vectors from './test-vectors.json';

for (const test of vectors.canonicalization.vectors) {
  const result = ashCanonicalizeJson(test.input);
  const passed = result === test.expected;
  console.log(`${passed ? '✓' : '✗'} ${test.id}: ${test.description}`);
}
```

### Example Implementation (Go)

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    ash "github.com/3maem/ash-go-sdk"
)

func main() {
    data, _ := os.ReadFile("test-vectors.json")
    var vectors TestVectors
    json.Unmarshal(data, &vectors)

    for _, test := range vectors.Canonicalization.Vectors {
        result, _ := ash.CanonicalizeJSON(test.Input)
        if result == test.Expected {
            fmt.Printf("✓ %s: %s\n", test.ID, test.Description)
        } else {
            fmt.Printf("✗ %s: Expected %s, got %s\n", test.ID, test.Expected, result)
        }
    }
}
```

## Adding New Test Vectors

When adding new test vectors:

1. Add to appropriate category in `test-vectors.json`
2. Include unique ID (e.g., `canon-021`)
3. Add clear description
4. Verify expected output with at least 2 SDKs
5. Update this README if adding new categories

## Critical Test Vectors

These tests are **critical** for interoperability:

| ID | Why Critical |
|----|--------------|
| `canon-001` | Basic key sorting |
| `canon-005` | Unicode handling |
| `canon-006` | Number normalization |
| `bind-001` | Basic binding format |
| `bind-006` | Query string canonicalization |

If any SDK fails these tests, cross-SDK communication will break.

## Verification Matrix

Track which SDKs pass all test vectors:

| SDK | Canonicalization | Binding | Hash | Proof | Status |
|-----|------------------|---------|------|-------|--------|
| ashcore (Rust) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ash-node-sdk (Node.js) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ash-python-sdk (Python) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ash-go-sdk (Go) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ash-php-sdk (PHP) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ash-wasm-sdk (WebAssembly) | ✓ | ✓ | ✓ | ✓ | ✓ |

## CI Integration

Add to your CI pipeline:

```yaml
# .github/workflows/cross-sdk-tests.yml
name: Cross-SDK Tests

on: [push, pull_request]

jobs:
  test-vectors:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run cross-SDK test vectors
        run: |
          cd tests/cross-sdk
          python run_tests.py
```
