# ASH Go SDK API Reference

**Version:** 1.0.0
**Package:** `github.com/3maem/ash-go-sdk`

## Installation

```bash
go get github.com/3maem/ash-go-sdk@v1.0.0
```

## Package Import

```go
import ash "github.com/3maem/ash-go-sdk"
```

---

## Constants

### Version Constants

```go
const (
    Version           = "1.0.0"
    ProtocolVersion   = "ASHv2.3"
    ProtocolVersionV1 = "ASHv1"
    ProtocolVersionV21 = "ASHv2.1"
)
```

### Security Modes

```go
type AshMode string

const (
    ModeMinimal  AshMode = "minimal"   // Basic integrity checking
    ModeBalanced AshMode = "balanced"  // Recommended for most applications
    ModeStrict   AshMode = "strict"    // Maximum security with nonce requirement
)
```

### Error Codes

```go
type AshErrorCode string

const (
    ErrCtxNotFound         AshErrorCode = "ASH_CTX_NOT_FOUND"
    ErrCtxExpired          AshErrorCode = "ASH_CTX_EXPIRED"
    ErrCtxAlreadyUsed      AshErrorCode = "ASH_CTX_ALREADY_USED"
    ErrBindingMismatch     AshErrorCode = "ASH_BINDING_MISMATCH"
    ErrProofMissing        AshErrorCode = "ASH_PROOF_MISSING"
    ErrProofInvalid        AshErrorCode = "ASH_PROOF_INVALID"
    ErrCanonicalizationError AshErrorCode = "ASH_CANONICALIZATION_ERROR"
    ErrModeViolation       AshErrorCode = "ASH_MODE_VIOLATION"
    ErrUnsupportedContentType AshErrorCode = "ASH_UNSUPPORTED_CONTENT_TYPE"
    ErrScopeMismatch       AshErrorCode = "ASH_SCOPE_MISMATCH"
    ErrChainBroken         AshErrorCode = "ASH_CHAIN_BROKEN"
)
```

---

## Types

### AshError

```go
type AshError struct {
    Code    AshErrorCode
    Message string
}

func (e *AshError) Error() string
func (e *AshError) HTTPStatus() int
```

### StoredContext

```go
type StoredContext struct {
    ContextID  string            // Unique context identifier
    Binding    string            // Canonical binding: "METHOD|PATH|QUERY"
    Mode       AshMode           // Security mode
    IssuedAt   int64             // Unix timestamp (milliseconds)
    ExpiresAt  int64             // Unix timestamp (milliseconds)
    Nonce      string            // Server-generated nonce
    ConsumedAt int64             // 0 if not consumed
    Metadata   map[string]any    // Optional metadata
}
```

### ContextPublicInfo

```go
type ContextPublicInfo struct {
    ContextID string  `json:"contextId"`
    ExpiresAt int64   `json:"expiresAt"`
    Mode      AshMode `json:"mode"`
    Nonce     string  `json:"nonce,omitempty"`
}
```

### BuildProofInput

```go
type BuildProofInput struct {
    Mode             AshMode
    Binding          string
    ContextID        string
    Nonce            string  // Optional
    CanonicalPayload string
}
```

### VerifyResult

```go
type VerifyResult struct {
    Valid        bool
    ErrorCode    AshErrorCode
    ErrorMessage string
    Metadata     map[string]any
}
```

---

## Functions

### Canonicalization

#### CanonicalizeJSON

```go
func CanonicalizeJSON(value interface{}) (string, error)
```

Canonicalizes any Go value to a deterministic JSON string per RFC 8785 (JCS).

**Parameters:**
- `value` - Any Go value (struct, map, slice, etc.)

**Returns:**
- Canonical JSON string
- Error if canonicalization fails

**Example:**
```go
data := map[string]interface{}{"z": 1, "a": 2}
canonical, err := ash.CanonicalizeJSON(data)
// canonical = `{"a":2,"z":1}`
```

#### ParseJSON

```go
func ParseJSON(jsonStr string) (string, error)
```

Parses a JSON string and returns its canonical form.

**Example:**
```go
canonical, err := ash.ParseJSON(`{"z": 1, "a": 2}`)
// canonical = `{"a":2,"z":1}`
```

#### CanonicalizeURLEncoded

```go
func CanonicalizeURLEncoded(input string) (string, error)
```

Canonicalizes URL-encoded form data by sorting parameters.

**Example:**
```go
canonical, err := ash.CanonicalizeURLEncoded("z=1&a=2")
// canonical = "a=2&z=1"
```

#### CanonicalizeURLEncodedFromMap

```go
func CanonicalizeURLEncodedFromMap(data map[string][]string) string
```

Canonicalizes URL-encoded data from a map.

---

### Binding

#### NormalizeBinding

```go
func NormalizeBinding(method, path, query string) (string, error)
```

Normalizes an endpoint binding to canonical form.

**Format:** `METHOD|PATH|CANONICAL_QUERY`

**Rules:**
- Method uppercased
- Path starts with `/`
- Duplicate slashes collapsed
- Trailing slash removed (except root)
- Query parameters sorted

**Example:**
```go
binding, err := ash.NormalizeBinding("post", "/api//users/", "z=1&a=2")
// binding = "POST|/api/users|a=2&z=1"
```

#### NormalizeBindingFromURL

```go
func NormalizeBindingFromURL(method, fullPath string) (string, error)
```

Normalizes binding from a full URL path including query string.

---

### Proof Generation

#### BuildProof

```go
func BuildProof(input BuildProofInput) string
```

Builds a cryptographic proof (legacy v1 format).

**Example:**
```go
proof := ash.BuildProof(ash.BuildProofInput{
    Mode:             ash.ModeBalanced,
    Binding:          "POST|/api/update|",
    ContextID:        "ctx_abc123",
    CanonicalPayload: `{"amount":100}`,
})
```

#### BuildProofV21

```go
func BuildProofV21(clientSecret, timestamp, binding, bodyHash string) string
```

Builds an HMAC-SHA256 proof (v2.1 format).

**Parameters:**
- `clientSecret` - Derived from `DeriveClientSecret()`
- `timestamp` - Unix timestamp in milliseconds as string
- `binding` - Canonical binding
- `bodyHash` - SHA-256 hash of body from `HashBody()`

#### BuildProofV21Scoped

```go
func BuildProofV21Scoped(clientSecret, timestamp, binding, bodyHash, scopeHash string) string
```

Builds a scoped proof (v2.2 format) with selective field protection.

#### BuildProofV21Unified

```go
func BuildProofV21Unified(clientSecret, timestamp, binding, bodyHash, scopeHash, chainHash string) string
```

Builds a unified proof (v2.3 format) with scoping and chaining.

---

### Proof Verification

#### TimingSafeCompare

```go
func TimingSafeCompare(a, b string) bool
```

Constant-time string comparison to prevent timing attacks.

#### TimingSafeCompareBytes

```go
func TimingSafeCompareBytes(a, b []byte) bool
```

Constant-time byte slice comparison.

#### VerifyProofV21

```go
func VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof string) bool
```

Verifies an HMAC-SHA256 proof.

#### VerifyProofV21Scoped

```go
func VerifyProofV21Scoped(nonce, contextID, binding, timestamp, bodyHash, scopeHash, proof string) bool
```

Verifies a scoped proof.

#### VerifyProofV21Unified

```go
func VerifyProofV21Unified(nonce, contextID, binding, timestamp, bodyHash, scopeHash, chainHash, proof string) bool
```

Verifies a unified proof with scoping and chaining.

---

### Cryptographic Utilities

#### GenerateNonce

```go
func GenerateNonce(bytes int) string
```

Generates a cryptographically secure nonce.

**Example:**
```go
nonce := ash.GenerateNonce(32)  // 32-byte nonce, base64url encoded
```

#### GenerateContextID

```go
func GenerateContextID() string
```

Generates a unique context identifier.

#### DeriveClientSecret

```go
func DeriveClientSecret(nonce, contextID, binding string) string
```

Derives a client secret from server nonce (one-way function).

#### HashBody

```go
func HashBody(body string) string
```

Computes SHA-256 hash of request body.

#### HashProof

```go
func HashProof(proof string) string
```

Computes hash of proof for chaining.

#### HashScopedBody

```go
func HashScopedBody(payload map[string]interface{}, scope []string) string
```

Computes hash of scoped fields only.

#### ExtractScopedFields

```go
func ExtractScopedFields(payload map[string]interface{}, scope []string) map[string]interface{}
```

Extracts specified fields from payload for scoping.

---

### Encoding

#### Base64URLEncode

```go
func Base64URLEncode(data []byte) string
```

Encodes data as base64url without padding.

#### Base64URLDecode

```go
func Base64URLDecode(input string) ([]byte, error)
```

Decodes base64url string to bytes.

---

## Context Store Interface

```go
type ContextStore interface {
    Create(binding string, ttlMs int64, mode AshMode, metadata map[string]any) (*StoredContext, error)
    Get(contextID string) (*StoredContext, error)
    Consume(contextID string) error
    Cleanup() (int, error)
}
```

### Implementations

- `MemoryStore` - In-memory store for development
- `RedisStore` - Redis-backed store for production

---

## Gin Middleware

```go
import (
    ash "github.com/3maem/ash-go-sdk"
    "github.com/3maem/ash-go-sdk/middleware"
    "github.com/gin-gonic/gin"
)

func main() {
    store := ash.NewMemoryStore()

    r := gin.Default()

    // Apply ASH middleware to specific routes
    api := r.Group("/api")
    api.Use(middleware.AshGin(store, middleware.AshGinOptions{
        GetBinding: func(c *gin.Context) string {
            binding, _ := ash.NormalizeBinding(c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery)
            return binding
        },
    }))

    api.POST("/transfer", func(c *gin.Context) {
        // Access verified context
        ctx := c.MustGet("ashContext").(*ash.StoredContext)
        c.JSON(200, gin.H{"status": "success", "contextId": ctx.ContextID})
    })

    r.Run(":8080")
}
```

### AshGinOptions

```go
type AshGinOptions struct {
    // GetBinding extracts binding from request (required)
    GetBinding func(c *gin.Context) string

    // Skip determines if request should skip verification (optional)
    Skip func(c *gin.Context) bool

    // OnError handles verification errors (optional)
    OnError func(c *gin.Context, err *ash.AshError)
}
```

---

## HTTP Headers

| Header | Description |
|--------|-------------|
| `X-ASH-Context-ID` | Context identifier |
| `X-ASH-Proof` | Cryptographic proof |
| `X-ASH-Mode` | Security mode |
| `X-ASH-Timestamp` | Request timestamp |
| `X-ASH-Scope` | Comma-separated scoped fields |
| `X-ASH-Scope-Hash` | Hash of scoped fields |
| `X-ASH-Chain-Hash` | Hash of previous proof |

---

## Complete Example

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    ash "github.com/3maem/ash-go-sdk"
)

func main() {
    // Server: Generate context
    nonce := ash.GenerateNonce(32)
    contextID := ash.GenerateContextID()
    binding := "POST|/api/transfer|"

    // Client: Build proof
    payload := map[string]interface{}{
        "amount": 100,
        "to":     "account123",
    }
    canonical, _ := ash.CanonicalizeJSON(payload)
    clientSecret := ash.DeriveClientSecret(nonce, contextID, binding)
    bodyHash := ash.HashBody(canonical)
    timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())

    proof := ash.BuildProofV21(clientSecret, timestamp, binding, bodyHash)

    // Server: Verify proof
    isValid := ash.VerifyProofV21(nonce, contextID, binding, timestamp, bodyHash, proof)
    fmt.Printf("Proof valid: %v\n", isValid)
}
```

---

## License

ASH Source-Available License (ASAL-1.0)

See [LICENSE](../LICENSE) for full terms.
