# ASH Gin (Go) Integration Example

This example demonstrates how to integrate ASH with Gin for request integrity verification.

## Quick Start

```bash
# Initialize module
go mod init ash-gin-example
go get github.com/gin-gonic/gin
go get github.com/3maem/ash-go-sdk

# Run the server
go run main.go
```

## Middleware Setup

```go
func AshMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        contextID := c.GetHeader("X-ASH-Context-ID")
        timestamp := c.GetHeader("X-ASH-Timestamp")
        proof := c.GetHeader("X-ASH-Proof")

        // Verify headers exist
        if contextID == "" || timestamp == "" || proof == "" {
            c.AbortWithStatusJSON(403, gin.H{"error": "Missing ASH headers"})
            return
        }

        // Get and validate context
        stored, _ := ashStore.Get(contextID)
        // ... verification logic ...

        // Verify proof
        if !ash.TimingSafeCompare(proof, expectedProof) {
            c.AbortWithStatusJSON(403, gin.H{"error": "Invalid proof"})
            return
        }

        c.Next()
    }
}
```

## Client Usage (Go)

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"

    "github.com/3maem/ash-go-sdk"
)

func main() {
    // 1. Get context
    ctxResp, _ := http.Post("http://localhost:8080/api/context",
        "application/json",
        bytes.NewReader([]byte(`{"endpoint":"/api/transfer"}`)))

    var ctx struct {
        ContextID    string `json:"contextId"`
        ClientSecret string `json:"clientSecret"`
    }
    json.NewDecoder(ctxResp.Body).Decode(&ctx)

    // 2. Build proof
    payload := `{"fromAccount":"ACC_001","toAccount":"ACC_002","amount":100}`
    binding := ash.NormalizeBinding("POST", "/api/transfer", "")
    bodyHash := ash.HashBody(payload)
    timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
    proof := ash.BuildProofV21(ctx.ClientSecret, timestamp, binding, bodyHash)

    // 3. Make request
    req, _ := http.NewRequest("POST", "http://localhost:8080/api/transfer",
        bytes.NewReader([]byte(payload)))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-ASH-Context-ID", ctx.ContextID)
    req.Header.Set("X-ASH-Timestamp", timestamp)
    req.Header.Set("X-ASH-Proof", proof)

    client := &http.Client{}
    resp, _ := client.Do(req)
    // Handle response...
}
```

## Production Considerations

1. **Use Redis Store**: Implement Redis-backed store for clustering
2. **Add Logging**: Use structured logging for audit trails
3. **Configure Timeouts**: Set appropriate request timeouts
4. **Enable TLS**: Use TLS termination at load balancer

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| ASH_CTX_NOT_FOUND | 403 | Context doesn't exist |
| ASH_CTX_EXPIRED | 403 | Context has expired |
| ASH_CTX_USED | 403 | Context already consumed |
| ASH_PROOF_MISMATCH | 403 | Invalid proof |
