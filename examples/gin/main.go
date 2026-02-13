/*
ASH Integration Example: Gin (Go) Server

This example demonstrates how to integrate ASH with Gin
for request integrity verification and anti-replay protection.
*/
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/3maem/ash-go-sdk"
	"github.com/gin-gonic/gin"
)

// In-memory store (use Redis in production)
var ashStore = NewMemoryStore()

func main() {
	r := gin.Default()

	// Public endpoints
	r.GET("/health", healthHandler)
	r.POST("/api/context", issueContextHandler)

	// Protected endpoints with ASH middleware
	protected := r.Group("/api")
	protected.Use(AshMiddleware())
	{
		protected.POST("/transfer", transferHandler)
		protected.POST("/payment", paymentHandler)
	}

	fmt.Println("ASH Gin example running on port 8080")
	fmt.Println("Protected endpoints: /api/transfer, /api/payment")
	r.Run(":8080")
}

// AshMiddleware verifies ASH proofs on protected endpoints
func AshMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		contextID := c.GetHeader("X-ASH-Context-ID")
		timestamp := c.GetHeader("X-ASH-Timestamp")
		proof := c.GetHeader("X-ASH-Proof")

		if contextID == "" || timestamp == "" || proof == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Missing ASH headers",
			})
			return
		}

		// Get stored context
		stored, err := ashStore.Get(contextID)
		if err != nil || stored == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Context not found",
				"code":  "ASH_CTX_NOT_FOUND",
			})
			return
		}

		// Check expiration
		nowMs := time.Now().UnixMilli()
		if nowMs > stored.ExpiresAt {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Context expired",
				"code":  "ASH_CTX_EXPIRED",
			})
			return
		}

		// Build binding
		binding := ash.AshNormalizeBinding(c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery)

		// Read body
		body, _ := c.GetRawData()
		if len(body) == 0 {
			body = []byte("{}")
		}

		// Verify proof
		bodyHash := ash.AshHashBody(string(body))
		clientSecret := ash.AshDeriveClientSecret(stored.Nonce, contextID, binding)
		expectedProof := ash.AshBuildProofHmac(clientSecret, timestamp, binding, bodyHash)

		if !ash.AshTimingSafeCompare(proof, expectedProof) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid proof",
				"code":  "ASH_PROOF_MISMATCH",
			})
			return
		}

		// Consume context
		if err := ashStore.Consume(contextID, nowMs); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Context already used",
				"code":  "ASH_CTX_USED",
			})
			return
		}

		// Re-set body for handler
		c.Request.Body = NewReadCloser(body)
		c.Next()
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func issueContextHandler(c *gin.Context) {
	var req struct {
		Endpoint string `json:"endpoint"`
		TtlMs    int64  `json:"ttlMs"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Endpoint == "" {
		req.Endpoint = "/api/transfer"
	}
	if req.TtlMs == 0 {
		req.TtlMs = 30000
	}

	binding := ash.AshNormalizeBinding("POST", req.Endpoint, "")
	ctx := ashStore.Create(binding, req.TtlMs)

	clientSecret := ash.AshDeriveClientSecret(ctx.Nonce, ctx.ContextID, binding)

	c.JSON(http.StatusOK, gin.H{
		"contextId":    ctx.ContextID,
		"clientSecret": clientSecret,
		"expiresAt":    ctx.ExpiresAt,
	})
}

func transferHandler(c *gin.Context) {
	var req struct {
		FromAccount string  `json:"fromAccount"`
		ToAccount   string  `json:"toAccount"`
		Amount      float64 `json:"amount"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fmt.Printf("Transfer: %.2f from %s to %s\n", req.Amount, req.FromAccount, req.ToAccount)

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"message":       "Transfer completed",
		"transactionId": fmt.Sprintf("TXN_%d", time.Now().UnixMilli()),
	})
}

func paymentHandler(c *gin.Context) {
	var req struct {
		MerchantID string  `json:"merchantId"`
		Amount     float64 `json:"amount"`
		Currency   string  `json:"currency"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Currency == "" {
		req.Currency = "USD"
	}

	fmt.Printf("Payment: %.2f %s to merchant %s\n", req.Amount, req.Currency, req.MerchantID)

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"paymentId": fmt.Sprintf("PAY_%d", time.Now().UnixMilli()),
	})
}

// Helper types and functions

type StoredContext struct {
	ContextID string
	Nonce     string
	Binding   string
	ExpiresAt int64
	Consumed  bool
}

type MemoryStore struct {
	contexts map[string]*StoredContext
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{contexts: make(map[string]*StoredContext)}
}

func (s *MemoryStore) Create(binding string, ttlMs int64) *StoredContext {
	ctx := &StoredContext{
		ContextID: generateID(),
		Nonce:     generateNonce(),
		Binding:   binding,
		ExpiresAt: time.Now().UnixMilli() + ttlMs,
		Consumed:  false,
	}
	s.contexts[ctx.ContextID] = ctx
	return ctx
}

func (s *MemoryStore) Get(contextID string) (*StoredContext, error) {
	ctx, ok := s.contexts[contextID]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return ctx, nil
}

func (s *MemoryStore) Consume(contextID string, nowMs int64) error {
	ctx, ok := s.contexts[contextID]
	if !ok || ctx.Consumed {
		return fmt.Errorf("already consumed or not found")
	}
	ctx.Consumed = true
	return nil
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "ash_" + hex.EncodeToString(b)
}

func generateNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

type readCloser struct {
	data []byte
	pos  int
}

func NewReadCloser(data []byte) *readCloser {
	return &readCloser{data: data}
}

func (r *readCloser) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return
}

func (r *readCloser) Close() error { return nil }
