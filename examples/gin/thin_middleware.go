// Gin thin-wrapper middleware (ASH v1.0.0)
package main

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	ash "github.com/3maem/ash-go-sdk"
)

// lookupContext retrieves a stored ASH context by ID.
// In production, this should look up the context from a persistent store (e.g., Redis).
// Returns nonce and binding, or empty strings if not found.
func lookupContext(contextID string) (nonce string, binding string, ok bool) {
	// TODO: Replace with actual context store lookup
	return "", "", false
}

// AshMiddleware returns a Gin middleware that verifies ASH proofs using core SDK functions.
func AshMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Read body once, then restore for downstream handlers
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"code":    "ASH_BODY_READ_ERROR",
				"message": "Failed to read request body",
			})
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		// 2. Extract ASH headers
		contextID := c.GetHeader("X-ASH-Context-ID")
		clientProof := c.GetHeader("X-ASH-Proof")
		timestamp := c.GetHeader("X-ASH-Timestamp")

		if contextID == "" || clientProof == "" || timestamp == "" {
			c.JSON(460, gin.H{
				"code":    "ASH_PROOF_INVALID",
				"message": "Missing required ASH headers (X-ASH-Context-ID, X-ASH-Proof, X-ASH-Timestamp)",
			})
			c.Abort()
			return
		}

		// 3. Look up context
		nonce, _, ok := lookupContext(contextID)
		if !ok || nonce == "" {
			c.JSON(460, gin.H{
				"code":    "ASH_PROOF_INVALID",
				"message": "Unknown or expired context",
			})
			c.Abort()
			return
		}

		// 4. Normalize binding from the incoming request
		binding, err := ash.AshNormalizeBinding(c.Request.Method, c.Request.URL.Path, c.Request.URL.RawQuery)
		if err != nil {
			c.JSON(460, gin.H{
				"code":    "ASH_PROOF_INVALID",
				"message": "Failed to normalize binding",
			})
			c.Abort()
			return
		}

		// 5. Canonicalize and hash body
		canonical, err := ash.AshCanonicalizeJSON(body)
		if err != nil {
			c.JSON(460, gin.H{
				"code":    "ASH_PROOF_INVALID",
				"message": "Failed to canonicalize request body",
			})
			c.Abort()
			return
		}
		bodyHash := ash.AshHashBody(canonical)

		// 6. Derive client secret
		clientSecret := ash.AshDeriveClientSecret(nonce, contextID, binding)

		// 7. Verify the proof
		valid := ash.AshVerifyProof(clientSecret, timestamp, binding, bodyHash, clientProof)

		if valid {
			// NOTE: In production, replay protection (context consumption) should be
			// implemented here to prevent the same context from being reused.
			c.Next()
			return
		}

		c.JSON(460, gin.H{
			"code":    "ASH_PROOF_INVALID",
			"message": "Proof verification failed",
		})
		c.Abort()
	}
}
