/*
ASH Protocol - Go HTTP Example

This example demonstrates:
1. Server: Issuing contexts and verifying requests
2. Client: Getting context, building proof, sending verified request

Run: go run main.go

The program runs the server and client in one process for demonstration.
*/
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// ASH Implementation (simplified for demonstration)
// In production, use the github.com/3maem/ash-go-sdk package
// =============================================================================

const ASHVersion = "ASHv1"

// Context represents a stored ASH context
type Context struct {
	ID        string `json:"contextId"`
	Binding   string `json:"binding"`
	Mode      string `json:"mode"`
	ExpiresAt int64  `json:"expiresAt"`
	Used      bool   `json:"-"`
	Nonce     string `json:"nonce,omitempty"`
}

// ContextStore is an in-memory store (use Redis in production)
type ContextStore struct {
	mu       sync.RWMutex
	contexts map[string]*Context
}

func NewContextStore() *ContextStore {
	return &ContextStore{
		contexts: make(map[string]*Context),
	}
}

func (s *ContextStore) Set(ctx *Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contexts[ctx.ID] = ctx
}

func (s *ContextStore) Get(id string) *Context {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.contexts[id]
}

func (s *ContextStore) MarkUsed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx, ok := s.contexts[id]; ok && !ctx.Used {
		ctx.Used = true
		return true
	}
	return false
}

func (s *ContextStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.contexts)
}

// generateContextID generates a unique context ID
func generateContextID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "ctx_" + hex.EncodeToString(b)
}

// generateNonce generates a server nonce
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// canonicalizeJSON canonicalizes JSON to deterministic form
// - Minified (no whitespace)
// - Object keys sorted alphabetically
// - Arrays preserve order
func canonicalizeJSON(v interface{}) (string, error) {
	switch val := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case float64:
		// Handle -0 -> 0
		if val == 0 {
			return "0", nil
		}
		// Integer check
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val)), nil
		}
		return fmt.Sprintf("%v", val), nil
	case string:
		b, _ := json.Marshal(val)
		return string(b), nil
	case []interface{}:
		parts := make([]string, len(val))
		for i, item := range val {
			s, err := canonicalizeJSON(item)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]interface{}:
		// Sort keys alphabetically
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		pairs := make([]string, len(keys))
		for i, k := range keys {
			keyJSON, _ := json.Marshal(k)
			valJSON, err := canonicalizeJSON(val[k])
			if err != nil {
				return "", err
			}
			pairs[i] = string(keyJSON) + ":" + valJSON
		}
		return "{" + strings.Join(pairs, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported type: %T", v)
	}
}

// buildProof builds an ASH proof
//
// Proof = SHA256(
//
//	"ASHv1" + "\n" +
//	mode + "\n" +
//	binding + "\n" +
//	contextId + "\n" +
//	(nonce? + "\n" : "") +
//	canonicalPayload
//
// )
//
// Output: Base64URL encoded (no padding)
func buildProof(mode, binding, contextID, nonce, canonicalPayload string) string {
	var sb strings.Builder
	sb.WriteString(ASHVersion)
	sb.WriteByte('\n')
	sb.WriteString(mode)
	sb.WriteByte('\n')
	sb.WriteString(binding)
	sb.WriteByte('\n')
	sb.WriteString(contextID)
	sb.WriteByte('\n')

	// Add nonce if present (strict mode)
	if nonce != "" {
		sb.WriteString(nonce)
		sb.WriteByte('\n')
	}

	sb.WriteString(canonicalPayload)

	// Hash with SHA-256
	hash := sha256.Sum256([]byte(sb.String()))

	// Encode as Base64URL (no padding)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// timingSafeEqual compares two strings in constant time
func timingSafeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

// =============================================================================
// Server Implementation
// =============================================================================

type Server struct {
	store *ContextStore
}

func NewServer() *Server {
	return &Server{
		store: NewContextStore(),
	}
}

// handleContext issues a new ASH context
func (s *Server) handleContext(w http.ResponseWriter, r *http.Request) {
	// Step 1: Determine binding and mode
	binding := r.URL.Query().Get("binding")
	if binding == "" {
		binding = "POST /api/protected"
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "balanced"
	}

	// Step 2: Generate context ID
	contextID := generateContextID()

	// Step 3: Calculate expiration (30 seconds)
	ttlMs := int64(30000)
	expiresAt := time.Now().UnixMilli() + ttlMs

	// Step 4: Generate nonce for strict mode
	var nonce string
	if mode == "strict" {
		nonce = generateNonce()
	}

	// Step 5: Store context
	ctx := &Context{
		ID:        contextID,
		Binding:   binding,
		Mode:      mode,
		ExpiresAt: expiresAt,
		Used:      false,
		Nonce:     nonce,
	}
	s.store.Set(ctx)

	fmt.Printf("[ASH] Issued context: %s for %s\n", contextID, binding)

	// Step 6: Return context to client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ctx)
}

// handleProtected handles protected endpoint requests
func (s *Server) handleProtected(w http.ResponseWriter, r *http.Request) {
	// Step 1: Extract ASH headers
	contextID := r.Header.Get("X-ASH-Context")
	clientProof := r.Header.Get("X-ASH-Proof")

	if contextID == "" || clientProof == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_MISSING_HEADERS",
			"message": "Missing X-ASH-Context or X-ASH-Proof headers",
		})
		return
	}

	// Step 2: Retrieve context from store
	ctx := s.store.Get(contextID)
	if ctx == nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_INVALID_CONTEXT",
			"message": "Context not found or expired",
		})
		return
	}

	// Step 3: Check if context expired
	if time.Now().UnixMilli() > ctx.ExpiresAt {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_CONTEXT_EXPIRED",
			"message": "Context has expired",
		})
		return
	}

	// Step 4: Check for replay (already used)
	if ctx.Used {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_REPLAY_DETECTED",
			"message": "Context already used (replay attack detected)",
		})
		return
	}

	// Step 5: Verify binding matches
	expectedBinding := "POST /api/protected"
	if ctx.Binding != expectedBinding {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_ENDPOINT_MISMATCH",
			"message": fmt.Sprintf("Binding mismatch: expected %s, got %s", ctx.Binding, expectedBinding),
		})
		return
	}

	// Step 6: Read and parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_MALFORMED_REQUEST",
			"message": "Failed to read request body",
		})
		return
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_CANONICALIZATION_FAILED",
			"message": "Failed to parse JSON payload",
		})
		return
	}

	// Step 7: Canonicalize the payload
	canonicalPayload, err := canonicalizeJSON(payload)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_CANONICALIZATION_FAILED",
			"message": "Failed to canonicalize payload",
		})
		return
	}

	// Step 8: Build expected proof
	expectedProof := buildProof(ctx.Mode, ctx.Binding, contextID, ctx.Nonce, canonicalPayload)

	// Step 9: Verify proof using constant-time comparison
	if !timingSafeEqual(expectedProof, clientProof) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_INTEGRITY_FAILED",
			"message": "Proof verification failed - request may have been tampered",
		})
		return
	}

	// Step 10: Mark context as used (prevents replay)
	if !s.store.MarkUsed(contextID) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "ASH_REPLAY_DETECTED",
			"message": "Context already used (replay attack detected)",
		})
		return
	}

	fmt.Printf("[ASH] Verified request with context: %s\n", contextID)

	// Step 11: Process the verified request
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Request verified and processed",
		"data":    payload,
	})
}

// handleHealth returns health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"contexts": s.store.Size(),
	})
}

// =============================================================================
// Client Implementation
// =============================================================================

func runClient() {
	fmt.Println("=== ASH Protocol Client Example ===\n")

	baseURL := "http://localhost:8080"

	// The data we want to send
	requestData := map[string]interface{}{
		"action": "update",
		"userId": float64(123),
		"settings": map[string]interface{}{
			"notifications": true,
			"theme":         "dark",
		},
	}

	// =========================================================================
	// Step 1: Get a context from the server
	// =========================================================================
	fmt.Println("Step 1: Requesting context from server...")

	binding := "POST /api/protected"
	contextResp, err := http.Get(baseURL + "/api/context?binding=" + binding)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	defer contextResp.Body.Close()

	var ctx Context
	if err := json.NewDecoder(contextResp.Body).Decode(&ctx); err != nil {
		fmt.Printf("  Error decoding context: %v\n", err)
		return
	}
	fmt.Printf("  Context received: contextId=%s, binding=%s, mode=%s\n",
		ctx.ID, ctx.Binding, ctx.Mode)

	// =========================================================================
	// Step 2: Canonicalize the payload
	// =========================================================================
	fmt.Println("\nStep 2: Canonicalizing payload...")

	canonicalPayload, err := canonicalizeJSON(requestData)
	if err != nil {
		fmt.Printf("  Error canonicalizing: %v\n", err)
		return
	}
	originalJSON, _ := json.Marshal(requestData)
	fmt.Printf("  Original: %s\n", originalJSON)
	fmt.Printf("  Canonical: %s\n", canonicalPayload)

	// =========================================================================
	// Step 3: Build the ASH proof
	// =========================================================================
	fmt.Println("\nStep 3: Building ASH proof...")

	proof := buildProof(
		ctx.Mode,        // Security mode (balanced)
		ctx.Binding,     // Endpoint binding (POST /api/protected)
		ctx.ID,          // Server-issued context ID
		ctx.Nonce,       // Server nonce (for strict mode)
		canonicalPayload, // Canonicalized request body
	)
	fmt.Printf("  Proof: %s\n", proof)

	// =========================================================================
	// Step 4: Send the protected request
	// =========================================================================
	fmt.Println("\nStep 4: Sending protected request...")

	bodyBytes, _ := json.Marshal(requestData)
	req, _ := http.NewRequest("POST", baseURL+"/api/protected", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ASH-Context", ctx.ID) // Include context ID
	req.Header.Set("X-ASH-Proof", proof)    // Include computed proof

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("  Success! Response: %v\n", result)
	} else {
		fmt.Printf("  Failed! Error: %v\n", result)
	}

	// =========================================================================
	// Step 5: Demonstrate replay protection
	// =========================================================================
	fmt.Println("\nStep 5: Attempting replay attack (same context)...")

	req2, _ := http.NewRequest("POST", baseURL+"/api/protected", bytes.NewReader(bodyBytes))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-ASH-Context", ctx.ID)
	req2.Header.Set("X-ASH-Proof", proof)

	resp2, _ := http.DefaultClient.Do(req2)
	defer resp2.Body.Close()

	var replayResult map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&replayResult)
	fmt.Printf("  Replay attempt result: %v\n", replayResult)
	fmt.Println("  (Expected: ASH_REPLAY_DETECTED)")

	// =========================================================================
	// Step 6: Demonstrate tamper protection
	// =========================================================================
	fmt.Println("\nStep 6: Attempting tampered request...")

	// Get a new context for the tamper test
	ctx2Resp, _ := http.Get(baseURL + "/api/context?binding=" + binding)
	var ctx2 Context
	json.NewDecoder(ctx2Resp.Body).Decode(&ctx2)
	ctx2Resp.Body.Close()

	// Build proof with original data
	originalData := map[string]interface{}{"amount": float64(100)}
	originalCanonical, _ := canonicalizeJSON(originalData)
	originalProof := buildProof(ctx2.Mode, ctx2.Binding, ctx2.ID, ctx2.Nonce, originalCanonical)

	// But send different data (tampered!)
	tamperedData := map[string]interface{}{"amount": float64(1000000)}
	tamperedBytes, _ := json.Marshal(tamperedData)

	req3, _ := http.NewRequest("POST", baseURL+"/api/protected", bytes.NewReader(tamperedBytes))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-ASH-Context", ctx2.ID)
	req3.Header.Set("X-ASH-Proof", originalProof) // Proof for original data

	resp3, _ := http.DefaultClient.Do(req3)
	defer resp3.Body.Close()

	var tamperResult map[string]interface{}
	json.NewDecoder(resp3.Body).Decode(&tamperResult)
	fmt.Printf("  Tamper attempt result: %v\n", tamperResult)
	fmt.Println("  (Expected: ASH_INTEGRITY_FAILED)")
}

// =============================================================================
// Main
// =============================================================================

func main() {
	// Create server
	server := NewServer()

	// Setup routes
	http.HandleFunc("/api/context", server.handleContext)
	http.HandleFunc("/api/protected", server.handleProtected)
	http.HandleFunc("/health", server.handleHealth)

	// Start server in background
	go func() {
		fmt.Println("ASH Go HTTP Example Server running on http://localhost:8080")
		fmt.Println("")
		fmt.Println("Endpoints:")
		fmt.Println("  GET  /api/context    - Issue a new context")
		fmt.Println("  POST /api/protected  - Protected endpoint (requires ASH)")
		fmt.Println("  GET  /health         - Health check")
		fmt.Println("")

		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Run client demo
	fmt.Println("--- Running Client Demo ---\n")
	runClient()

	fmt.Println("\n--- Demo Complete ---")
	fmt.Println("Press Ctrl+C to stop the server, or it will keep running.")

	// Keep server running
	select {}
}
