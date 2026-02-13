package ash

import (
	"strings"
	"testing"
)

// ============================================================================
// Cross-SDK Test Vectors for ASH v2.3.2
//
// These test vectors MUST produce identical results across all SDK implementations.
// Any SDK that fails these tests is not compliant with the ASH specification.
// ============================================================================

// FIXED TEST VECTORS - DO NOT MODIFY
const (
	TestNonce     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	TestContextID = "ash_test_ctx_12345"
	TestBinding   = "POST|/api/transfer|"
	TestTimestamp = "1704067200000" // 2024-01-01 00:00:00 UTC in ms
)

// ============================================================================
// JSON Canonicalization Tests (RFC 8785 JCS)
// ============================================================================

func TestVectorJsonSimpleObject(t *testing.T) {
	input := map[string]interface{}{"z": float64(1), "a": float64(2), "m": float64(3)}
	expected := `{"a":2,"m":3,"z":1}`
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestVectorJsonNestedObject(t *testing.T) {
	input := map[string]interface{}{
		"outer": map[string]interface{}{"z": float64(1), "a": float64(2)},
		"inner": map[string]interface{}{"b": float64(2), "a": float64(1)},
	}
	expected := `{"inner":{"a":1,"b":2},"outer":{"a":2,"z":1}}`
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestVectorJsonArrayPreservesOrder(t *testing.T) {
	input := map[string]interface{}{"arr": []interface{}{float64(3), float64(1), float64(2)}}
	expected := `{"arr":[3,1,2]}`
	result, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestVectorJsonEmptyValues(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected string
	}{
		{nil, "null"},
		{true, "true"},
		{false, "false"},
		{map[string]interface{}{}, "{}"},
		{[]interface{}{}, "[]"},
	}

	for _, tc := range tests {
		result, err := CanonicalizeJSON(tc.input)
		if err != nil {
			t.Fatalf("Unexpected error for input %v: %v", tc.input, err)
		}
		if result != tc.expected {
			t.Errorf("For input %v: expected %q, got %q", tc.input, tc.expected, result)
		}
	}
}

// ============================================================================
// Query String Canonicalization Tests
// ============================================================================

func TestVectorQuerySorted(t *testing.T) {
	result, err := CanonicalizeQuery("z=1&a=2&m=3")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=2&m=3&z=1" {
		t.Errorf("Expected a=2&m=3&z=1, got %q", result)
	}
}

func TestVectorQueryStripLeadingQuestionMark(t *testing.T) {
	result, err := CanonicalizeQuery("?a=1&b=2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=1&b=2" {
		t.Errorf("Expected a=1&b=2, got %q", result)
	}
}

func TestVectorQueryUppercaseHex(t *testing.T) {
	result, err := CanonicalizeQuery("a=%2f&b=%2F")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=%2F&b=%2F" {
		t.Errorf("Expected a=%%2F&b=%%2F, got %q", result)
	}
}

func TestVectorQueryPreserveEmptyValues(t *testing.T) {
	result, err := CanonicalizeQuery("a=&b=1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=&b=1" {
		t.Errorf("Expected a=&b=1, got %q", result)
	}
}

func TestVectorQueryDuplicateKeysSortedByValue(t *testing.T) {
	// Per ASH spec: sort by key first, then by value for duplicate keys
	result, err := CanonicalizeQuery("a=z&a=a&a=m")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=a&a=m&a=z" {
		t.Errorf("Expected a=a&a=m&a=z, got %q", result)
	}
}

func TestVectorUrlEncodedDuplicateKeysSortedByValue(t *testing.T) {
	// Per ASH spec: sort by key first, then by value for duplicate keys
	result, err := CanonicalizeURLEncoded("a=z&a=a&a=m")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=a&a=m&a=z" {
		t.Errorf("Expected a=a&a=m&a=z, got %q", result)
	}
}

// ============================================================================
// URL-Encoded Canonicalization Tests
// ============================================================================

func TestVectorUrlEncodedSorted(t *testing.T) {
	result, err := CanonicalizeURLEncoded("b=2&a=1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=1&b=2" {
		t.Errorf("Expected a=1&b=2, got %q", result)
	}
}

func TestVectorUrlEncodedPlusAsLiteral(t *testing.T) {
	// ASH protocol treats + as literal plus, not space
	result, err := CanonicalizeURLEncoded("a=hello+world")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=hello%2Bworld" {
		t.Errorf("Expected a=hello%%2Bworld, got %q", result)
	}
}

func TestVectorUrlEncodedUppercaseHex(t *testing.T) {
	result, err := CanonicalizeURLEncoded("a=hello%2fworld")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result != "a=hello%2Fworld" {
		t.Errorf("Expected a=hello%%2Fworld, got %q", result)
	}
}

// ============================================================================
// Binding Normalization Tests (v2.3.1+ format: METHOD|PATH|QUERY)
// ============================================================================

func TestVectorBindingSimple(t *testing.T) {
	result := NormalizeBinding("POST", "/api/test", "")
	if result != "POST|/api/test|" {
		t.Errorf("Expected POST|/api/test|, got %q", result)
	}
}

func TestVectorBindingLowercaseMethod(t *testing.T) {
	result := NormalizeBinding("post", "/api/test", "")
	if result != "POST|/api/test|" {
		t.Errorf("Expected POST|/api/test|, got %q", result)
	}
}

func TestVectorBindingWithQuery(t *testing.T) {
	result := NormalizeBinding("GET", "/api/users", "page=1&sort=name")
	if result != "GET|/api/users|page=1&sort=name" {
		t.Errorf("Expected GET|/api/users|page=1&sort=name, got %q", result)
	}
}

func TestVectorBindingQuerySorted(t *testing.T) {
	result := NormalizeBinding("GET", "/api/users", "z=1&a=2")
	if result != "GET|/api/users|a=2&z=1" {
		t.Errorf("Expected GET|/api/users|a=2&z=1, got %q", result)
	}
}

func TestVectorBindingCollapseSlashes(t *testing.T) {
	result := NormalizeBinding("GET", "/api//test///path", "")
	if result != "GET|/api/test/path|" {
		t.Errorf("Expected GET|/api/test/path|, got %q", result)
	}
}

func TestVectorBindingRemoveTrailingSlash(t *testing.T) {
	result := NormalizeBinding("GET", "/api/test/", "")
	if result != "GET|/api/test|" {
		t.Errorf("Expected GET|/api/test|, got %q", result)
	}
}

func TestVectorBindingPreserveRoot(t *testing.T) {
	result := NormalizeBinding("GET", "/", "")
	if result != "GET|/|" {
		t.Errorf("Expected GET|/|, got %q", result)
	}
}

func TestVectorBindingAddLeadingSlash(t *testing.T) {
	result := NormalizeBinding("GET", "api/test", "")
	if result != "GET|/api/test|" {
		t.Errorf("Expected GET|/api/test|, got %q", result)
	}
}

func TestVectorBindingStripFragment(t *testing.T) {
	result := NormalizeBinding("GET", "/api/test#section", "")
	if result != "GET|/api/test|" {
		t.Errorf("Expected GET|/api/test|, got %q", result)
	}
}

// ============================================================================
// Hash Body Tests (SHA-256 lowercase hex)
// ============================================================================

func TestVectorHashBodyKnownValue(t *testing.T) {
	result := HashBody("test")
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestVectorHashBodyEmpty(t *testing.T) {
	result := HashBody("")
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestVectorHashBodyFormat(t *testing.T) {
	result := HashBody(`{"amount":100,"recipient":"user123"}`)
	if len(result) != 64 {
		t.Errorf("Expected length 64, got %d", len(result))
	}
	if result != strings.ToLower(result) {
		t.Error("Expected lowercase hex")
	}
}

// ============================================================================
// Client Secret Derivation Tests (v2.1)
// ============================================================================

func TestVectorDeriveClientSecretDeterministic(t *testing.T) {
	secret1 := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	secret2 := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	if secret1 != secret2 {
		t.Error("DeriveClientSecret should be deterministic")
	}
}

func TestVectorDeriveClientSecretFormat(t *testing.T) {
	secret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	if len(secret) != 64 {
		t.Errorf("Expected length 64, got %d", len(secret))
	}
	if secret != strings.ToLower(secret) {
		t.Error("Expected lowercase hex")
	}
}

func TestVectorDeriveClientSecretDifferentInputs(t *testing.T) {
	secret1 := DeriveClientSecret(TestNonce, "ctx_a", TestBinding)
	secret2 := DeriveClientSecret(TestNonce, "ctx_b", TestBinding)
	if secret1 == secret2 {
		t.Error("Different inputs should produce different secrets")
	}
}

// ============================================================================
// v2.1 Proof Tests
// ============================================================================

func TestVectorBuildProofV21Deterministic(t *testing.T) {
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	bodyHash := HashBody(`{"amount":100}`)

	proof1 := BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash)
	proof2 := BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash)

	if proof1 != proof2 {
		t.Error("BuildProofV21 should be deterministic")
	}
}

func TestVectorBuildProofV21Format(t *testing.T) {
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	bodyHash := HashBody(`{"amount":100}`)

	proof := BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash)

	if len(proof) != 64 {
		t.Errorf("Expected length 64, got %d", len(proof))
	}
	if proof != strings.ToLower(proof) {
		t.Error("Expected lowercase hex")
	}
}

func TestVectorVerifyProofV21Valid(t *testing.T) {
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	bodyHash := HashBody(`{"amount":100}`)
	proof := BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash)

	valid := VerifyProofV21(TestNonce, TestContextID, TestBinding, TestTimestamp, bodyHash, proof)
	if !valid {
		t.Error("Expected valid proof")
	}
}

func TestVectorVerifyProofV21InvalidProof(t *testing.T) {
	bodyHash := HashBody(`{"amount":100}`)
	wrongProof := strings.Repeat("0", 64)

	valid := VerifyProofV21(TestNonce, TestContextID, TestBinding, TestTimestamp, bodyHash, wrongProof)
	if valid {
		t.Error("Expected invalid proof")
	}
}

func TestVectorVerifyProofV21WrongBody(t *testing.T) {
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	bodyHash1 := HashBody(`{"amount":100}`)
	bodyHash2 := HashBody(`{"amount":200}`)
	proof := BuildProofV21(clientSecret, TestTimestamp, TestBinding, bodyHash1)

	valid := VerifyProofV21(TestNonce, TestContextID, TestBinding, TestTimestamp, bodyHash2, proof)
	if valid {
		t.Error("Expected invalid proof with wrong body")
	}
}

// ============================================================================
// v2.3 Unified Proof Tests (with Scoping and Chaining)
// ============================================================================

func TestVectorBuildProofUnifiedBasicNoScopeNoChain(t *testing.T) {
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	payload := map[string]interface{}{"amount": float64(100), "note": "test"}

	result := BuildProofUnified(clientSecret, TestTimestamp, TestBinding, payload, nil, "")

	if len(result.Proof) != 64 {
		t.Errorf("Expected proof length 64, got %d", len(result.Proof))
	}
	if result.ScopeHash != "" {
		t.Errorf("Expected empty scope hash, got %q", result.ScopeHash)
	}
	if result.ChainHash != "" {
		t.Errorf("Expected empty chain hash, got %q", result.ChainHash)
	}

	// Verify
	valid := VerifyProofUnified(TestNonce, TestContextID, TestBinding, TestTimestamp, payload, result.Proof, nil, "", "", "")
	if !valid {
		t.Error("Expected valid proof")
	}
}

func TestVectorBuildProofUnifiedWithScope(t *testing.T) {
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, TestBinding)
	payload := map[string]interface{}{"amount": float64(100), "note": "test", "recipient": "user123"}
	scope := []string{"amount", "recipient"}

	result := BuildProofUnified(clientSecret, TestTimestamp, TestBinding, payload, scope, "")

	if result.ScopeHash == "" {
		t.Error("Expected non-empty scope hash")
	}
	if result.ChainHash != "" {
		t.Errorf("Expected empty chain hash, got %q", result.ChainHash)
	}

	// Verify
	valid := VerifyProofUnified(TestNonce, TestContextID, TestBinding, TestTimestamp, payload, result.Proof, scope, result.ScopeHash, "", "")
	if !valid {
		t.Error("Expected valid proof")
	}
}

func TestVectorBuildProofUnifiedWithChain(t *testing.T) {
	binding := "POST|/api/confirm|"
	clientSecret := DeriveClientSecret(TestNonce, TestContextID, binding)
	payload := map[string]interface{}{"confirmed": true}
	previousProof := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	result := BuildProofUnified(clientSecret, TestTimestamp, binding, payload, nil, previousProof)

	if result.ScopeHash != "" {
		t.Errorf("Expected empty scope hash, got %q", result.ScopeHash)
	}
	if result.ChainHash == "" {
		t.Error("Expected non-empty chain hash")
	}
	if result.ChainHash != HashProof(previousProof) {
		t.Errorf("Chain hash mismatch: expected %q, got %q", HashProof(previousProof), result.ChainHash)
	}

	// Verify
	valid := VerifyProofUnified(TestNonce, TestContextID, binding, TestTimestamp, payload, result.Proof, nil, "", previousProof, result.ChainHash)
	if !valid {
		t.Error("Expected valid proof")
	}
}

// ============================================================================
// Scoped Field Extraction Tests (ENH-003)
// ============================================================================

func TestVectorExtractScopedFieldsSimple(t *testing.T) {
	payload := map[string]interface{}{"amount": float64(100), "note": "test", "recipient": "user123"}
	scope := []string{"amount", "recipient"}

	result := ExtractScopedFields(payload, scope)

	if result["amount"] != float64(100) {
		t.Errorf("Expected amount=100, got %v", result["amount"])
	}
	if result["recipient"] != "user123" {
		t.Errorf("Expected recipient=user123, got %v", result["recipient"])
	}
	if _, exists := result["note"]; exists {
		t.Error("note should not be in result")
	}
}

func TestVectorExtractScopedFieldsNested(t *testing.T) {
	payload := map[string]interface{}{
		"user":   map[string]interface{}{"name": "John", "email": "john@example.com"},
		"amount": float64(100),
	}
	scope := []string{"user.name", "amount"}

	result := ExtractScopedFields(payload, scope)

	if result["amount"] != float64(100) {
		t.Errorf("Expected amount=100, got %v", result["amount"])
	}
	userMap, ok := result["user"].(map[string]interface{})
	if !ok {
		t.Fatal("user should be a map")
	}
	if userMap["name"] != "John" {
		t.Errorf("Expected user.name=John, got %v", userMap["name"])
	}
	if _, exists := userMap["email"]; exists {
		t.Error("user.email should not be in result")
	}
}

func TestVectorExtractScopedFieldsEmptyScope(t *testing.T) {
	payload := map[string]interface{}{"amount": float64(100), "note": "test"}
	scope := []string{}

	result := ExtractScopedFields(payload, scope)

	if len(result) != len(payload) {
		t.Error("Empty scope should return full payload")
	}
}

// ============================================================================
// Hash Proof Tests (for Chaining)
// ============================================================================

func TestVectorHashProofDeterministic(t *testing.T) {
	proof := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	hash1 := HashProof(proof)
	hash2 := HashProof(proof)
	if hash1 != hash2 {
		t.Error("HashProof should be deterministic")
	}
}

func TestVectorHashProofFormat(t *testing.T) {
	proof := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	hash := HashProof(proof)
	if len(hash) != 64 {
		t.Errorf("Expected length 64, got %d", len(hash))
	}
	if hash != strings.ToLower(hash) {
		t.Error("Expected lowercase hex")
	}
}

// ============================================================================
// Timing-Safe Comparison Tests
// ============================================================================

func TestVectorTimingSafeCompareEqual(t *testing.T) {
	if !TimingSafeCompare("hello", "hello") {
		t.Error("Expected true for equal strings")
	}
	if !TimingSafeCompare("", "") {
		t.Error("Expected true for empty strings")
	}
}

func TestVectorTimingSafeCompareNotEqual(t *testing.T) {
	if TimingSafeCompare("hello", "world") {
		t.Error("Expected false for different strings")
	}
	if TimingSafeCompare("hello", "hello!") {
		t.Error("Expected false for different length strings")
	}
	if TimingSafeCompare("hello", "") {
		t.Error("Expected false for empty comparison")
	}
}

// ============================================================================
// Fixed Test Vectors
// ============================================================================

func TestFixedVectorClientSecret(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	contextID := "ash_fixed_test_001"
	binding := "POST|/api/test|"

	secret := DeriveClientSecret(nonce, contextID, binding)

	if len(secret) != 64 {
		t.Errorf("Expected length 64, got %d", len(secret))
	}
	secret2 := DeriveClientSecret(nonce, contextID, binding)
	if secret != secret2 {
		t.Error("Expected deterministic secret")
	}
}

func TestFixedVectorBodyHash(t *testing.T) {
	payload := map[string]interface{}{"amount": float64(100), "recipient": "user123"}
	canonical, err := CanonicalizeJSON(payload)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	hash := HashBody(canonical)

	expectedCanonical := `{"amount":100,"recipient":"user123"}`
	if canonical != expectedCanonical {
		t.Errorf("Expected canonical %q, got %q", expectedCanonical, canonical)
	}
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}
}
