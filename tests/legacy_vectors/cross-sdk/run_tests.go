// Cross-SDK Test Vector Runner for Go
//
// Runs the standard ASH test vectors against the Go SDK to verify
// interoperability with other language implementations.
//
// Usage:
//
//	go run run_tests.go
//	go run run_tests.go -verbose
//	go run run_tests.go -category canonicalization
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ash "github.com/3maem/ash-go-sdk"
)

// TestVectors represents the test vectors JSON structure
type TestVectors struct {
	Canonicalization struct {
		Vectors []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Input       string `json:"input"`
			Expected    string `json:"expected"`
		} `json:"vectors"`
	} `json:"canonicalization"`
	URLEncodedCanonicalization struct {
		Vectors []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Input       string `json:"input"`
			Expected    string `json:"expected"`
		} `json:"vectors"`
	} `json:"urlencoded_canonicalization"`
	BindingNormalization struct {
		Vectors []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Method      string `json:"method"`
			Path        string `json:"path"`
			Query       string `json:"query"`
			Expected    string `json:"expected"`
		} `json:"vectors"`
	} `json:"binding_normalization"`
	TimingSafeEqual struct {
		Vectors []struct {
			ID       string `json:"id"`
			A        string `json:"a"`
			B        string `json:"b"`
			Expected bool   `json:"expected"`
		} `json:"vectors"`
	} `json:"timing_safe_equal"`
}

func loadTestVectors() (*TestVectors, error) {
	// Get the directory of this script
	execPath, err := os.Executable()
	if err != nil {
		execPath = "."
	}
	dir := filepath.Dir(execPath)

	// Try current directory first
	vectorsPath := filepath.Join(dir, "test-vectors.json")
	if _, err := os.Stat(vectorsPath); os.IsNotExist(err) {
		// Try relative path from where go run is executed
		vectorsPath = "tests/cross-sdk/test-vectors.json"
	}

	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test vectors: %w", err)
	}

	var vectors TestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		return nil, fmt.Errorf("failed to parse test vectors: %w", err)
	}

	return &vectors, nil
}

func runCanonicalizationTests(vectors *TestVectors, verbose bool) (int, int) {
	fmt.Println("\n=== JSON Canonicalization Tests ===")
	passed := 0
	failed := 0

	for _, test := range vectors.Canonicalization.Vectors {
		result, err := ash.CanonicalizeJSON(test.Input)
		if err != nil {
			failed++
			fmt.Printf("  ✗ %s: %s\n", test.ID, test.Description)
			fmt.Printf("    Error: %v\n", err)
			continue
		}

		if result == test.Expected {
			passed++
			if verbose {
				fmt.Printf("  ✓ %s: %s\n", test.ID, test.Description)
			}
		} else {
			failed++
			fmt.Printf("  ✗ %s: %s\n", test.ID, test.Description)
			fmt.Printf("    Expected: %s\n", test.Expected)
			fmt.Printf("    Got:      %s\n", result)
		}
	}

	fmt.Printf("\nCanonicalization: %d passed, %d failed\n", passed, failed)
	return passed, failed
}

func runURLEncodedTests(vectors *TestVectors, verbose bool) (int, int) {
	fmt.Println("\n=== URL-Encoded Canonicalization Tests ===")
	passed := 0
	failed := 0

	for _, test := range vectors.URLEncodedCanonicalization.Vectors {
		result, err := ash.CanonicalizeURLEncoded(test.Input)
		if err != nil {
			failed++
			fmt.Printf("  ✗ %s: %s\n", test.ID, test.Description)
			fmt.Printf("    Error: %v\n", err)
			continue
		}

		if result == test.Expected {
			passed++
			if verbose {
				fmt.Printf("  ✓ %s: %s\n", test.ID, test.Description)
			}
		} else {
			failed++
			fmt.Printf("  ✗ %s: %s\n", test.ID, test.Description)
			fmt.Printf("    Expected: %s\n", test.Expected)
			fmt.Printf("    Got:      %s\n", result)
		}
	}

	fmt.Printf("\nURL-Encoded: %d passed, %d failed\n", passed, failed)
	return passed, failed
}

func runBindingTests(vectors *TestVectors, verbose bool) (int, int) {
	fmt.Println("\n=== Binding Normalization Tests ===")
	passed := 0
	failed := 0

	for _, test := range vectors.BindingNormalization.Vectors {
		result, err := ash.NormalizeBinding(test.Method, test.Path, test.Query)
		if err != nil {
			failed++
			fmt.Printf("  ✗ %s: %s\n", test.ID, test.Description)
			fmt.Printf("    Error: %v\n", err)
			continue
		}

		if result == test.Expected {
			passed++
			if verbose {
				fmt.Printf("  ✓ %s: %s\n", test.ID, test.Description)
			}
		} else {
			failed++
			fmt.Printf("  ✗ %s: %s\n", test.ID, test.Description)
			fmt.Printf("    Expected: %s\n", test.Expected)
			fmt.Printf("    Got:      %s\n", result)
		}
	}

	fmt.Printf("\nBinding: %d passed, %d failed\n", passed, failed)
	return passed, failed
}

func runTimingSafeTests(vectors *TestVectors, verbose bool) (int, int) {
	fmt.Println("\n=== Timing-Safe Comparison Tests ===")
	passed := 0
	failed := 0

	for _, test := range vectors.TimingSafeEqual.Vectors {
		result := ash.TimingSafeCompare(test.A, test.B)

		if result == test.Expected {
			passed++
			if verbose {
				fmt.Printf("  ✓ %s: a=%q, b=%q\n", test.ID, test.A, test.B)
			}
		} else {
			failed++
			fmt.Printf("  ✗ %s: a=%q, b=%q\n", test.ID, test.A, test.B)
			fmt.Printf("    Expected: %v\n", test.Expected)
			fmt.Printf("    Got:      %v\n", result)
		}
	}

	fmt.Printf("\nTiming-Safe: %d passed, %d failed\n", passed, failed)
	return passed, failed
}

func main() {
	verbose := flag.Bool("verbose", false, "Show all test results")
	category := flag.String("category", "", "Run specific category only")
	flag.Parse()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("ASH Cross-SDK Test Vector Runner - Go")
	fmt.Println(strings.Repeat("=", 60))

	vectors, err := loadTestVectors()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}

	totalPassed := 0
	totalFailed := 0

	categories := map[string]func(*TestVectors, bool) (int, int){
		"canonicalization": runCanonicalizationTests,
		"urlencoded":       runURLEncodedTests,
		"binding":          runBindingTests,
		"timing":           runTimingSafeTests,
	}

	if *category != "" {
		if fn, ok := categories[*category]; ok {
			p, f := fn(vectors, *verbose)
			totalPassed += p
			totalFailed += f
		} else {
			fmt.Printf("Unknown category: %s\n", *category)
			fmt.Print("Available: ")
			for k := range categories {
				fmt.Printf("%s ", k)
			}
			fmt.Println()
			os.Exit(1)
		}
	} else {
		for _, fn := range categories {
			p, f := fn(vectors, *verbose)
			totalPassed += p
			totalFailed += f
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("TOTAL: %d passed, %d failed\n", totalPassed, totalFailed)
	fmt.Println(strings.Repeat("=", 60))

	if totalFailed > 0 {
		os.Exit(1)
	}
}
