//! Cross-SDK Test Vector Runner for Rust
//!
//! Runs the standard ASH test vectors against the Rust SDK to verify
//! interoperability with other language implementations.
//!
//! Usage:
//!     cargo run --bin run_tests
//!     cargo run --bin run_tests -- --verbose
//!     cargo run --bin run_tests -- --category canonicalization

use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

// Import ASH core functions
use ashcore::{
    canonicalize_json, canonicalize_urlencoded, normalize_binding, timing_safe_equal,
};

#[derive(Debug, Deserialize)]
struct TestVectors {
    canonicalization: CanonicalizationSection,
    urlencoded_canonicalization: UrlencodedSection,
    binding_normalization: BindingSection,
    timing_safe_equal: TimingSafeSection,
}

#[derive(Debug, Deserialize)]
struct CanonicalizationSection {
    vectors: Vec<CanonicalizationVector>,
}

#[derive(Debug, Deserialize)]
struct CanonicalizationVector {
    id: String,
    description: String,
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct UrlencodedSection {
    vectors: Vec<UrlencodedVector>,
}

#[derive(Debug, Deserialize)]
struct UrlencodedVector {
    id: String,
    description: String,
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct BindingSection {
    vectors: Vec<BindingVector>,
}

#[derive(Debug, Deserialize)]
struct BindingVector {
    id: String,
    description: String,
    method: String,
    path: String,
    query: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct TimingSafeSection {
    vectors: Vec<TimingSafeVector>,
}

#[derive(Debug, Deserialize)]
struct TimingSafeVector {
    id: String,
    a: String,
    b: String,
    expected: bool,
}

fn load_test_vectors() -> Result<TestVectors, Box<dyn std::error::Error>> {
    // Try current directory first
    let paths = vec![
        "test-vectors.json",
        "tests/cross-sdk/test-vectors.json",
        "../tests/cross-sdk/test-vectors.json",
    ];

    for path in paths {
        if Path::new(path).exists() {
            let content = fs::read_to_string(path)?;
            return Ok(serde_json::from_str(&content)?);
        }
    }

    Err("Could not find test-vectors.json".into())
}

fn run_canonicalization_tests(vectors: &TestVectors, verbose: bool) -> (usize, usize) {
    println!("\n=== JSON Canonicalization Tests ===");
    let mut passed = 0;
    let mut failed = 0;

    for test in &vectors.canonicalization.vectors {
        match canonicalize_json(&test.input) {
            Ok(result) => {
                if result == test.expected {
                    passed += 1;
                    if verbose {
                        println!("  ✓ {}: {}", test.id, test.description);
                    }
                } else {
                    failed += 1;
                    println!("  ✗ {}: {}", test.id, test.description);
                    println!("    Expected: {}", test.expected);
                    println!("    Got:      {}", result);
                }
            }
            Err(e) => {
                failed += 1;
                println!("  ✗ {}: {}", test.id, test.description);
                println!("    Error: {}", e);
            }
        }
    }

    println!("\nCanonicalization: {} passed, {} failed", passed, failed);
    (passed, failed)
}

fn run_urlencoded_tests(vectors: &TestVectors, verbose: bool) -> (usize, usize) {
    println!("\n=== URL-Encoded Canonicalization Tests ===");
    let mut passed = 0;
    let mut failed = 0;

    for test in &vectors.urlencoded_canonicalization.vectors {
        match canonicalize_urlencoded(&test.input) {
            Ok(result) => {
                if result == test.expected {
                    passed += 1;
                    if verbose {
                        println!("  ✓ {}: {}", test.id, test.description);
                    }
                } else {
                    failed += 1;
                    println!("  ✗ {}: {}", test.id, test.description);
                    println!("    Expected: {}", test.expected);
                    println!("    Got:      {}", result);
                }
            }
            Err(e) => {
                failed += 1;
                println!("  ✗ {}: {}", test.id, test.description);
                println!("    Error: {}", e);
            }
        }
    }

    println!("\nURL-Encoded: {} passed, {} failed", passed, failed);
    (passed, failed)
}

fn run_binding_tests(vectors: &TestVectors, verbose: bool) -> (usize, usize) {
    println!("\n=== Binding Normalization Tests ===");
    let mut passed = 0;
    let mut failed = 0;

    for test in &vectors.binding_normalization.vectors {
        match normalize_binding(&test.method, &test.path, &test.query) {
            Ok(result) => {
                if result == test.expected {
                    passed += 1;
                    if verbose {
                        println!("  ✓ {}: {}", test.id, test.description);
                    }
                } else {
                    failed += 1;
                    println!("  ✗ {}: {}", test.id, test.description);
                    println!("    Expected: {}", test.expected);
                    println!("    Got:      {}", result);
                }
            }
            Err(e) => {
                failed += 1;
                println!("  ✗ {}: {}", test.id, test.description);
                println!("    Error: {}", e);
            }
        }
    }

    println!("\nBinding: {} passed, {} failed", passed, failed);
    (passed, failed)
}

fn run_timing_safe_tests(vectors: &TestVectors, verbose: bool) -> (usize, usize) {
    println!("\n=== Timing-Safe Comparison Tests ===");
    let mut passed = 0;
    let mut failed = 0;

    for test in &vectors.timing_safe_equal.vectors {
        let result = timing_safe_equal(&test.a, &test.b);
        if result == test.expected {
            passed += 1;
            if verbose {
                println!("  ✓ {}: a=\"{}\", b=\"{}\"", test.id, test.a, test.b);
            }
        } else {
            failed += 1;
            println!("  ✗ {}: a=\"{}\", b=\"{}\"", test.id, test.a, test.b);
            println!("    Expected: {}", test.expected);
            println!("    Got:      {}", result);
        }
    }

    println!("\nTiming-Safe: {} passed, {} failed", passed, failed);
    (passed, failed)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let verbose = args.contains(&"--verbose".to_string()) || args.contains(&"-v".to_string());

    let category = args
        .iter()
        .position(|a| a == "--category" || a == "-c")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    println!("{}", "=".repeat(60));
    println!("ASH Cross-SDK Test Vector Runner - Rust");
    println!("{}", "=".repeat(60));

    let vectors = match load_test_vectors() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    };

    let mut total_passed = 0;
    let mut total_failed = 0;

    type TestFn = fn(&TestVectors, bool) -> (usize, usize);
    let categories: HashMap<&str, TestFn> = [
        ("canonicalization", run_canonicalization_tests as TestFn),
        ("urlencoded", run_urlencoded_tests as TestFn),
        ("binding", run_binding_tests as TestFn),
        ("timing", run_timing_safe_tests as TestFn),
    ]
    .into_iter()
    .collect();

    if let Some(cat) = category {
        if let Some(func) = categories.get(cat) {
            let (p, f) = func(&vectors, verbose);
            total_passed += p;
            total_failed += f;
        } else {
            eprintln!("Unknown category: {}", cat);
            eprint!("Available: ");
            for k in categories.keys() {
                eprint!("{} ", k);
            }
            eprintln!();
            std::process::exit(1);
        }
    } else {
        for func in categories.values() {
            let (p, f) = func(&vectors, verbose);
            total_passed += p;
            total_failed += f;
        }
    }

    println!();
    println!("{}", "=".repeat(60));
    println!("TOTAL: {} passed, {} failed", total_passed, total_failed);
    println!("{}", "=".repeat(60));

    if total_failed > 0 {
        std::process::exit(1);
    }
}
