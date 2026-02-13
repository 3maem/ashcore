#!/usr/bin/env python3
"""
Cross-SDK Test Vector Runner for Python

Runs the standard ASH test vectors against the Python SDK to verify
interoperability with other language implementations.

Usage:
    python run_tests.py
    python run_tests.py --verbose
    python run_tests.py --category canonicalization
"""

import json
import sys
import argparse
from pathlib import Path

# Add the SDK to path
SDK_PATH = Path(__file__).parent.parent.parent / "packages" / "ash-python-sdk" / "src"
sys.path.insert(0, str(SDK_PATH))

try:
    from ash.core import (
        canonicalize_json,
        canonicalize_url_encoded,
        normalize_binding,
        hash_body,
        timing_safe_compare,
    )
    SDK_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import ash SDK: {e}")
    SDK_AVAILABLE = False


def load_test_vectors():
    """Load test vectors from JSON file."""
    vectors_path = Path(__file__).parent / "test-vectors.json"
    with open(vectors_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_canonicalization_tests(vectors, verbose=False):
    """Run JSON canonicalization test vectors."""
    print("\n=== JSON Canonicalization Tests ===")
    passed = 0
    failed = 0

    for test in vectors["canonicalization"]["vectors"]:
        try:
            # Parse input JSON string to Python object first
            input_obj = json.loads(test["input"])
            result = canonicalize_json(input_obj)
            if result == test["expected"]:
                passed += 1
                if verbose:
                    print(f"  [PASS] {test['id']}: {test['description']}")
            else:
                failed += 1
                print(f"  [FAIL] {test['id']}: {test['description']}")
                print(f"    Expected: {test['expected']}")
                print(f"    Got:      {result}")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {test['id']}: {test['description']}")
            print(f"    Error: {e}")

    print(f"\nCanonicalisation: {passed} passed, {failed} failed")
    return passed, failed


def run_urlencoded_tests(vectors, verbose=False):
    """Run URL-encoded canonicalization test vectors."""
    print("\n=== URL-Encoded Canonicalization Tests ===")
    passed = 0
    failed = 0

    for test in vectors["urlencoded_canonicalization"]["vectors"]:
        try:
            result = canonicalize_url_encoded(test["input"])
            if result == test["expected"]:
                passed += 1
                if verbose:
                    print(f"  [PASS] {test['id']}: {test['description']}")
            else:
                failed += 1
                print(f"  [FAIL] {test['id']}: {test['description']}")
                print(f"    Expected: {test['expected']}")
                print(f"    Got:      {result}")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {test['id']}: {test['description']}")
            print(f"    Error: {e}")

    print(f"\nURL-Encoded: {passed} passed, {failed} failed")
    return passed, failed


def run_binding_tests(vectors, verbose=False):
    """Run binding normalization test vectors."""
    print("\n=== Binding Normalization Tests ===")
    passed = 0
    failed = 0

    for test in vectors["binding_normalization"]["vectors"]:
        try:
            result = normalize_binding(test["method"], test["path"], test["query"])
            if result == test["expected"]:
                passed += 1
                if verbose:
                    print(f"  [PASS] {test['id']}: {test['description']}")
            else:
                failed += 1
                print(f"  [FAIL] {test['id']}: {test['description']}")
                print(f"    Expected: {test['expected']}")
                print(f"    Got:      {result}")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {test['id']}: {test['description']}")
            print(f"    Error: {e}")

    print(f"\nBinding: {passed} passed, {failed} failed")
    return passed, failed


def run_timing_safe_tests(vectors, verbose=False):
    """Run timing-safe comparison test vectors."""
    print("\n=== Timing-Safe Comparison Tests ===")
    passed = 0
    failed = 0

    for test in vectors["timing_safe_equal"]["vectors"]:
        try:
            result = timing_safe_compare(test["a"], test["b"])
            if result == test["expected"]:
                passed += 1
                if verbose:
                    print(f"  [PASS] {test['id']}: a={repr(test['a'])}, b={repr(test['b'])}")
            else:
                failed += 1
                print(f"  [FAIL] {test['id']}: a={repr(test['a'])}, b={repr(test['b'])}")
                print(f"    Expected: {test['expected']}")
                print(f"    Got:      {result}")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {test['id']}")
            print(f"    Error: {e}")

    print(f"\nTiming-Safe: {passed} passed, {failed} failed")
    return passed, failed


def main():
    parser = argparse.ArgumentParser(description="Run ASH cross-SDK test vectors")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all test results")
    parser.add_argument("--category", "-c", help="Run specific category only")
    args = parser.parse_args()

    if not SDK_AVAILABLE:
        print("ERROR: ASH Python SDK not available")
        print("Install with: pip install -e packages/ash-python-sdk")
        sys.exit(1)

    print("=" * 60)
    print("ASH Cross-SDK Test Vector Runner - Python")
    print("=" * 60)

    vectors = load_test_vectors()
    total_passed = 0
    total_failed = 0

    categories = {
        "canonicalization": run_canonicalization_tests,
        "urlencoded": run_urlencoded_tests,
        "binding": run_binding_tests,
        "timing": run_timing_safe_tests,
    }

    if args.category:
        if args.category in categories:
            p, f = categories[args.category](vectors, args.verbose)
            total_passed += p
            total_failed += f
        else:
            print(f"Unknown category: {args.category}")
            print(f"Available: {', '.join(categories.keys())}")
            sys.exit(1)
    else:
        for name, func in categories.items():
            p, f = func(vectors, args.verbose)
            total_passed += p
            total_failed += f

    print("\n" + "=" * 60)
    print(f"TOTAL: {total_passed} passed, {total_failed} failed")
    print("=" * 60)

    sys.exit(0 if total_failed == 0 else 1)


if __name__ == "__main__":
    main()
