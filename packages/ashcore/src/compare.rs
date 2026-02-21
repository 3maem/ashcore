//! Constant-time comparison for timing-attack resistance.
//!
//! ## Why Constant-Time Comparison?
//!
//! Standard string comparison (`==`) stops at the first difference:
//!
//! ```text
//! "abc" == "xyz"  // Stops immediately (first char differs)
//! "abc" == "abd"  // Stops at third char
//! "abc" == "abc"  // Checks all chars
//! ```
//!
//! An attacker measuring response times can deduce how many characters
//! matched, gradually learning the secret value. This is a **timing attack**.
//!
//! ## How This Module Helps
//!
//! The functions in this module always take the same amount of time,
//! regardless of where (or if) differences occur:
//!
//! - Uses the `subtle` crate for constant-time operations
//! - Fixed iteration count (BUG-030) prevents length leakage
//! - Length comparison is also constant-time
//!
//! ## Security Properties
//!
//! | Property | Guarantee |
//! |----------|-----------|
//! | **SEC-008** | Constant-time byte comparison |
//! | **BUG-008** | Fixed-size work regardless of input |
//! | **BUG-026** | Uniform padding for timing consistency |
//! | **BUG-030** | Fixed iteration count |
//!
//! ## Example
//!
//! ```rust
//! use ashcore::ash_timing_safe_equal;
//!
//! let secret = b"my_secret_proof_value_12345";
//! let attempt = b"my_secret_proof_value_12345";
//! let wrong = b"wrong_attempt_xxxxxxxxxxxxxx";
//!
//! // Both comparisons take the same time
//! assert!(ash_timing_safe_equal(secret, attempt));
//! assert!(!ash_timing_safe_equal(secret, wrong));
//! ```
//!
//! ## When to Use
//!
//! Always use these functions when comparing:
//! - Cryptographic proofs
//! - HMAC values
//! - API tokens or secrets
//! - Session IDs
//! - Any security-sensitive values

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Chunk size for timing-safe comparison.
const CHUNK_SIZE: usize = 256;

/// Fixed number of iterations for timing normalization.
/// BUG-037: Increased from 4 to 8 iterations (2048 bytes) for safety margin.
/// Covers all typical cryptographic values including longer chain proofs.
/// BUG-030: Using fixed iterations prevents leaking length via iteration count.
const FIXED_ITERATIONS: usize = 8;

/// Total bytes processed in fixed iterations.
/// BUG-037: 2048 bytes provides safety margin beyond typical 64-128 char proofs.
const FIXED_WORK_SIZE: usize = CHUNK_SIZE * FIXED_ITERATIONS;

/// Perform a constant-time comparison of two byte slices.
///
/// This function takes the same amount of time regardless of where
/// the first difference occurs, preventing timing attacks.
///
/// # Security Note
///
/// Always use this function when comparing proofs, tokens, or any
/// security-sensitive values. Regular `==` comparison can leak
/// information about where differences occur.
///
/// # Security (SEC-008 & BUG-008 & BUG-026 & BUG-030)
///
/// - The length comparison is constant-time to prevent length oracle attacks
/// - The comparison always performs FIXED_ITERATIONS iterations
/// - BUG-026: All branches perform equivalent constant-time operations
/// - BUG-030: Fixed iteration count prevents leaking length via timing
///
/// # Input Size Limit
///
/// Inputs larger than 2048 bytes are rejected (returns `false`).
/// BUG-037: Extended from 1024 to 2048 bytes for safety margin.
/// SEC-AUDIT-007: Inputs exceeding the fixed work size are rejected rather than
/// silently truncated, preventing subtle comparison bypass.
/// For ASH proofs (64-128 hex chars), this limit is always sufficient.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_timing_safe_equal;
///
/// let a = b"secret_proof_123";
/// let b = b"secret_proof_123";
/// let c = b"secret_proof_456";
///
/// assert!(ash_timing_safe_equal(a, b));
/// assert!(!ash_timing_safe_equal(a, c));
/// ```
pub fn ash_timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
    // SEC-AUDIT-007: Reject inputs exceeding the fixed work size.
    // BUG-064: Perform constant-time work even for oversized inputs to prevent
    // timing leaks that could reveal whether inputs are within the size limit.
    // The dummy comparison ensures uniform execution time regardless of the
    // rejection reason (oversized vs mismatched).
    if a.len() > FIXED_WORK_SIZE || b.len() > FIXED_WORK_SIZE {
        // Perform fixed-iteration dummy work so the rejection path takes the
        // same time as a normal comparison (prevents size-oracle via timing).
        // M10-FIX: Use XOR accumulation instead of AND to prevent convergence
        // to a fixed point after the first iteration (AND with 0 = 0 forever).
        // L15-FIX: Access real input data in dummy path to match memory access
        // patterns of the normal path (heap vs stack timing difference).
        let dummy_a = [0u8; CHUNK_SIZE];
        let dummy_b = [0xFFu8; CHUNK_SIZE];
        let mut sink = Choice::from(1u8);
        for i in 0..FIXED_ITERATIONS {
            // XOR accumulation alternates, preventing optimizer from recognizing
            // a fixed-point convergence pattern.
            sink ^= dummy_a.ct_eq(&dummy_b);
            // Access real input data (if available) to create similar cache patterns
            // to the normal comparison path, reducing timing distinguishability.
            // BUG-FIX: Use .get() to prevent panic when a or b is empty.
            // Also access both inputs for symmetric cache patterns.
            let idx_a = i * CHUNK_SIZE % a.len().max(1);
            let idx_b = i * CHUNK_SIZE % b.len().max(1);
            std::hint::black_box(a.get(idx_a).copied().unwrap_or(0));
            std::hint::black_box(b.get(idx_b).copied().unwrap_or(0));
        }
        // BUG-069: Prevent LLVM from optimizing away the dummy work.
        std::hint::black_box(sink);
        return false;
    }

    // SEC-008: Use constant-time length comparison
    let len_a = a.len() as u64;
    let len_b = b.len() as u64;
    let lengths_equal: Choice = len_a.ct_eq(&len_b);

    // BUG-008 & BUG-026 & BUG-030: Always perform fixed number of iterations
    // This prevents leaking length information via iteration count
    let min_len = std::cmp::min(a.len(), b.len());

    // Cap comparison at FIXED_WORK_SIZE to ensure fixed iterations
    let capped_min_len = std::cmp::min(min_len, FIXED_WORK_SIZE);
    let capped_a_len = std::cmp::min(a.len(), FIXED_WORK_SIZE);
    let capped_b_len = std::cmp::min(b.len(), FIXED_WORK_SIZE);

    // BUG-FIX: Pre-pad both inputs into fixed-size buffers to eliminate
    // data-dependent branches in the hot loop (timing side-channel fix).
    // Previously, conditional `if pos < capped_a_len` branches leaked
    // length information via branch prediction and cache access patterns.
    let mut padded_full_a = [0u8; FIXED_WORK_SIZE];
    let mut padded_full_b = [0u8; FIXED_WORK_SIZE];
    padded_full_a[..capped_a_len].copy_from_slice(&a[..capped_a_len]);
    padded_full_b[..capped_b_len].copy_from_slice(&b[..capped_b_len]);

    let mut result = Choice::from(1u8); // Start assuming equal

    // BUG-030: Always perform exactly FIXED_ITERATIONS iterations
    for i in 0..FIXED_ITERATIONS {
        let pos = i * CHUNK_SIZE;

        // BUG-026: Compare full chunks from pre-padded buffers — no branching
        let chunk_a = &padded_full_a[pos..pos + CHUNK_SIZE];
        let chunk_b = &padded_full_b[pos..pos + CHUNK_SIZE];
        let chunk_cmp = chunk_a.ct_eq(chunk_b);

        // SEC-AUDIT-001: Use constant-time conditional selection instead of branch
        // This prevents micro-timing leaks from branch prediction
        let in_range = Choice::from((pos < capped_min_len) as u8);
        let combined = result & chunk_cmp;
        result = Choice::conditional_select(&result, &combined, in_range);
    }

    // Both length equality and content equality must be true
    (lengths_equal & result).into()
}

/// Perform a fixed-time comparison for known-length secrets.
///
/// This is optimized for comparing values that should always have the same length,
/// like HMAC outputs or SHA-256 hashes.
///
/// # Security Note
///
/// The length check at the start is NOT constant-time, but this is intentional:
/// this function is designed for inputs that are always the same length (e.g.,
/// HMAC-SHA256 outputs are always 32 bytes). Length mismatch indicates a
/// programming error, not an attacker-controlled input. For variable-length
/// inputs, use [`ash_timing_safe_equal`] instead.
///
/// # Panics
///
/// Debug builds will panic if lengths differ (indicating a programming error).
/// Release builds will return false.
#[inline]
pub fn ash_timing_safe_equal_fixed_length(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(
        a.len(),
        b.len(),
        "timing_safe_equal_fixed_length called with different lengths"
    );

    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

/// Compare two strings in constant time.
///
/// Convenience wrapper around `ash_timing_safe_equal` for string comparison.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_timing_safe_equal;
///
/// let proof1 = "abc123xyz";
/// let proof2 = "abc123xyz";
///
/// assert!(ash_timing_safe_equal(proof1.as_bytes(), proof2.as_bytes()));
/// ```
pub fn ash_timing_safe_compare(a: &str, b: &str) -> bool {
    ash_timing_safe_equal(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_safe_equal_same() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_equal_different() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_equal_different_length() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_timing_safe_equal_empty() {
        let a = b"";
        let b = b"";
        assert!(ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_ash_timing_safe_compare() {
        assert!(ash_timing_safe_compare("test", "test"));
        assert!(!ash_timing_safe_compare("test", "Test"));
    }

    #[test]
    fn test_timing_safe_equal_fixed_length() {
        // SHA-256 hash length (64 hex chars)
        let a = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let b = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let c = b"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

        assert!(ash_timing_safe_equal_fixed_length(a, b));
        assert!(!ash_timing_safe_equal_fixed_length(a, c));
    }

    #[test]
    fn test_empty_vs_nonempty() {
        let a = b"";
        let b = b"x";
        assert!(!ash_timing_safe_equal(a, b));
        assert!(!ash_timing_safe_equal(b, a));
    }

    #[test]
    fn test_single_byte_difference() {
        let a = b"aaaaaaaaaa";
        let b = b"aaaaaaaaab";
        assert!(!ash_timing_safe_equal(a, b));
    }

    #[test]
    fn test_rejects_oversized_inputs() {
        // SEC-AUDIT-007: Inputs exceeding FIXED_WORK_SIZE must be rejected
        let large = vec![0x41u8; FIXED_WORK_SIZE + 1];
        let small = b"hello";

        // Both oversized → false
        assert!(!ash_timing_safe_equal(&large, &large));
        // One oversized → false
        assert!(!ash_timing_safe_equal(&large, small));
        assert!(!ash_timing_safe_equal(small, &large));
    }

    #[test]
    fn test_empty_vs_oversized_no_panic() {
        // BUG-FIX: Previously panicked with index-out-of-bounds when
        // a was empty and b exceeded FIXED_WORK_SIZE.
        let large = vec![0x41u8; FIXED_WORK_SIZE + 1];
        assert!(!ash_timing_safe_equal(b"", &large));
        assert!(!ash_timing_safe_equal(&large, b""));
    }

    #[test]
    fn test_accepts_max_size_inputs() {
        // Inputs exactly at FIXED_WORK_SIZE should still work
        let a = vec![0x41u8; FIXED_WORK_SIZE];
        let b = vec![0x41u8; FIXED_WORK_SIZE];
        assert!(ash_timing_safe_equal(&a, &b));
    }
}
