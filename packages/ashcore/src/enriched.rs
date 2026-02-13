//! Enriched API variants (Phase 2).
//!
//! These functions return structured result types with metadata,
//! extending the existing Core primitives without changing them.
//!
//! ## Design Principle
//!
//! Each enriched function wraps the corresponding Core function:
//! - Same behavior, same validation, same errors
//! - Additional metadata in the return type
//! - No new logic — only metadata extraction
//!
//! ## Functions
//!
//! | Enriched | Base Function |
//! |----------|---------------|
//! | `ash_canonicalize_query_enriched` | `ash_canonicalize_query` |
//! | `ash_hash_body_enriched` | `ash_hash_body` |
//! | `ash_normalize_binding_enriched` | `ash_normalize_binding` |

use crate::canonicalize::ash_canonicalize_query;
use crate::errors::{AshError, AshErrorCode};
use crate::proof::ash_hash_body;

// ── Enriched Query Canonicalization ──────────────────────────────────

/// Result of enriched query canonicalization.
///
/// Contains the canonical query string plus metadata about the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalQueryResult {
    /// The canonical query string (same as `ash_canonicalize_query` output)
    pub canonical: String,

    /// Number of key=value pairs in the canonical output
    pub pairs_count: usize,

    /// Whether the input had a fragment (`#...`) that was stripped
    pub had_fragment: bool,

    /// Whether the input had a leading `?` that was stripped
    pub had_leading_question_mark: bool,

    /// Number of distinct keys after normalization
    pub unique_keys: usize,
}

/// Canonicalize a query string and return enriched metadata.
///
/// Wraps `ash_canonicalize_query` — identical behavior, richer return type.
///
/// # Example
///
/// ```rust
/// use ashcore::enriched::ash_canonicalize_query_enriched;
///
/// let result = ash_canonicalize_query_enriched("?z=3&a=1&a=2#section").unwrap();
/// assert_eq!(result.canonical, "a=1&a=2&z=3");
/// assert_eq!(result.pairs_count, 3);
/// assert!(result.had_fragment);
/// assert!(result.had_leading_question_mark);
/// assert_eq!(result.unique_keys, 2); // "a" and "z"
/// ```
pub fn ash_canonicalize_query_enriched(input: &str) -> Result<CanonicalQueryResult, AshError> {
    let had_leading_question_mark = input.starts_with('?');
    let had_fragment = input.contains('#');

    let canonical = ash_canonicalize_query(input)?;

    let pairs_count = if canonical.is_empty() {
        0
    } else {
        canonical.split('&').count()
    };

    let unique_keys = if canonical.is_empty() {
        0
    } else {
        let mut keys: Vec<&str> = canonical
            .split('&')
            .filter_map(|pair| pair.split('=').next())
            .collect();
        keys.sort();
        keys.dedup();
        keys.len()
    };

    Ok(CanonicalQueryResult {
        canonical,
        pairs_count,
        had_fragment,
        had_leading_question_mark,
        unique_keys,
    })
}

// ── Enriched Body Hashing ────────────────────────────────────────────

/// Result of enriched body hashing.
///
/// Contains the SHA-256 hash plus metadata about the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyHashResult {
    /// The SHA-256 hex hash (same as `ash_hash_body` output, 64 chars)
    pub hash: String,

    /// Size of the canonical body input in bytes
    pub input_bytes: usize,

    /// Whether the input was empty
    pub is_empty: bool,
}

/// Hash a canonical body and return enriched metadata.
///
/// Wraps `ash_hash_body` — identical behavior, richer return type.
///
/// # Example
///
/// ```rust
/// use ashcore::enriched::ash_hash_body_enriched;
///
/// let result = ash_hash_body_enriched(r#"{"amount":100}"#);
/// assert_eq!(result.hash.len(), 64);
/// assert_eq!(result.input_bytes, 14);
/// assert!(!result.is_empty);
///
/// let empty = ash_hash_body_enriched("");
/// assert!(empty.is_empty);
/// assert_eq!(empty.input_bytes, 0);
/// ```
pub fn ash_hash_body_enriched(canonical_body: &str) -> BodyHashResult {
    let hash = ash_hash_body(canonical_body);
    let input_bytes = canonical_body.len();

    BodyHashResult {
        hash,
        input_bytes,
        is_empty: canonical_body.is_empty(),
    }
}

// ── Enriched Binding Normalization ───────────────────────────────────

/// Structured binding with accessible parts.
///
/// Contains the normalized binding string plus its decomposed components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedBinding {
    /// The full binding string (METHOD|PATH|CANONICAL_QUERY)
    pub binding: String,

    /// HTTP method (uppercased)
    pub method: String,

    /// Normalized path (decoded, dot-resolved, re-encoded)
    pub path: String,

    /// Canonical query string (sorted, normalized, may be empty)
    pub canonical_query: String,

    /// Whether the input query was non-empty
    pub had_query: bool,
}

/// Normalize a binding and return enriched structured result.
///
/// Wraps `ash_normalize_binding` — identical behavior, richer return type.
///
/// # Example
///
/// ```rust
/// use ashcore::enriched::ash_normalize_binding_enriched;
///
/// let result = ash_normalize_binding_enriched("post", "/api//users/", "z=3&a=1").unwrap();
/// assert_eq!(result.binding, "POST|/api/users|a=1&z=3");
/// assert_eq!(result.method, "POST");
/// assert_eq!(result.path, "/api/users");
/// assert_eq!(result.canonical_query, "a=1&z=3");
/// assert!(result.had_query);
/// ```
pub fn ash_normalize_binding_enriched(
    method: &str,
    path: &str,
    query: &str,
) -> Result<NormalizedBinding, AshError> {
    let binding = crate::ash_normalize_binding(method, path, query)?;

    // Parse the binding back into parts (METHOD|PATH|QUERY)
    // Clone parts before consuming binding
    let parsed = ash_parse_binding(&binding)?;
    // BUG-071: Use canonical query (from parsed binding) to determine had_query,
    // not the raw input. The raw input could have whitespace-only content that
    // canonicalizes to empty, causing had_query to be true when the canonical
    // binding actually has no query. This also makes the logic consistent with
    // ash_parse_binding() which uses the canonical output.
    Ok(NormalizedBinding {
        had_query: !parsed.canonical_query.is_empty(),
        ..parsed
    })
}

/// Parse an existing normalized binding string into structured parts.
///
/// Useful when you have a binding from `build_request_proof` or `verify_incoming_request`
/// and want to inspect its components.
///
/// # Example
///
/// ```rust
/// use ashcore::enriched::ash_parse_binding;
///
/// let parts = ash_parse_binding("POST|/api/users|page=1&sort=name").unwrap();
/// assert_eq!(parts.method, "POST");
/// assert_eq!(parts.path, "/api/users");
/// assert_eq!(parts.canonical_query, "page=1&sort=name");
/// ```
pub fn ash_parse_binding(binding: &str) -> Result<NormalizedBinding, AshError> {
    let parts: Vec<&str> = binding.splitn(3, '|').collect();
    if parts.len() != 3 {
        return Err(AshError::new(
            AshErrorCode::ValidationError,
            format!(
                "Invalid binding format: expected METHOD|PATH|QUERY, got {} parts",
                parts.len()
            ),
        ));
    }

    let canonical_query = parts[2].to_string();
    let had_query = !canonical_query.is_empty();

    Ok(NormalizedBinding {
        binding: binding.to_string(),
        method: parts[0].to_string(),
        path: parts[1].to_string(),
        canonical_query,
        had_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Query Enrichment Tests ────────────────────────────────────────

    #[test]
    fn test_query_enriched_basic() {
        let result = ash_canonicalize_query_enriched("a=1&b=2").unwrap();
        assert_eq!(result.canonical, "a=1&b=2");
        assert_eq!(result.pairs_count, 2);
        assert_eq!(result.unique_keys, 2);
        assert!(!result.had_fragment);
        assert!(!result.had_leading_question_mark);
    }

    #[test]
    fn test_query_enriched_with_fragment() {
        let result = ash_canonicalize_query_enriched("a=1#section").unwrap();
        assert_eq!(result.canonical, "a=1");
        assert!(result.had_fragment);
    }

    #[test]
    fn test_query_enriched_with_question_mark() {
        let result = ash_canonicalize_query_enriched("?a=1").unwrap();
        assert_eq!(result.canonical, "a=1");
        assert!(result.had_leading_question_mark);
    }

    #[test]
    fn test_query_enriched_duplicate_keys() {
        let result = ash_canonicalize_query_enriched("a=1&a=2&b=3").unwrap();
        assert_eq!(result.pairs_count, 3);
        assert_eq!(result.unique_keys, 2); // "a" and "b"
    }

    #[test]
    fn test_query_enriched_empty() {
        let result = ash_canonicalize_query_enriched("").unwrap();
        assert_eq!(result.canonical, "");
        assert_eq!(result.pairs_count, 0);
        assert_eq!(result.unique_keys, 0);
    }

    #[test]
    fn test_query_enriched_sorting() {
        let result = ash_canonicalize_query_enriched("z=3&a=1&m=2").unwrap();
        assert_eq!(result.canonical, "a=1&m=2&z=3");
        assert_eq!(result.pairs_count, 3);
    }

    #[test]
    fn test_query_enriched_full_metadata() {
        let result = ash_canonicalize_query_enriched("?z=3&a=1&a=2#frag").unwrap();
        assert_eq!(result.canonical, "a=1&a=2&z=3");
        assert_eq!(result.pairs_count, 3);
        assert_eq!(result.unique_keys, 2);
        assert!(result.had_fragment);
        assert!(result.had_leading_question_mark);
    }

    // ── Body Hash Enrichment Tests ────────────────────────────────────

    #[test]
    fn test_body_hash_enriched_basic() {
        let result = ash_hash_body_enriched(r#"{"amount":100}"#);
        assert_eq!(result.hash.len(), 64);
        assert_eq!(result.input_bytes, 14);
        assert!(!result.is_empty);
    }

    #[test]
    fn test_body_hash_enriched_empty() {
        let result = ash_hash_body_enriched("");
        assert_eq!(result.hash.len(), 64);
        assert_eq!(result.input_bytes, 0);
        assert!(result.is_empty);
    }

    #[test]
    fn test_body_hash_enriched_matches_base() {
        let body = r#"{"test":"value"}"#;
        let base = ash_hash_body(body);
        let enriched = ash_hash_body_enriched(body);
        assert_eq!(base, enriched.hash);
    }

    // ── Binding Enrichment Tests ──────────────────────────────────────

    #[test]
    fn test_binding_enriched_basic() {
        let result = ash_normalize_binding_enriched("POST", "/api/users", "").unwrap();
        assert_eq!(result.binding, "POST|/api/users|");
        assert_eq!(result.method, "POST");
        assert_eq!(result.path, "/api/users");
        assert_eq!(result.canonical_query, "");
        assert!(!result.had_query);
    }

    #[test]
    fn test_binding_enriched_with_query() {
        let result =
            ash_normalize_binding_enriched("GET", "/api/search", "z=3&a=1").unwrap();
        assert_eq!(result.binding, "GET|/api/search|a=1&z=3");
        assert_eq!(result.method, "GET");
        assert_eq!(result.path, "/api/search");
        assert_eq!(result.canonical_query, "a=1&z=3");
        assert!(result.had_query);
    }

    #[test]
    fn test_binding_enriched_normalization() {
        let result =
            ash_normalize_binding_enriched("post", "/api//users/", "").unwrap();
        assert_eq!(result.method, "POST");
        assert_eq!(result.path, "/api/users");
    }

    #[test]
    fn test_binding_enriched_matches_base() {
        let base = crate::ash_normalize_binding("GET", "/api/test", "b=2&a=1").unwrap();
        let enriched =
            ash_normalize_binding_enriched("GET", "/api/test", "b=2&a=1").unwrap();
        assert_eq!(base, enriched.binding);
    }

    // ── Parse Binding Tests ───────────────────────────────────────────

    #[test]
    fn test_parse_binding_basic() {
        let result = ash_parse_binding("POST|/api/users|page=1").unwrap();
        assert_eq!(result.method, "POST");
        assert_eq!(result.path, "/api/users");
        assert_eq!(result.canonical_query, "page=1");
        assert!(result.had_query);
    }

    #[test]
    fn test_parse_binding_no_query() {
        let result = ash_parse_binding("GET|/|").unwrap();
        assert_eq!(result.method, "GET");
        assert_eq!(result.path, "/");
        assert_eq!(result.canonical_query, "");
        assert!(!result.had_query);
    }

    #[test]
    fn test_parse_binding_invalid_format() {
        assert!(ash_parse_binding("invalid").is_err());
        assert!(ash_parse_binding("GET|/api").is_err());
    }

    #[test]
    fn test_parse_binding_roundtrip() {
        let binding = crate::ash_normalize_binding("PUT", "/api/resource", "id=5").unwrap();
        let parsed = ash_parse_binding(&binding).unwrap();
        assert_eq!(parsed.binding, binding);
        assert_eq!(parsed.method, "PUT");
    }
}
