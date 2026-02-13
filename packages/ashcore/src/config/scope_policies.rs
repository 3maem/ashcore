//! Server-side scope policy registry for ASH.
//!
//! This module allows servers to define which fields must be protected for each route,
//! without requiring client-side scope management. The server can enforce that
//! specific sensitive fields (like `amount`, `recipient`) are always included in
//! the ASH proof for particular endpoints.
//!
//! ## Overview
//!
//! Scope policies answer the question: **"For this endpoint, which fields MUST be protected?"**
//!
//! ```text
//! POST /api/transfer  →  ["amount", "recipient"]  // Must protect these fields
//! POST /api/payment   →  ["amount", "card_last4"]
//! PUT  /api/users/*   →  ["role", "permissions"]  // Wildcard pattern
//! ```
//!
//! ## Pattern Syntax
//!
//! | Pattern | Matches |
//! |---------|---------|
//! | `POST\|/api/users\|` | Exact match |
//! | `GET\|/api/users/*\|` | Single path segment wildcard |
//! | `GET\|/api/**\|` | Multiple path segments |
//! | `*\|/api/users\|` | Any HTTP method |
//! | `PUT\|/api/users/<id>\|` | Named parameter (Express/Flask style) |
//! | `PUT\|/api/users/{id}\|` | Named parameter (Laravel style) |
//!
//! ## Escape Sequences (BUG-020)
//!
//! | Escape | Meaning |
//! |--------|---------|
//! | `\\*` | Literal asterisk |
//! | `\\<` | Literal `<` |
//! | `\\{` | Literal `{` |
//! | `\\\\` | Literal backslash |
//!
//! ## Example
//!
//! ```rust
//! use ashcore::config::{ash_register_scope_policy, ash_get_scope_policy, ash_clear_scope_policies};
//!
//! // Clear any existing policies (useful in tests)
//! ash_clear_scope_policies();
//!
//! // Register policies at application startup
//! ash_register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);
//! ash_register_scope_policy("POST|/api/payment|", &["amount", "card_last4"]);
//! ash_register_scope_policy("PUT|/api/users/*|", &["role", "permissions"]);
//!
//! // Later, get policy for a binding
//! let scope = ash_get_scope_policy("POST|/api/transfer|");
//! assert_eq!(scope, vec!["amount", "recipient"]);
//!
//! // Wildcard matches
//! let scope = ash_get_scope_policy("PUT|/api/users/123|");
//! assert_eq!(scope, vec!["role", "permissions"]);
//! ```
//!
//! ## Pattern Priority (BUG-006)
//!
//! When multiple patterns could match a binding, the **first registered pattern wins**.
//! Register more specific patterns before general ones:
//!
//! ```rust,ignore
//! // CORRECT: Specific first
//! ash_register_scope_policy("POST|/api/admin/users|", &["all_fields"]);
//! ash_register_scope_policy("POST|/api/*/users|", &["some_fields"]);
//!
//! // WRONG: General pattern would match first
//! ash_register_scope_policy("POST|/api/*/users|", &["some_fields"]);
//! ash_register_scope_policy("POST|/api/admin/users|", &["all_fields"]); // Never matches!
//! ```
//!
//! ## Security Properties
//!
//! | Property | Description |
//! |----------|-------------|
//! | **SEC-001** | Regex complexity limits prevent ReDoS |
//! | **SEC-003** | RwLock poisoning handled gracefully |
//! | **SEC-007** | Registration order determinism |
//! | **SEC-009** | Compiled patterns are cached |
//! | **BUG-006** | First-registered pattern wins |
//! | **BUG-020** | Proper escape sequence handling |

use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, RwLock};

/// Maximum allowed pattern length to prevent ReDoS attacks.
const MAX_PATTERN_LENGTH: usize = 512;

/// Maximum allowed wildcards in a pattern to prevent exponential backtracking.
const MAX_WILDCARDS: usize = 8;

/// Wildcard characters that have special meaning in patterns.
const WILDCARD_CHARS: &[char] = &['*', '<', ':', '{'];

/// Check if a wildcard character at position `i` is escaped.
/// BUG-020: Properly counts consecutive backslashes to handle `\\*` (escaped backslash + wildcard).
/// An odd number of preceding backslashes means the wildcard is escaped.
/// An even number means the backslashes are paired (escaped) and the wildcard is unescaped.
fn ash_is_wildcard_escaped(chars: &[char], i: usize) -> bool {
    if i == 0 {
        return false;
    }
    // Count consecutive backslashes before this position
    let mut backslash_count = 0;
    let mut pos = i - 1;
    loop {
        if chars[pos] == '\\' {
            backslash_count += 1;
            if pos == 0 {
                break;
            }
            pos -= 1;
        } else {
            break;
        }
    }
    // Odd number of backslashes = wildcard is escaped
    // Even number = backslashes are paired, wildcard is NOT escaped
    backslash_count % 2 == 1
}

/// Check if a pattern has any unescaped wildcards.
fn ash_has_unescaped_wildcard(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if WILDCARD_CHARS.contains(&ch) {
            // BUG-020: Use proper escape detection
            if !ash_is_wildcard_escaped(&chars, i) {
                return true;
            }
        }
    }
    false
}

/// Count unescaped wildcards in a pattern.
fn ash_count_unescaped_wildcards(pattern: &str) -> usize {
    let chars: Vec<char> = pattern.chars().collect();
    let mut count = 0;
    for (i, &ch) in chars.iter().enumerate() {
        if WILDCARD_CHARS.contains(&ch) {
            // BUG-020: Use proper escape detection
            if !ash_is_wildcard_escaped(&chars, i) {
                count += 1;
            }
        }
    }
    count
}

/// Unescape a pattern by removing escape backslashes.
/// BUG-020: Properly handles `\\\\*` (two backslashes + asterisk) as `\*` (literal backslash + literal asterisk).
/// - `\\` (escaped backslash) becomes `\`
/// - `\*` (escaped wildcard) becomes `*`
/// - `\\\\*` becomes `\*` (one literal backslash, one literal asterisk)
fn ash_unescape_pattern(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            if next == '\\' {
                // Escaped backslash: \\ -> \
                result.push('\\');
                i += 2;
            } else if WILDCARD_CHARS.contains(&next) {
                // Escaped wildcard: \* -> *
                result.push(next);
                i += 2;
            } else {
                // Backslash not followed by escapable char: keep as-is
                result.push(chars[i]);
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result
}

/// Compiled pattern for efficient matching.
#[derive(Debug, Clone)]
struct CompiledPattern {
    /// Original pattern string
    pattern: String,
    /// Compiled regex (None if pattern has no wildcards)
    regex: Option<Regex>,
    /// Whether this is an exact match pattern
    is_exact: bool,
}

impl CompiledPattern {
    /// Compile a pattern into a matcher.
    /// Returns None if the pattern is invalid or too complex.
    ///
    /// # Escape Sequences (BUG-010)
    ///
    /// Use `\\*` to match a literal asterisk, `\\<` for literal `<`, etc.
    /// Escaped wildcards don't count toward the wildcard limit.
    fn compile(pattern: &str) -> Option<Self> {
        // SEC-001: Limit pattern length to prevent ReDoS
        if pattern.len() > MAX_PATTERN_LENGTH {
            return None;
        }

        // BUG-010: Check for unescaped wildcards only
        // Count wildcards that are NOT escaped (not preceded by \)
        let has_unescaped_wildcards = ash_has_unescaped_wildcard(pattern);

        if !has_unescaped_wildcards {
            // Pattern may have escaped wildcards - exact matching will unescape
            return Some(CompiledPattern {
                pattern: pattern.to_string(),
                regex: None,
                is_exact: true,
            });
        }

        // SEC-001: Count unescaped wildcards to prevent exponential backtracking
        let wildcard_count = ash_count_unescaped_wildcards(pattern);

        if wildcard_count > MAX_WILDCARDS {
            return None;
        }

        // Build regex pattern safely
        let regex = ash_build_safe_regex(pattern)?;

        Some(CompiledPattern {
            pattern: pattern.to_string(),
            regex: Some(regex),
            is_exact: false,
        })
    }

    /// Check if a binding matches this pattern.
    fn matches(&self, binding: &str) -> bool {
        if self.is_exact {
            // BUG-010: For exact match, compare against unescaped pattern
            return binding == ash_unescape_pattern(&self.pattern);
        }

        if let Some(ref regex) = self.regex {
            regex.is_match(binding)
        } else {
            false
        }
    }
}

/// Build a safe regex from a pattern, preventing ReDoS.
///
/// # BUG-010 & BUG-020: Escape Sequences
///
/// Handles escape sequences properly:
/// - `\\` (escaped backslash) becomes literal `\`
/// - `\*` (escaped asterisk) becomes literal `*`
/// - `\\*` (escaped backslash + asterisk) becomes literal `\` + wildcard match
fn ash_build_safe_regex(pattern: &str) -> Option<Regex> {
    // Use pre-compiled static patterns for replacements
    // These patterns match on the ESCAPED regex string
    // After regex::escape: < stays <, : stays :, { becomes \{, } becomes \}
    // BUG-068: Replaced lazy_static with std::sync::LazyLock.
    static FLASK_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"<[a-zA-Z_][a-zA-Z0-9_]*>").unwrap());
    static EXPRESS_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r":[a-zA-Z_][a-zA-Z0-9_]*").unwrap());
    // In escaped regex, { becomes \{ and } becomes \}
    // So we need to match the escaped version: \\\{id\\\}
    static LARAVEL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\\\{[a-zA-Z_][a-zA-Z0-9_]*\\\}").unwrap());

    // BUG-020: Process escape sequences properly by iterating through chars
    // We need to handle: \\ -> literal backslash, \* -> literal *, etc.
    // NOTE: Null-byte delimited placeholders are safe here because:
    // 1. Binding patterns cannot contain \x00 (rejected by binding validation)
    // 2. Placeholders are fully replaced before the final regex is compiled
    // 3. The pattern is scope-internal, never exposed to external consumers
    let placeholder_backslash = "\x00ESCAPED_BACKSLASH\x00";
    let placeholder_star = "\x00ESCAPED_STAR\x00";
    let placeholder_lt = "\x00ESCAPED_LT\x00";
    let placeholder_colon = "\x00ESCAPED_COLON\x00";
    let placeholder_lbrace = "\x00ESCAPED_LBRACE\x00";

    let mut temp = String::with_capacity(pattern.len() * 2);
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            if next == '\\' {
                // Escaped backslash: \\ -> placeholder for literal backslash
                temp.push_str(placeholder_backslash);
                i += 2;
            } else if next == '*' {
                temp.push_str(placeholder_star);
                i += 2;
            } else if next == '<' {
                temp.push_str(placeholder_lt);
                i += 2;
            } else if next == ':' {
                temp.push_str(placeholder_colon);
                i += 2;
            } else if next == '{' {
                temp.push_str(placeholder_lbrace);
                i += 2;
            } else {
                temp.push(chars[i]);
                i += 1;
            }
        } else {
            temp.push(chars[i]);
            i += 1;
        }
    }

    // Now escape for regex
    let mut regex_str = regex::escape(&temp);

    // Replace ** first (multi-segment) - use non-greedy and limit depth
    // SEC-001: Use [^|]* instead of .* to prevent catastrophic backtracking
    regex_str = regex_str.replace(r"\*\*", "[^|]*");

    // Replace * (single segment - not containing | or /)
    regex_str = regex_str.replace(r"\*", "[^|/]*");

    // Replace route params with bounded character class
    regex_str = FLASK_RE.replace_all(&regex_str, "[^|/]+").to_string();
    regex_str = EXPRESS_RE.replace_all(&regex_str, "[^|/]+").to_string();
    regex_str = LARAVEL_RE.replace_all(&regex_str, "[^|/]+").to_string();

    // BUG-020: Restore escaped characters as literals
    regex_str = regex_str.replace(&regex::escape(placeholder_backslash), r"\\");
    regex_str = regex_str.replace(&regex::escape(placeholder_star), r"\*");
    regex_str = regex_str.replace(&regex::escape(placeholder_lt), "<");
    regex_str = regex_str.replace(&regex::escape(placeholder_colon), ":");
    regex_str = regex_str.replace(&regex::escape(placeholder_lbrace), r"\{");

    // SEC-001: Use RegexBuilder with size limit to prevent complex patterns
    regex::RegexBuilder::new(&format!("^{}$", regex_str))
        .size_limit(10 * 1024) // 10KB limit on compiled regex size
        .build()
        .ok()
}

/// Scope policy registry that can be instantiated for isolated testing.
///
/// For most use cases, use the global functions (`ash_register_scope_policy`, etc.)
/// which operate on a shared global registry.
///
/// # Pattern Priority (BUG-006 fix)
///
/// When multiple patterns could match a binding, the **first registered pattern wins**.
/// This uses registration order, not alphabetical order, for deterministic matching.
#[derive(Debug, Default)]
pub struct ScopePolicyRegistry {
    /// Policies stored in registration order for pattern matching priority.
    /// BUG-006: Uses Vec to preserve registration order.
    policies_ordered: Vec<(String, CompiledPattern, Vec<String>)>,
    /// Fast lookup for exact match bindings.
    exact_matches: HashMap<String, usize>, // Maps unescaped pattern -> index in policies_ordered
}

impl ScopePolicyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            policies_ordered: Vec::new(),
            exact_matches: HashMap::new(),
        }
    }

    /// Register a scope policy for a binding pattern.
    ///
    /// Returns false if the pattern is invalid or too complex.
    ///
    /// # Pattern Priority (BUG-006)
    ///
    /// Later registrations for the same pattern will replace earlier ones.
    /// When matching, the first registered pattern that matches wins.
    pub fn register(&mut self, binding: &str, fields: &[&str]) -> bool {
        // BUG-098: Reject patterns containing null bytes. Null bytes could cause
        // truncation in regex compilation or downstream C-interop, leading to
        // overly permissive pattern matching.
        if binding.contains('\0') {
            return false;
        }

        // L17-FIX: Reject patterns containing control characters (U+0001-U+001F, U+007F).
        // Control chars in patterns could cause log injection or match unexpected inputs.
        if binding.bytes().any(|b| (b > 0 && b < 0x20) || b == 0x7F) {
            return false;
        }

        // BUG-099: Validate field names — reject empty names and names containing
        // control characters. Empty field names would match nothing; control chars
        // could cause log injection or unpredictable JSON field extraction.
        for field in fields {
            if field.is_empty() || field.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return false;
            }
        }

        if let Some(compiled) = CompiledPattern::compile(binding) {
            let fields_vec: Vec<String> = fields.iter().map(|s| s.to_string()).collect();

            // Check if this exact pattern was already registered
            let existing_idx = self.policies_ordered.iter().position(|(p, _, _)| p == binding);

            if let Some(idx) = existing_idx {
                // MED-001 FIX: Remove old entry from exact_matches if it existed
                // The old pattern may have been exact while new one is wildcard (or vice versa)
                let old_unescaped = ash_unescape_pattern(binding);
                self.exact_matches.remove(&old_unescaped);

                // Update existing entry
                self.policies_ordered[idx] = (binding.to_string(), compiled.clone(), fields_vec);

                // MED-001 FIX: Re-add to exact_matches if new pattern is exact
                if compiled.is_exact {
                    let unescaped = ash_unescape_pattern(binding);
                    self.exact_matches.insert(unescaped, idx);
                }
            } else {
                // Add new entry
                let idx = self.policies_ordered.len();
                self.policies_ordered.push((binding.to_string(), compiled.clone(), fields_vec));

                // BUG-010: For exact matches, store the unescaped pattern in lookup
                if compiled.is_exact {
                    let unescaped = ash_unescape_pattern(binding);
                    self.exact_matches.insert(unescaped, idx);
                }
            }
            true
        } else {
            false
        }
    }

    /// Register multiple scope policies at once from a BTreeMap.
    ///
    /// Returns the number of successfully registered policies.
    ///
    /// # Pattern Priority (BUG-034 Warning)
    ///
    /// **Important**: BTreeMap iterates in **alphabetical order** by key, not insertion order.
    /// When you call this method, patterns are registered in alphabetical order of their
    /// binding strings.
    ///
    /// For insertion-order-preserving registration (required when pattern priority matters),
    /// use [`register_many_ordered`] instead.
    pub fn register_many(&mut self, policies_map: &BTreeMap<&str, Vec<&str>>) -> usize {
        let mut count = 0;
        for (binding, fields) in policies_map {
            if self.register(binding, fields) {
                count += 1;
            }
        }
        count
    }

    /// Register multiple scope policies in caller-specified order.
    ///
    /// Returns the number of successfully registered policies.
    ///
    /// # Pattern Priority
    ///
    /// BUG-067: Unlike [`register_many`] (which takes a BTreeMap and thus iterates in
    /// alphabetical order), this method preserves the caller's slice order. Since
    /// "first registered pattern wins" (BUG-006), this is essential when a more
    /// specific pattern must take priority over a general wildcard pattern.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ashcore::config::ScopePolicyRegistry;
    ///
    /// let mut registry = ScopePolicyRegistry::new();
    /// let count = registry.register_many_ordered(&[
    ///     ("POST|/api/admin/users|", &["all_fields"]),  // Specific — registered first
    ///     ("POST|/api/*/users|", &["some_fields"]),     // General — registered second
    /// ]);
    /// assert_eq!(count, 2);
    ///
    /// // The specific pattern wins because it was registered first
    /// let scope = registry.get("POST|/api/admin/users|");
    /// assert_eq!(scope, vec!["all_fields"]);
    /// ```
    pub fn register_many_ordered(&mut self, policies: &[(&str, &[&str])]) -> usize {
        let mut count = 0;
        for (binding, fields) in policies {
            if self.register(binding, fields) {
                count += 1;
            }
        }
        count
    }

    /// Get the scope policy for a binding.
    ///
    /// # Pattern Priority (BUG-006 fix)
    ///
    /// Uses registration order - earlier registered patterns take precedence.
    pub fn get(&self, binding: &str) -> Vec<String> {
        // Fast path: exact match lookup — but only if no earlier wildcard wins.
        // BUG-006 FIX: "First registered pattern wins" means a wildcard registered
        // before this exact match takes priority. Only use the fast path when no
        // lower-indexed wildcard pattern also matches this binding.
        if let Some(&idx) = self.exact_matches.get(binding) {
            if idx < self.policies_ordered.len() {
                let earlier_wildcard_wins = self.policies_ordered[..idx]
                    .iter()
                    .any(|(_, compiled, _)| !compiled.is_exact && compiled.matches(binding));
                if !earlier_wildcard_wins {
                    return self.policies_ordered[idx].2.clone();
                }
            }
        }

        // BUG-006: Iterate in registration order, first match wins
        for (_, compiled, fields) in &self.policies_ordered {
            if compiled.matches(binding) {
                return fields.clone();
            }
        }

        // Default: no scoping (full payload protection)
        Vec::new()
    }

    /// Check if a binding has a scope policy defined.
    pub fn has(&self, binding: &str) -> bool {
        // Fast path: exact match lookup
        if self.exact_matches.contains_key(binding) {
            return true;
        }

        // Check pattern matches in registration order
        for (_, compiled, _) in &self.policies_ordered {
            if compiled.matches(binding) {
                return true;
            }
        }

        false
    }

    /// Get all registered policies.
    ///
    /// BUG-086: Returns a `Vec` of `(pattern, fields)` tuples in registration order.
    /// Previously returned `BTreeMap` which sorted alphabetically, losing the
    /// registration order that determines pattern priority ("first match wins").
    pub fn get_all(&self) -> Vec<(String, Vec<String>)> {
        self.policies_ordered
            .iter()
            .map(|(pattern, _, fields)| (pattern.clone(), fields.clone()))
            .collect()
    }

    /// Clear all registered policies.
    pub fn clear(&mut self) {
        self.policies_ordered.clear();
        self.exact_matches.clear();
    }
}

/// Global scope policy registry.
/// BUG-068: Replaced lazy_static with std::sync::LazyLock (stable since Rust 1.80).
static GLOBAL_REGISTRY: LazyLock<RwLock<ScopePolicyRegistry>> =
    LazyLock::new(|| RwLock::new(ScopePolicyRegistry::new()));

/// Safely acquire write lock, recovering from poison if needed.
/// SEC-003: Handle RwLock poisoning gracefully.
/// M7-FIX: On poison recovery, clear the registry to prevent using potentially
/// corrupted state from a panic during a previous write operation.
fn ash_get_write_lock() -> std::sync::RwLockWriteGuard<'static, ScopePolicyRegistry> {
    GLOBAL_REGISTRY
        .write()
        .unwrap_or_else(|poisoned| {
            let mut guard = poisoned.into_inner();
            // Clear potentially-corrupted state — caller must re-register policies.
            guard.clear();
            guard
        })
}

/// Safely acquire read lock, recovering from poison if needed.
/// SEC-003: Handle RwLock poisoning gracefully.
fn ash_get_read_lock() -> std::sync::RwLockReadGuard<'static, ScopePolicyRegistry> {
    GLOBAL_REGISTRY
        .read()
        .unwrap_or_else(|poisoned| {
            // Read-only access: the data may be partially corrupted, but
            // returning an empty match is safer than serving wrong policies.
            poisoned.into_inner()
        })
}

/// Register a scope policy for a binding pattern.
///
/// # Arguments
///
/// * `binding` - The binding pattern (supports `<param>`, `:param`, `{param}`, `*`, `**` wildcards)
/// * `fields` - The fields that must be protected
///
/// # Returns
///
/// `true` if the policy was registered, `false` if the pattern is invalid or too complex.
///
/// # Security Limits
///
/// - Maximum pattern length: 512 characters
/// - Maximum wildcards: 8 per pattern
///
/// # Example
///
/// ```rust
/// use ashcore::config::{ash_register_scope_policy, ash_clear_scope_policies};
///
/// ash_clear_scope_policies();
/// assert!(ash_register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]));
/// assert!(ash_register_scope_policy("PUT|/api/users/<id>|", &["role", "permissions"]));
/// ```
pub fn ash_register_scope_policy(binding: &str, fields: &[&str]) -> bool {
    let mut registry = ash_get_write_lock();
    registry.register(binding, fields)
}

/// Register multiple scope policies at once.
///
/// # Arguments
///
/// * `policies` - Map of binding => fields
///
/// # Returns
///
/// Number of successfully registered policies.
///
/// # Pattern Priority (BUG-034 Warning)
///
/// **Important**: BTreeMap iterates in **alphabetical order** by key, not insertion order.
/// Patterns are registered in alphabetical order of their binding strings.
///
/// If you need specific registration order for pattern priority (since "first registered
/// pattern wins"), use multiple calls to `ash_register_scope_policy()` instead.
///
/// # Example
///
/// ```rust
/// use std::collections::BTreeMap;
/// use ashcore::config::{ash_register_scope_policies, ash_clear_scope_policies};
///
/// ash_clear_scope_policies();
/// let mut policies = BTreeMap::new();
/// policies.insert("POST|/api/transfer|", vec!["amount", "recipient"]);
/// policies.insert("POST|/api/payment|", vec!["amount", "card_last4"]);
/// assert_eq!(ash_register_scope_policies(&policies), 2);
/// // Note: These are registered in alphabetical order!
/// ```
pub fn ash_register_scope_policies(policies_map: &BTreeMap<&str, Vec<&str>>) -> usize {
    let mut registry = ash_get_write_lock();
    registry.register_many(policies_map)
}

/// Register multiple scope policies in caller-specified order (global).
///
/// BUG-067: Preserves caller's slice order for pattern priority.
/// Use this instead of `ash_register_scope_policies` when registration order matters.
///
/// # Arguments
///
/// * `policies` - Slice of (binding, fields) tuples in priority order
///
/// # Returns
///
/// Number of successfully registered policies.
///
/// # Example
///
/// ```rust
/// use ashcore::config::{ash_register_scope_policies_ordered, ash_get_scope_policy, ash_clear_scope_policies};
///
/// ash_clear_scope_policies();
/// ash_register_scope_policies_ordered(&[
///     ("POST|/api/admin/transfer|", &["all_fields"]),
///     ("POST|/api/*/transfer|", &["amount"]),
/// ]);
///
/// let scope = ash_get_scope_policy("POST|/api/admin/transfer|");
/// assert_eq!(scope, vec!["all_fields"]);
/// ```
pub fn ash_register_scope_policies_ordered(policies: &[(&str, &[&str])]) -> usize {
    let mut registry = ash_get_write_lock();
    registry.register_many_ordered(policies)
}

/// Get the scope policy for a binding.
///
/// Returns empty vector if no policy is defined (full payload protection).
///
/// # Arguments
///
/// * `binding` - The normalized binding string
///
/// # Returns
///
/// The fields that must be protected
///
/// # Example
///
/// ```rust
/// use ashcore::config::{ash_register_scope_policy, ash_get_scope_policy, ash_clear_scope_policies};
///
/// ash_clear_scope_policies();
/// ash_register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);
///
/// let scope = ash_get_scope_policy("POST|/api/transfer|");
/// assert_eq!(scope, vec!["amount", "recipient"]);
///
/// let no_scope = ash_get_scope_policy("GET|/api/users|");
/// assert!(no_scope.is_empty());
/// ```
pub fn ash_get_scope_policy(binding: &str) -> Vec<String> {
    let registry = ash_get_read_lock();
    registry.get(binding)
}

/// Check if a binding has a scope policy defined.
///
/// # Arguments
///
/// * `binding` - The normalized binding string
///
/// # Returns
///
/// True if a policy exists
pub fn ash_has_scope_policy(binding: &str) -> bool {
    let registry = ash_get_read_lock();
    registry.has(binding)
}

/// Get all registered policies.
///
/// # Returns
///
/// All registered scope policies in registration order.
pub fn ash_get_all_scope_policies() -> Vec<(String, Vec<String>)> {
    let registry = ash_get_read_lock();
    registry.get_all()
}

/// Clear all registered policies.
///
/// Useful for testing.
pub fn ash_clear_scope_policies() {
    let mut registry = ash_get_write_lock();
    registry.clear();
}

// =========================================================================
// Deprecated Aliases for Backward Compatibility
// =========================================================================

// =========================================================================
// Deprecated Aliases for Backward Compatibility (Non-conforming names)
// =========================================================================

/// Register a scope policy for a binding pattern.
///
/// # Deprecated
///
/// Use [`ash_register_scope_policy`] instead. This alias is provided for backward compatibility.
/// Note: This function name does not follow the `ash_` prefix convention and will be removed in v3.0.
#[deprecated(since = "1.0.0", note = "Use ash_register_scope_policy instead")]
pub fn register_scope_policy(binding: &str, fields: &[&str]) -> bool {
    ash_register_scope_policy(binding, fields)
}

/// Register multiple scope policies at once.
///
/// # Deprecated
///
/// Use [`ash_register_scope_policies`] instead. This alias is provided for backward compatibility.
/// Note: This function name does not follow the `ash_` prefix convention and will be removed in v3.0.
#[deprecated(since = "1.0.0", note = "Use ash_register_scope_policies instead")]
pub fn register_scope_policies(policies_map: &BTreeMap<&str, Vec<&str>>) -> usize {
    ash_register_scope_policies(policies_map)
}

/// Get the scope policy for a binding.
///
/// # Deprecated
///
/// Use [`ash_get_scope_policy`] instead. This alias is provided for backward compatibility.
/// Note: This function name does not follow the `ash_` prefix convention and will be removed in v3.0.
#[deprecated(since = "1.0.0", note = "Use ash_get_scope_policy instead")]
pub fn get_scope_policy(binding: &str) -> Vec<String> {
    ash_get_scope_policy(binding)
}

/// Check if a binding has a scope policy defined.
///
/// # Deprecated
///
/// Use [`ash_has_scope_policy`] instead. This alias is provided for backward compatibility.
/// Note: This function name does not follow the `ash_` prefix convention and will be removed in v3.0.
#[deprecated(since = "1.0.0", note = "Use ash_has_scope_policy instead")]
pub fn has_scope_policy(binding: &str) -> bool {
    ash_has_scope_policy(binding)
}

/// Get all registered policies.
///
/// # Deprecated
///
/// Use [`ash_get_all_scope_policies`] instead. This alias is provided for backward compatibility.
/// Note: This function name does not follow the `ash_` prefix convention and will be removed in v3.0.
#[deprecated(since = "1.0.0", note = "Use ash_get_all_scope_policies instead")]
pub fn get_all_scope_policies() -> Vec<(String, Vec<String>)> {
    ash_get_all_scope_policies()
}

/// Clear all registered policies.
///
/// # Deprecated
///
/// Use [`ash_clear_scope_policies`] instead. This alias is provided for backward compatibility.
/// Note: This function name does not follow the `ash_` prefix convention and will be removed in v3.0.
#[deprecated(since = "1.0.0", note = "Use ash_clear_scope_policies instead")]
pub fn clear_scope_policies() {
    ash_clear_scope_policies()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests using isolated ScopePolicyRegistry instances - can run in parallel

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = ScopePolicyRegistry::new();
        assert!(registry.register("POST|/api/transfer|", &["amount", "recipient"]));

        let scope = registry.get("POST|/api/transfer|");
        assert_eq!(scope, vec!["amount", "recipient"]);
    }

    #[test]
    fn test_registry_get_no_match() {
        let registry = ScopePolicyRegistry::new();

        let scope = registry.get("GET|/api/users|");
        assert!(scope.is_empty());
    }

    #[test]
    fn test_registry_has() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("POST|/api/transfer|", &["amount"]);

        assert!(registry.has("POST|/api/transfer|"));
        assert!(!registry.has("GET|/api/users|"));
    }

    #[test]
    fn test_registry_pattern_matching_flask_style() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("PUT|/api/users/<id>|", &["role", "permissions"]);

        let scope = registry.get("PUT|/api/users/123|");
        assert_eq!(scope, vec!["role", "permissions"]);
    }

    #[test]
    fn test_registry_pattern_matching_express_style() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("PUT|/api/users/:id|", &["role"]);

        let scope = registry.get("PUT|/api/users/456|");
        assert_eq!(scope, vec!["role"]);
    }

    #[test]
    fn test_registry_pattern_matching_laravel_style() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("PUT|/api/users/{id}|", &["email"]);

        let scope = registry.get("PUT|/api/users/789|");
        assert_eq!(scope, vec!["email"]);
    }

    #[test]
    fn test_registry_pattern_matching_wildcard() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("POST|/api/*/transfer|", &["amount"]);

        let scope = registry.get("POST|/api/v1/transfer|");
        assert_eq!(scope, vec!["amount"]);
    }

    #[test]
    fn test_registry_pattern_matching_double_wildcard() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("POST|/api/**/transfer|", &["amount"]);

        let scope = registry.get("POST|/api/v1/users/transfer|");
        assert_eq!(scope, vec!["amount"]);
    }

    #[test]
    fn test_registry_clear() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("POST|/api/transfer|", &["amount"]);

        assert!(registry.has("POST|/api/transfer|"));

        registry.clear();

        assert!(!registry.has("POST|/api/transfer|"));
    }

    #[test]
    fn test_registry_register_many() {
        let mut registry = ScopePolicyRegistry::new();
        let mut policies = BTreeMap::new();
        policies.insert("POST|/api/transfer|", vec!["amount"]);
        policies.insert("POST|/api/payment|", vec!["card"]);

        let count = registry.register_many(&policies);
        assert_eq!(count, 2);

        assert!(registry.has("POST|/api/transfer|"));
        assert!(registry.has("POST|/api/payment|"));
    }

    #[test]
    fn test_registry_get_all() {
        let mut registry = ScopePolicyRegistry::new();
        registry.register("POST|/api/transfer|", &["amount"]);
        registry.register("POST|/api/payment|", &["card"]);

        let all = registry.get_all();
        assert_eq!(all.len(), 2);
    }

    // Security tests

    #[test]
    fn test_rejects_pattern_too_long() {
        let mut registry = ScopePolicyRegistry::new();
        let long_pattern = "POST|/api/".to_string() + &"a".repeat(600) + "|";

        // Should reject pattern that's too long (SEC-001)
        assert!(!registry.register(&long_pattern, &["field"]));
    }

    #[test]
    fn test_rejects_too_many_wildcards() {
        let mut registry = ScopePolicyRegistry::new();
        let many_wildcards = "POST|/*/*/*/*/*/*/*/*/*|"; // 9 wildcards

        // Should reject pattern with too many wildcards (SEC-001)
        assert!(!registry.register(many_wildcards, &["field"]));
    }

    #[test]
    fn test_accepts_valid_wildcards() {
        let mut registry = ScopePolicyRegistry::new();
        let valid_pattern = "POST|/*/*/*/*/*/*/*|"; // 7 wildcards (within limit)

        // Should accept pattern within limits
        assert!(registry.register(valid_pattern, &["field"]));
    }

    // BUG-020: Escape sequence handling tests

    #[test]
    fn test_escaped_backslash_before_wildcard() {
        let mut registry = ScopePolicyRegistry::new();
        // Pattern: \\* means literal backslash + wildcard (match any)
        // This should match "POST|/api\anything|"
        assert!(registry.register(r"POST|/api\\*|", &["field"]));

        // Should match path with literal backslash followed by anything
        let scope = registry.get(r"POST|/api\test|");
        assert_eq!(scope, vec!["field"]);

        let scope2 = registry.get(r"POST|/api\foo|");
        assert_eq!(scope2, vec!["field"]);
    }

    #[test]
    fn test_escaped_asterisk_exact_match() {
        let mut registry = ScopePolicyRegistry::new();
        // Pattern: \* means literal asterisk (exact match)
        assert!(registry.register(r"POST|/api/\*|", &["field"]));

        // Should match path with literal asterisk
        let scope = registry.get("POST|/api/*|");
        assert_eq!(scope, vec!["field"]);

        // Should NOT match other paths
        let scope2 = registry.get("POST|/api/test|");
        assert!(scope2.is_empty());
    }

    #[test]
    fn test_double_escaped_backslash() {
        let mut registry = ScopePolicyRegistry::new();
        // Pattern: \\\\ means two literal backslashes (exact match)
        assert!(registry.register(r"POST|/api/\\\\test|", &["field"]));

        // Should match path with two literal backslashes
        let scope = registry.get(r"POST|/api/\\test|");
        assert_eq!(scope, vec!["field"]);
    }

    #[test]
    fn test_is_wildcard_escaped_helper() {
        // Test the helper function directly
        let chars1: Vec<char> = r"\*".chars().collect();
        assert!(ash_is_wildcard_escaped(&chars1, 1)); // * is escaped

        let chars2: Vec<char> = r"\\*".chars().collect();
        assert!(!ash_is_wildcard_escaped(&chars2, 2)); // * is NOT escaped (backslash is escaped)

        let chars3: Vec<char> = r"\\\*".chars().collect();
        assert!(ash_is_wildcard_escaped(&chars3, 3)); // * is escaped

        let chars4: Vec<char> = "*".chars().collect();
        assert!(!ash_is_wildcard_escaped(&chars4, 0)); // * is NOT escaped (no preceding backslash)
    }
}
