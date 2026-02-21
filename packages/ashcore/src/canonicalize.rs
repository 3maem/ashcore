//! Deterministic canonicalization for JSON and URL-encoded payloads.
//!
//! Canonicalization transforms payloads into a **deterministic byte sequence** that is
//! identical across all platforms, languages, and implementations. This is essential
//! for cryptographic hashing - the same logical data must always produce the same hash.
//!
//! ## Why Canonicalization?
//!
//! JSON and URL-encoded data can be represented in multiple equivalent ways:
//!
//! ```text
//! // These are logically equivalent but have different bytes:
//! {"a":1,"b":2}
//! {"b":2,"a":1}
//! { "a" : 1 , "b" : 2 }
//! ```
//!
//! Canonicalization ensures all representations normalize to a single form.
//!
//! ## JSON Canonicalization (RFC 8785)
//!
//! | Rule | Example |
//! |------|---------|
//! | Keys sorted lexicographically | `{"z":1,"a":2}` → `{"a":2,"z":1}` |
//! | No whitespace | `{ "a" : 1 }` → `{"a":1}` |
//! | Unicode NFC normalization | Combining characters normalized |
//! | `-0` becomes `0` | `{"a":-0}` → `{"a":0}` |
//! | Whole floats become integers | `{"a":5.0}` → `{"a":5}` |
//! | Arrays preserve order | `[3,1,2]` → `[3,1,2]` |
//!
//! ## Query String Canonicalization
//!
//! | Rule | Example |
//! |------|---------|
//! | Parameters sorted by key | `z=3&a=1` → `a=1&z=3` |
//! | Duplicate keys sorted by value | `a=2&a=1` → `a=1&a=2` |
//! | `+` is literal plus, not space | `a+b` → `a%2Bb` |
//! | Fragment stripped | `a=1#section` → `a=1` |
//! | Uppercase percent encoding | `%2f` → `%2F` |
//!
//! ## Security Limits
//!
//! - **Max recursion depth**: 64 levels (prevents stack overflow)
//! - **Max payload size**: 10 MB (prevents memory exhaustion)
//!
//! ## Example
//!
//! ```rust
//! use ashcore::{ash_canonicalize_json, ash_canonicalize_query};
//!
//! // JSON canonicalization
//! let json = r#"{ "z": 1, "a": { "c": 3, "b": 2 } }"#;
//! let canonical = ash_canonicalize_json(json).unwrap();
//! assert_eq!(canonical, r#"{"a":{"b":2,"c":3},"z":1}"#);
//!
//! // Query string canonicalization
//! let query = "z=3&a=1&a=2#fragment";
//! let canonical = ash_canonicalize_query(query).unwrap();
//! assert_eq!(canonical, "a=1&a=2&z=3");
//! ```

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::errors::{AshError, AshErrorCode};

/// Maximum recursion depth for JSON canonicalization to prevent stack overflow.
/// VULN-001: Prevents DoS via deeply nested JSON.
const MAX_RECURSION_DEPTH: usize = 64;

/// Maximum payload size in bytes for canonicalization.
/// VULN-002: Prevents memory exhaustion from large payloads.
const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// BUG-096: Maximum number of query parameters to prevent DoS via sort amplification.
/// 1024 is generous for legitimate use (most APIs have < 50 params) while preventing
/// adversarial inputs with millions of parameters that would cause O(n log n) sort overhead.
const MAX_QUERY_PARAMS: usize = 1024;

/// Canonicalize a JSON string to deterministic form.
///
/// # Canonicalization Rules
///
/// 1. **Minified**: No whitespace between elements
/// 2. **Key Ordering**: Object keys sorted lexicographically (ascending)
/// 3. **Array Order**: Preserved (arrays are ordered)
/// 4. **Unicode**: NFC normalization applied to all strings
/// 5. **Numbers**:
///    - No scientific notation
///    - No trailing zeros after decimal
///    - `-0` becomes `0`
/// 6. **Unsupported Values**: `NaN`, `Infinity` cause rejection
///
/// # Example
///
/// ```rust
/// use ashcore::ash_canonicalize_json;
///
/// let input = r#"{ "z": 1, "a": { "c": 3, "b": 2 } }"#;
/// let output = ash_canonicalize_json(input).unwrap();
/// assert_eq!(output, r#"{"a":{"b":2,"c":3},"z":1}"#);
/// ```
///
/// # Errors
///
/// Returns `AshError` with `CanonicalizationError` if:
/// - Input is not valid JSON
/// - JSON contains unsupported values (NaN, Infinity)
pub fn ash_canonicalize_json(input: &str) -> Result<String, AshError> {
    // VULN-002: Validate payload size to prevent memory exhaustion
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    // Parse JSON
    // SEC-AUDIT-006: Sanitize error messages to prevent information disclosure
    // The original error may contain portions of the input payload
    let value: Value = serde_json::from_str(input).map_err(|_e| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            "Invalid JSON format".to_string(),
        )
    })?;

    // Canonicalize recursively with depth tracking (VULN-001)
    let canonical = ash_canonicalize_value_with_depth(&value, 0)?;

    // H1-FIX: Use custom JCS serializer instead of serde_json::to_string.
    // serde_json uses ryu for floats which may diverge from ES6 Number.toString()
    // for exponential notation (ryu: "1e21", ES6: "1e+21").
    Ok(jcs_serialize_value(&canonical))
}

/// H1-FIX: Serialize a canonicalized JSON Value to string with ES6-compliant float formatting.
/// Standard serde_json uses ryu which may produce "1e21" instead of ES6's "1e+21".
/// RFC 8785 Section 7.2.2 mandates ES6 Number.prototype.toString() formatting.
fn jcs_serialize_value(value: &Value) -> String {
    let mut out = String::new();
    jcs_write_value(value, &mut out);
    out
}

fn jcs_write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // Check integer types first to preserve precision for large integers
            // (as_f64 would lose precision for values > 2^53)
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                // Use ES6-compliant formatting for true floats
                out.push_str(&es6_format_number(f));
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => {
            // JSON string with proper escaping (delegate to serde for correctness).
            // serde_json::to_string on &str cannot fail for valid Rust strings,
            // so the unwrap is safe here. Using unwrap instead of a broken fallback
            // that would produce unescaped JSON.
            out.push_str(&serde_json::to_string(s).unwrap());
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 { out.push(','); }
                jcs_write_value(v, out);
            }
            out.push(']');
        }
        Value::Object(obj) => {
            out.push('{');
            // Keys are already sorted by ash_canonicalize_value_with_depth
            // (using UTF-16 code unit order). serde_json::Map preserves insertion
            // order when `preserve_order` feature is on, or uses BTreeMap order.
            // Re-sort here to guarantee UTF-16 order regardless of Map implementation.
            let mut entries: Vec<(&String, &Value)> = obj.iter().collect();
            entries.sort_by(|a, b| cmp_utf16_code_units(a.0, b.0));
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 { out.push(','); }
                out.push_str(&serde_json::to_string(*k).unwrap());
                out.push(':');
                jcs_write_value(v, out);
            }
            out.push('}');
        }
    }
}

/// H1-FIX: Format an f64 using ES6 Number.prototype.toString() rules (ECMA-262 7.1.12.1).
///
/// Ryu produces the shortest round-trip representation but uses different thresholds
/// for exponential vs fixed notation than ES6. This function parses ryu's output and
/// re-formats it according to the exact ES6 spec rules:
///   - If k ≤ n ≤ 21: fixed notation with trailing zeros (e.g., 1e20 → "100000000000000000000")
///   - If 0 < n ≤ 21 (n < k): decimal within digits (e.g., 1.5 → "1.5")
///   - If -6 < n ≤ 0: leading zeros (e.g., 1e-6 → "0.000001")
///   - Otherwise: exponential with explicit sign (e.g., 1e21 → "1e+21", 1e-7 → "1e-7")
///
/// where k = number of significant digits, n = decimal exponent position.
fn es6_format_number(f: f64) -> String {
    // Handle zero (both +0 and -0 via IEEE 754 ==)
    if f == 0.0 {
        return "0".to_string();
    }

    // Integer values within safe range: format without decimal point
    if f.fract() == 0.0 && f.abs() < 9007199254740992.0 {
        return format!("{}", f as i64);
    }

    let negative = f.is_sign_negative();
    let f_abs = f.abs();

    // Use ryu for shortest round-trip representation, then parse and reformat
    let ryu_str = ryu::Buffer::new().format(f_abs).to_string();
    let (digits, n) = es6_parse_ryu_output(&ryu_str);
    let k = digits.len() as i32;

    let mut result = String::new();
    if negative {
        result.push('-');
    }

    // Apply ECMA-262 7.1.12.1 formatting rules
    if k <= n && n <= 21 {
        // Case a: all significant digits + trailing zeros
        // e.g., 1e20 → "100000000000000000000"
        result.push_str(&digits);
        for _ in 0..(n - k) {
            result.push('0');
        }
    } else if 0 < n && n <= 21 {
        // Case b: decimal point within the digits
        // e.g., 1.5 → "1.5", 0.5 → "0.5"
        result.push_str(&digits[..n as usize]);
        result.push('.');
        result.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        // Case c: leading zeros after decimal point
        // e.g., 1e-6 → "0.000001"
        result.push_str("0.");
        for _ in 0..(-n) {
            result.push('0');
        }
        result.push_str(&digits);
    } else {
        // Case d/e: exponential notation
        if k == 1 {
            result.push_str(&digits);
        } else {
            result.push(digits.as_bytes()[0] as char);
            result.push('.');
            result.push_str(&digits[1..]);
        }
        let exp = n - 1;
        if exp >= 0 {
            result.push_str(&format!("e+{}", exp));
        } else {
            result.push_str(&format!("e-{}", -exp));
        }
    }

    result
}

/// Parse ryu's output into (significant_digits, n) where n is the decimal
/// exponent position such that value = digits × 10^(n - k), k = digits.len().
fn es6_parse_ryu_output(s: &str) -> (String, i32) {
    if let Some(e_pos) = s.find('e') {
        let mantissa = &s[..e_pos];
        let exp: i32 = s[e_pos + 1..].parse().unwrap_or(0);
        let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
        let dot_pos = mantissa.find('.').unwrap_or(mantissa.len());
        let n = dot_pos as i32 + exp;
        (digits, n)
    } else {
        // Fixed-point notation (no exponent)
        let digits: String = s.chars().filter(|c| *c != '.').collect();
        let dot_pos = s.find('.').unwrap_or(s.len());
        let n = dot_pos as i32;
        (digits, n)
    }
}

/// M8-FIX: Quick node count estimate for pre-canonicalization size check.
/// Returns early once `limit` is exceeded, avoiding full traversal.
/// BUG-FIX: Added depth tracking to prevent stack overflow from deeply nested
/// pre-constructed Values passed to ash_canonicalize_json_value_with_size_check.
fn count_json_nodes(value: &Value, mut count: usize, limit: usize, depth: usize) -> usize {
    if count > limit || depth > MAX_RECURSION_DEPTH {
        return count;
    }
    count += 1;
    match value {
        Value::Array(arr) => {
            for v in arr {
                count = count_json_nodes(v, count, limit, depth + 1);
                if count > limit { return count; }
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj {
                count += 1; // count the key
                count = count_json_nodes(v, count, limit, depth + 1);
                if count > limit { return count; }
            }
        }
        _ => {}
    }
    count
}

/// M1-FIX: Compare two strings by UTF-16 code unit order per RFC 8785 Section 3.2.3.
/// This differs from UTF-8 byte order for supplementary characters (U+10000+).
fn cmp_utf16_code_units(a: &str, b: &str) -> std::cmp::Ordering {
    let mut a_iter = a.encode_utf16();
    let mut b_iter = b.encode_utf16();
    loop {
        match (a_iter.next(), b_iter.next()) {
            (Some(a_unit), Some(b_unit)) => {
                match a_unit.cmp(&b_unit) {
                    std::cmp::Ordering::Equal => continue,
                    other => return other,
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

/// Recursively canonicalize a JSON value with depth tracking.
/// VULN-001: Prevents stack overflow via deeply nested JSON.
fn ash_canonicalize_value_with_depth(value: &Value, depth: usize) -> Result<Value, AshError> {
    // BUG-095: Check recursion depth to prevent stack overflow.
    // Use >= instead of > to allow exactly MAX_RECURSION_DEPTH levels (0..63),
    // not MAX_RECURSION_DEPTH+1 levels (0..64).
    if depth >= MAX_RECURSION_DEPTH {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("JSON exceeds maximum nesting depth of {}", MAX_RECURSION_DEPTH),
        ));
    }

    match value {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(n) => ash_canonicalize_number(n),
        Value::String(s) => Ok(Value::String(ash_canonicalize_string(s))),
        Value::Array(arr) => {
            let canonical: Result<Vec<Value>, AshError> =
                arr.iter().map(|v| ash_canonicalize_value_with_depth(v, depth + 1)).collect();
            Ok(Value::Array(canonical?))
        }
        Value::Object(obj) => {
            // M1-FIX: Sort keys by UTF-16 code unit order per RFC 8785 Section 3.2.3.
            // UTF-8 byte order diverges from UTF-16 code-unit order for supplementary
            // characters (U+10000+). UTF-16 surrogate pairs sort differently than their
            // UTF-8 byte equivalents for characters in the U+E000-U+FFFD vs U+10000+ range.
            let mut sorted: Vec<(&String, &Value)> = obj.iter().collect();
            sorted.sort_by(|a, b| cmp_utf16_code_units(a.0, b.0));

            let mut canonical = serde_json::Map::new();
            for (key, val) in sorted {
                let canonical_key = ash_canonicalize_string(key);
                let canonical_val = ash_canonicalize_value_with_depth(val, depth + 1)?;
                canonical.insert(canonical_key, canonical_val);
            }
            Ok(Value::Object(canonical))
        }
    }
}

/// Canonicalize a number value per RFC 8785 (JCS).
///
/// Rules:
/// - MUST reject NaN and Infinity
/// - MUST convert -0 to 0
/// - MUST convert whole floats to integers (e.g., 5.0 -> 5)
fn ash_canonicalize_number(n: &serde_json::Number) -> Result<Value, AshError> {
    // Check for special values that shouldn't exist in valid JSON
    // but handle edge cases

    if let Some(i) = n.as_i64() {
        // Handle -0 case (though rare in integers)
        if i == 0 {
            return Ok(Value::Number(serde_json::Number::from(0)));
        }
        return Ok(Value::Number(serde_json::Number::from(i)));
    }

    if let Some(u) = n.as_u64() {
        return Ok(Value::Number(serde_json::Number::from(u)));
    }

    if let Some(f) = n.as_f64() {
        // Check for NaN and Infinity (MUST reject per RFC 8785)
        if f.is_nan() {
            return Err(AshError::new(
                AshErrorCode::CanonicalizationError,
                "NaN is not supported in ASH canonicalization (RFC 8785)",
            ));
        }
        if f.is_infinite() {
            return Err(AshError::new(
                AshErrorCode::CanonicalizationError,
                "Infinity is not supported in ASH canonicalization (RFC 8785)",
            ));
        }

        // Handle -0 -> 0 (MUST per RFC 8785)
        let f = if f == 0.0 && f.is_sign_negative() {
            0.0
        } else {
            f
        };

        // RFC 8785: Whole floats MUST become integers (5.0 -> 5)
        // Check if the float is a whole number within safe integer range
        // Note: i64::MAX as f64 rounds up, so we use JavaScript's MAX_SAFE_INTEGER (2^53 - 1)
        // which is the largest integer that can be exactly represented in f64
        const MAX_SAFE_INT: f64 = 9007199254740991.0; // 2^53 - 1
        if f.fract() == 0.0 && (-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&f) {
            let i = f as i64;
            return Ok(Value::Number(serde_json::Number::from(i)));
        }

        // Convert back to Number for non-whole floats
        serde_json::Number::from_f64(f)
            .map(Value::Number)
            .ok_or_else(|| {
                AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Failed to canonicalize number",
                )
            })
    } else {
        Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            "Unsupported number format",
        ))
    }
}

/// Canonicalize a string with Unicode NFC normalization.
fn ash_canonicalize_string(s: &str) -> String {
    s.nfc().collect()
}

/// Canonicalize a JSON Value to a deterministic string.
///
/// This is useful when you already have a parsed Value and want to canonicalize it.
///
/// # Security Note
///
/// Unlike [`ash_canonicalize_json`], this function does NOT validate the size of the input
/// Value, since it's already parsed and in memory. The size limit (MAX_PAYLOAD_SIZE)
/// is enforced by `canonicalize_json` during the string parsing phase.
///
/// If you're accepting Values from untrusted sources, use [`ash_canonicalize_json_value_with_size_check`]
/// instead, or ensure the original JSON string was validated via `ash_canonicalize_json` first.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_canonicalize_json_value;
/// use serde_json::json;
///
/// let value = json!({"z": 1, "a": 2});
/// let output = ash_canonicalize_json_value(&value).unwrap();
/// assert_eq!(output, r#"{"a":2,"z":1}"#);
/// ```
pub fn ash_canonicalize_json_value(value: &Value) -> Result<String, AshError> {
    // VULN-001: Use depth-tracked version to prevent stack overflow
    let canonical = ash_canonicalize_value_with_depth(value, 0)?;
    // H1-FIX: Use custom JCS serializer for ES6-compliant float formatting
    Ok(jcs_serialize_value(&canonical))
}

/// Canonicalize a JSON Value with size validation.
///
/// BUG-044: This is the size-safe version for Values from untrusted sources.
/// It serializes the Value first to check size, then canonicalizes.
///
/// # Security Note
///
/// Use this function when the Value was constructed programmatically from untrusted
/// input without going through `ash_canonicalize_json` first.
///
/// # Example
///
/// ```rust
/// use ashcore::ash_canonicalize_json_value_with_size_check;
/// use serde_json::json;
///
/// let value = json!({"z": 1, "a": 2});
/// let output = ash_canonicalize_json_value_with_size_check(&value).unwrap();
/// assert_eq!(output, r#"{"a":2,"z":1}"#);
/// ```
pub fn ash_canonicalize_json_value_with_size_check(value: &Value) -> Result<String, AshError> {
    // M8-FIX: Pre-canonicalization size estimate to reject huge Values early,
    // before performing O(n log n) sorting and full serialization.
    // Minimum 2 bytes per node (e.g., "1"), so node_count * 2 gives a lower bound.
    let estimated_nodes = count_json_nodes(value, 0, MAX_PAYLOAD_SIZE / 2, 0);
    if estimated_nodes > MAX_PAYLOAD_SIZE / 2 {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes (estimated)", MAX_PAYLOAD_SIZE),
        ));
    }

    // PERF-AUDIT-003: Canonicalize once, then check size of the result.
    let canonical = ash_canonicalize_value_with_depth(value, 0)?;
    // H1-FIX: Use custom JCS serializer for ES6-compliant float formatting
    let result = jcs_serialize_value(&canonical);

    if result.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    Ok(result)
}

/// Canonicalize URL-encoded form data.
///
/// # Canonicalization Rules
///
/// 1. Parse key=value pairs (split on `&`, then on first `=`)
/// 2. Percent-decode all values
/// 3. Apply Unicode NFC normalization
/// 4. Sort pairs by key lexicographically (byte order)
/// 5. For duplicate keys, sort by value (byte order)
/// 6. Re-encode with percent encoding
///
/// # Example
///
/// ```rust
/// use ashcore::ash_canonicalize_urlencoded;
///
/// let input = "z=3&a=1&a=2&b=hello%20world";
/// let output = ash_canonicalize_urlencoded(input).unwrap();
/// assert_eq!(output, "a=1&a=2&b=hello%20world&z=3");
/// ```
pub fn ash_canonicalize_urlencoded(input: &str) -> Result<String, AshError> {
    // VULN-002: Validate payload size
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    if input.is_empty() {
        return Ok(String::new());
    }

    // L14-FIX: Strip leading '?' and fragment '#' for consistency with ash_canonicalize_query.
    // Previously ash_canonicalize_urlencoded did not handle these, creating inconsistency.
    let input = input.strip_prefix('?').unwrap_or(input);
    let input = input.split('#').next().unwrap_or(input);

    if input.is_empty() {
        return Ok(String::new());
    }

    // Parse pairs
    let mut pairs: Vec<(String, String)> = Vec::new();

    for part in input.split('&') {
        if part.is_empty() {
            continue;
        }

        let (key, value) = match part.find('=') {
            Some(pos) => (&part[..pos], &part[pos + 1..]),
            None => (part, ""),
        };

        // Percent-decode (+ is literal plus, not space, per ashcore spec)
        let decoded_key = ash_percent_decode_query(key)?;
        let decoded_value = ash_percent_decode_query(value)?;

        // NFC normalize
        let normalized_key: String = decoded_key.nfc().collect();
        let normalized_value: String = decoded_value.nfc().collect();

        pairs.push((normalized_key, normalized_value));
    }

    // BUG-096: Enforce query parameter count limit before sorting.
    if pairs.len() > MAX_QUERY_PARAMS {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Query string exceeds maximum of {} parameters", MAX_QUERY_PARAMS),
        ));
    }

    // Sort by key first, then by value for duplicate keys (byte-wise)
    pairs.sort_by(|a, b| {
        match a.0.as_bytes().cmp(b.0.as_bytes()) {
            std::cmp::Ordering::Equal => a.1.as_bytes().cmp(b.1.as_bytes()),
            other => other,
        }
    });

    // Re-encode and join (uppercase hex per spec)
    let encoded: Vec<String> = pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", ash_percent_encode_uppercase(&k), ash_percent_encode_uppercase(&v)))
        .collect();

    Ok(encoded.join("&"))
}

/// Percent-decode a string for query strings (RFC 3986).
/// NOTE: + is treated as literal plus, NOT space. Space must be %20.
fn ash_percent_decode_query(input: &str) -> Result<String, AshError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            // Read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() != 2 {
                return Err(AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Invalid percent encoding",
                ));
            }
            let byte = u8::from_str_radix(&hex, 16).map_err(|_| {
                AshError::new(
                    AshErrorCode::CanonicalizationError,
                    "Invalid percent encoding hex",
                )
            })?;
            bytes.push(byte);
        } else {
            // + is literal plus in query strings (not space)
            // Encode character directly to UTF-8 bytes without allocation
            let mut buf = [0u8; 4];
            let encoded = ch.encode_utf8(&mut buf);
            bytes.extend_from_slice(encoded.as_bytes());
        }
    }

    // Convert bytes to UTF-8 string
    String::from_utf8(bytes).map_err(|_| {
        AshError::new(
            AshErrorCode::CanonicalizationError,
            "Invalid UTF-8 in percent-decoded string",
        )
    })
}

/// Canonicalize a URL query string according to ASH specification.
///
/// # Canonicalization Rules (10 MUST rules)
///
/// 1. MUST parse query string after `?` (or use full string if no `?`)
/// 2. MUST strip fragment (#) and everything after it
/// 3. MUST split on `&` to get key=value pairs
/// 4. MUST handle keys without values (treat as empty string)
/// 5. MUST percent-decode all keys and values (+ is literal plus, NOT space)
/// 6. MUST apply Unicode NFC normalization
/// 7. MUST sort pairs by key lexicographically (byte order, strcmp)
/// 8. MUST sort by value for duplicate keys (byte order, strcmp)
/// 9. MUST re-encode with uppercase hex (%XX)
/// 10. MUST join with `&` separator
///
/// # Example
///
/// ```rust
/// use ashcore::ash_canonicalize_query;
///
/// let input = "z=3&a=1&b=hello%20world";
/// let output = ash_canonicalize_query(input).unwrap();
/// assert_eq!(output, "a=1&b=hello%20world&z=3");
///
/// // With leading ?
/// let input2 = "?z=3&a=1";
/// let output2 = ash_canonicalize_query(input2).unwrap();
/// assert_eq!(output2, "a=1&z=3");
///
/// // Fragment is stripped
/// let input3 = "z=3&a=1#section";
/// let output3 = ash_canonicalize_query(input3).unwrap();
/// assert_eq!(output3, "a=1&z=3");
/// ```
pub fn ash_canonicalize_query(input: &str) -> Result<String, AshError> {
    // VULN-002: Validate payload size
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Query string exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE),
        ));
    }

    // Rule 1: Remove leading ? if present
    let query = input.strip_prefix('?').unwrap_or(input);

    // Rule 2: Strip fragment (#) and everything after
    let query = query.split('#').next().unwrap_or(query);

    if query.is_empty() {
        return Ok(String::new());
    }

    // Rule 3 & 4: Parse pairs
    let mut pairs: Vec<(String, String)> = Vec::new();

    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }

        let (key, value) = match part.find('=') {
            Some(pos) => (&part[..pos], &part[pos + 1..]),
            None => (part, ""), // Rule 4: keys without values
        };

        // Rule 5: Percent-decode (+ is literal plus in query strings, NOT space)
        let decoded_key = ash_percent_decode_query(key)?;
        let decoded_value = ash_percent_decode_query(value)?;

        // Rule 6: NFC normalize
        let normalized_key: String = decoded_key.nfc().collect();
        let normalized_value: String = decoded_value.nfc().collect();

        pairs.push((normalized_key, normalized_value));
    }

    // BUG-096: Enforce query parameter count limit before sorting.
    if pairs.len() > MAX_QUERY_PARAMS {
        return Err(AshError::new(
            AshErrorCode::CanonicalizationError,
            format!("Query string exceeds maximum of {} parameters", MAX_QUERY_PARAMS),
        ));
    }

    // Rule 7 & 8: Sort by key, then by value (byte-wise strcmp order)
    pairs.sort_by(|a, b| {
        match a.0.as_bytes().cmp(b.0.as_bytes()) {
            std::cmp::Ordering::Equal => a.1.as_bytes().cmp(b.1.as_bytes()),
            other => other,
        }
    });

    // Rule 9 & 10: Re-encode with uppercase hex and join
    let encoded: Vec<String> = pairs
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                ash_percent_encode_uppercase(&k),
                ash_percent_encode_uppercase(&v)
            )
        })
        .collect();

    Ok(encoded.join("&"))
}

/// Percent-encode a string with uppercase hex digits.
fn ash_percent_encode_uppercase(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);

    for ch in input.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(ch);
            }
            ' ' => {
                result.push_str("%20");
            }
            _ => {
                // Encode character directly to UTF-8 bytes without allocation
                let mut buf = [0u8; 4];
                let encoded = ch.encode_utf8(&mut buf);
                for byte in encoded.as_bytes() {
                    result.push('%');
                    // Use write! to avoid format! allocation
                    use std::fmt::Write;
                    write!(result, "{:02X}", byte).unwrap();
                }
            }
        }
    }

    result
}


#[cfg(test)]
mod tests {
    use super::*;

    // JSON Canonicalization Tests

    #[test]
    fn test_canonicalize_json_simple_object() {
        let input = r#"{"z":1,"a":2}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_nested_object() {
        let input = r#"{"b":{"d":4,"c":3},"a":1}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":1,"b":{"c":3,"d":4}}"#);
    }

    #[test]
    fn test_canonicalize_json_with_whitespace() {
        let input = r#"{ "z" : 1 , "a" : 2 }"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_canonicalize_json_array_preserved() {
        let input = r#"{"arr":[3,1,2]}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"arr":[3,1,2]}"#);
    }

    #[test]
    fn test_canonicalize_json_null() {
        let input = r#"{"a":null}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":null}"#);
    }

    #[test]
    fn test_canonicalize_json_boolean() {
        let input = r#"{"b":true,"a":false}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":false,"b":true}"#);
    }

    #[test]
    fn test_canonicalize_json_empty_object() {
        let input = r#"{}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{}"#);
    }

    #[test]
    fn test_canonicalize_json_empty_array() {
        let input = r#"[]"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"[]"#);
    }

    #[test]
    fn test_canonicalize_json_unicode() {
        // Test with Unicode characters
        let input = r#"{"name":"café"}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"name":"café"}"#);
    }

    #[test]
    fn test_canonicalize_json_invalid() {
        let input = r#"{"a":}"#;
        let result = ash_canonicalize_json(input);
        assert!(result.is_err());
        // SEC-AUDIT-006: Error message should be sanitized (not contain input details)
        let err = result.unwrap_err();
        let err_msg = err.message();
        assert!(!err_msg.contains("{"), "Error should not contain JSON fragments");
        assert!(err_msg.contains("Invalid") || err_msg.contains("invalid"));
    }

    #[test]
    fn test_canonicalize_json_whole_float_becomes_integer() {
        // RFC 8785: Whole floats MUST become integers (5.0 -> 5)
        let input = r#"{"a":5.0}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":5}"#);
    }

    #[test]
    fn test_canonicalize_json_negative_zero_becomes_zero() {
        // RFC 8785: -0 MUST become 0
        // Note: serde_json may normalize -0.0 on parse, but we handle it anyway
        let input = r#"{"a":-0.0}"#;
        let output = ash_canonicalize_json(input).unwrap();
        // Should be 0, not -0
        assert_eq!(output, r#"{"a":0}"#);
    }

    #[test]
    fn test_canonicalize_json_preserves_fractional() {
        // Non-whole floats should preserve their fractional part
        let input = r#"{"a":5.5}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":5.5}"#);
    }

    #[test]
    fn test_canonicalize_json_large_whole_float() {
        // Large whole floats within i64 range should become integers
        let input = r#"{"a":1000000.0}"#;
        let output = ash_canonicalize_json(input).unwrap();
        assert_eq!(output, r#"{"a":1000000}"#);
    }

    // URL-Encoded Canonicalization Tests

    #[test]
    fn test_canonicalize_urlencoded_simple() {
        let input = "z=3&a=1&b=2";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=1&b=2&z=3");
    }

    #[test]
    fn test_canonicalize_urlencoded_duplicate_keys() {
        let input = "a=2&a=1&b=3";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        // Duplicate keys should be sorted by value (byte-wise) per ASH spec
        assert_eq!(output, "a=1&a=2&b=3");
    }

    #[test]
    fn test_canonicalize_urlencoded_encoded_space() {
        let input = "a=hello%20world";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_urlencoded_plus_as_literal() {
        // ashcore treats + as literal plus, not space
        let input = "a=hello+world";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=hello%2Bworld");
    }

    #[test]
    fn test_canonicalize_urlencoded_empty() {
        let input = "";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_canonicalize_urlencoded_no_value() {
        let input = "a&b=2";
        let output = ash_canonicalize_urlencoded(input).unwrap();
        assert_eq!(output, "a=&b=2");
    }

    // Query String Canonicalization Tests

    #[test]
    fn test_canonicalize_query_strips_fragment() {
        let input = "z=3&a=1#section";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&z=3");
    }

    #[test]
    fn test_canonicalize_query_strips_fragment_with_question_mark() {
        let input = "?z=3&a=1#fragment";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&z=3");
    }

    #[test]
    fn test_canonicalize_query_plus_is_literal() {
        // In query strings, + is literal plus, not space
        let input = "a=hello+world";
        let output = ash_canonicalize_query(input).unwrap();
        // + is preserved as %2B (encoded plus)
        assert_eq!(output, "a=hello%2Bworld");
    }

    #[test]
    fn test_canonicalize_query_space_is_percent20() {
        let input = "a=hello%20world";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=hello%20world");
    }

    #[test]
    fn test_canonicalize_query_preserves_empty_value() {
        let input = "a=&b=2";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=&b=2");
    }

    #[test]
    fn test_canonicalize_query_key_without_equals() {
        let input = "flag&b=2";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "b=2&flag=");
    }

    #[test]
    fn test_canonicalize_query_sorts_by_key_then_value() {
        // When keys are equal, sort by value
        let input = "a=2&a=1&a=3";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "a=1&a=2&a=3");
    }

    #[test]
    fn test_canonicalize_query_uppercase_hex() {
        let input = "a=hello%20world"; // lowercase input
        let output = ash_canonicalize_query(input).unwrap();
        // Should be uppercase hex in output
        assert!(output.contains("%20"));
        assert!(!output.contains("%2a")); // no lowercase hex
    }

    #[test]
    fn test_canonicalize_query_byte_order_sorting() {
        // Ensure byte-wise (strcmp) sorting, not locale-dependent
        // ASCII order: '0' (48) < 'A' (65) < 'Z' (90) < 'a' (97) < 'z' (122)
        let input = "z=1&A=2&a=3&0=4";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "0=4&A=2&a=3&z=1");
    }

    #[test]
    fn test_canonicalize_query_only_fragment() {
        let input = "#onlyfragment";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "");
    }

    #[test]
    fn test_canonicalize_query_empty_with_question_mark() {
        let input = "?";
        let output = ash_canonicalize_query(input).unwrap();
        assert_eq!(output, "");
    }

    // Security Tests (VULN-001, VULN-002)

    #[test]
    fn test_rejects_deeply_nested_json() {
        // VULN-001: Test that deeply nested JSON is rejected
        let mut input = String::from("{\"a\":");
        for _ in 0..100 {
            input.push_str("{\"a\":");
        }
        input.push('1');
        for _ in 0..101 {
            input.push('}');
        }

        let result = ash_canonicalize_json(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("nesting depth"));
    }

    #[test]
    fn test_accepts_moderately_nested_json() {
        // Should accept nesting up to MAX_RECURSION_DEPTH (64)
        let mut input = String::from("{\"a\":");
        for _ in 0..30 {
            input.push_str("{\"a\":");
        }
        input.push('1');
        for _ in 0..31 {
            input.push('}');
        }

        let result = ash_canonicalize_json(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_oversized_json_payload() {
        // VULN-002: Test that oversized payloads are rejected
        let large_value = "x".repeat(11 * 1024 * 1024); // 11 MB
        let input = format!(r#"{{"data":"{}"}}"#, large_value);

        let result = ash_canonicalize_json(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum size"));
    }

    #[test]
    fn test_rejects_oversized_query_string() {
        // VULN-002: Test that oversized query strings are rejected
        let large_value = "x".repeat(11 * 1024 * 1024); // 11 MB
        let input = format!("a={}", large_value);

        let result = ash_canonicalize_query(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("maximum size"));
    }
}
