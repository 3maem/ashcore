//! Generic binding normalizer.
//!
//! Normalizes any binding value (ip, device, session, user, tenant, route)
//! with consistent rules: trimming, encoding, control character rejection,
//! and length enforcement.
//!
//! ## Why This Exists
//!
//! Previously, SDKs applied ad-hoc normalization to binding values with
//! inconsistent rules (different trimming, different charset checks).
//! This module provides a single function that all SDKs call for any
//! binding type.
//!
//! ## Binding Types
//!
//! | Type | Example | Description |
//! |------|---------|-------------|
//! | `Route` | `POST\|/api/users\|page=1` | HTTP method + path + query |
//! | `Ip` | `192.168.1.1` | Client IP address |
//! | `Device` | `device_abc123` | Device identifier |
//! | `Session` | `sess_xyz789` | Session token |
//! | `User` | `user@example.com` | User identifier |
//! | `Tenant` | `tenant_acme` | Multi-tenant identifier |
//! | `Custom` | any string | Application-defined binding |

use crate::errors::{AshError, AshErrorCode, InternalReason};

/// Maximum allowed length for any binding value.
pub const MAX_BINDING_VALUE_LENGTH: usize = 8192;

/// Minimum allowed length for a non-empty binding value.
pub const MIN_BINDING_VALUE_LENGTH: usize = 1;

/// Binding type classification.
///
/// Determines which additional validation rules apply beyond the
/// universal rules (trimming, control char rejection, length check).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingType {
    /// HTTP route binding (METHOD|PATH|QUERY format).
    /// Use `ash_normalize_binding()` for this type — it has specialized logic.
    Route,
    /// IP address binding.
    Ip,
    /// Device identifier.
    Device,
    /// Session identifier.
    Session,
    /// User identifier.
    User,
    /// Tenant identifier.
    Tenant,
    /// Application-defined custom binding.
    Custom,
}

impl std::fmt::Display for BindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingType::Route => write!(f, "route"),
            BindingType::Ip => write!(f, "ip"),
            BindingType::Device => write!(f, "device"),
            BindingType::Session => write!(f, "session"),
            BindingType::User => write!(f, "user"),
            BindingType::Tenant => write!(f, "tenant"),
            BindingType::Custom => write!(f, "custom"),
        }
    }
}

/// Result of binding normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedBindingValue {
    /// The normalized value (trimmed, validated)
    pub value: String,

    /// The binding type that was applied
    pub binding_type: BindingType,

    /// Original length before trimming
    pub original_length: usize,

    /// Whether the value was trimmed
    pub was_trimmed: bool,
}

/// Normalize a binding value with universal safety rules.
///
/// ## Universal Rules (all binding types)
///
/// 1. Leading/trailing whitespace is trimmed
/// 2. Control characters (U+0000–U+001F, U+007F) are rejected
/// 3. Newlines (`\r`, `\n`) are rejected
/// 4. NULL bytes are rejected
/// 5. Empty values (after trimming) are rejected
/// 6. Values exceeding `MAX_BINDING_VALUE_LENGTH` (8192 bytes) are rejected
///
/// ## Type-Specific Rules
///
/// - **Route**: Use `ash_normalize_binding()` instead (specialized path/query logic)
/// - **Ip**: Must be valid IPv4 or IPv6 address (parsed via `std::net::IpAddr`)
/// - **User**: NFC normalization applied
/// - **All others**: Universal rules only
///
/// # Example
///
/// ```rust
/// use ashcore::binding::{ash_normalize_binding_value, BindingType};
///
/// let result = ash_normalize_binding_value(BindingType::Ip, "  192.168.1.1  ").unwrap();
/// assert_eq!(result.value, "192.168.1.1");
/// assert!(result.was_trimmed);
///
/// let result = ash_normalize_binding_value(BindingType::Device, "device_abc123").unwrap();
/// assert_eq!(result.value, "device_abc123");
/// assert!(!result.was_trimmed);
///
/// // Control characters are rejected
/// assert!(ash_normalize_binding_value(BindingType::Session, "sess\x00abc").is_err());
/// ```
pub fn ash_normalize_binding_value(
    binding_type: BindingType,
    value: &str,
) -> Result<NormalizedBindingValue, AshError> {
    let original_length = value.len();

    // Rule 1: Trim whitespace
    let trimmed = value.trim();
    let was_trimmed = trimmed.len() != original_length;

    // Rule 5: Empty check (after trim)
    if trimmed.is_empty() {
        return Err(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::General,
            format!("Binding value for '{}' cannot be empty", binding_type),
        ));
    }

    // Rule 6: Length check
    if trimmed.len() > MAX_BINDING_VALUE_LENGTH {
        return Err(AshError::with_reason(
            AshErrorCode::ValidationError,
            InternalReason::General,
            format!(
                "Binding value for '{}' exceeds maximum length of {} bytes",
                binding_type, MAX_BINDING_VALUE_LENGTH
            ),
        ));
    }

    // Rules 2-4: Control character / newline / NULL rejection
    for (i, ch) in trimmed.char_indices() {
        if ch == '\0' {
            return Err(AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::General,
                format!(
                    "Binding value for '{}' contains NULL byte at position {}",
                    binding_type, i
                ),
            ));
        }
        if ch == '\r' || ch == '\n' {
            return Err(AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::General,
                format!(
                    "Binding value for '{}' contains newline at position {}",
                    binding_type, i
                ),
            ));
        }
        if ch.is_control() {
            return Err(AshError::with_reason(
                AshErrorCode::ValidationError,
                InternalReason::General,
                format!(
                    "Binding value for '{}' contains control character at position {}",
                    binding_type, i
                ),
            ));
        }
    }

    // Type-specific rules
    match binding_type {
        BindingType::Route => {
            Err(AshError::new(
                AshErrorCode::ValidationError,
                "Use ash_normalize_binding() for Route bindings — it has specialized path/query normalization",
            ))
        }
        BindingType::Ip => {
            // IP addresses must be ASCII printable, no spaces
            if !trimmed.is_ascii() {
                return Err(AshError::with_reason(
                    AshErrorCode::ValidationError,
                    InternalReason::General,
                    "IP binding must contain only ASCII characters",
                ));
            }
            if trimmed.contains(' ') {
                return Err(AshError::with_reason(
                    AshErrorCode::ValidationError,
                    InternalReason::General,
                    "IP binding must not contain spaces",
                ));
            }
            // SEC-AUDIT-008: Validate IP address is semantically valid
            // Prevents accepting syntactically plausible but invalid addresses
            // like 999.999.999.999 which could bypass binding checks.
            // BUG-063: Parse and re-serialize to canonical form. This ensures
            // IPv6 addresses like "2001:0db8::" and "2001:db8::" produce the
            // same binding value, preventing client-server mismatches.
            let parsed_ip: std::net::IpAddr = trimmed.parse().map_err(|_| {
                AshError::with_reason(
                    AshErrorCode::ValidationError,
                    InternalReason::General,
                    "IP binding must be a valid IPv4 or IPv6 address",
                )
            })?;
            // M5-FIX: Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4.
            // This prevents cross-SDK mismatches when one side sends IPv4 and
            // the other sends the IPv4-mapped IPv6 form.
            let canonical_ip = match parsed_ip {
                std::net::IpAddr::V6(v6) => {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        std::net::IpAddr::V4(v4).to_string()
                    } else {
                        parsed_ip.to_string()
                    }
                }
                _ => parsed_ip.to_string(),
            };
            Ok(NormalizedBindingValue {
                value: canonical_ip,
                binding_type,
                original_length,
                was_trimmed,
            })
        }
        BindingType::User => {
            // Apply NFC normalization to user identifiers
            use unicode_normalization::UnicodeNormalization;
            let normalized: String = trimmed.nfc().collect();
            // BUG-052: Re-validate length after NFC normalization.
            // Unicode normalization can change string length (e.g., combining
            // characters may expand), potentially bypassing the pre-normalization check.
            if normalized.len() > MAX_BINDING_VALUE_LENGTH {
                return Err(AshError::with_reason(
                    AshErrorCode::ValidationError,
                    InternalReason::General,
                    format!(
                        "Binding value for '{}' exceeds maximum length of {} bytes after NFC normalization",
                        binding_type, MAX_BINDING_VALUE_LENGTH
                    ),
                ));
            }
            Ok(NormalizedBindingValue {
                value: normalized,
                binding_type,
                original_length,
                was_trimmed,
            })
        }
        // BUG-094: Device, Session, Tenant, Custom — apply NFC normalization.
        // Previously only User had NFC normalization, but Unicode form mismatches
        // can occur on any platform for any binding type containing non-ASCII text.
        // Without NFC, the same logical string could produce different binding hashes
        // on macOS (NFD default) vs Linux (NFC default).
        // M6-FIX: List all remaining variants explicitly instead of wildcard `_`.
        // This ensures new BindingType variants trigger a compiler error, preventing
        // accidental bypass of NFC normalization.
        BindingType::Device
        | BindingType::Session
        | BindingType::Tenant
        | BindingType::Custom => {
            use unicode_normalization::UnicodeNormalization;
            let normalized: String = trimmed.nfc().collect();
            // Re-validate length after NFC normalization (same as User type).
            if normalized.len() > MAX_BINDING_VALUE_LENGTH {
                return Err(AshError::with_reason(
                    AshErrorCode::ValidationError,
                    InternalReason::General,
                    format!(
                        "Binding value for '{}' exceeds maximum length of {} bytes after NFC normalization",
                        binding_type, MAX_BINDING_VALUE_LENGTH
                    ),
                ));
            }
            Ok(NormalizedBindingValue {
                value: normalized,
                binding_type,
                original_length,
                was_trimmed,
            })
        }
    }
    // M6-FIX: Removed unreachable dead code that bypassed NFC normalization.
    // The #[allow(unreachable_code)] was suppressing a useful compiler safety net.
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Universal rules ───────────────────────────────────────────────

    #[test]
    fn test_trim_whitespace() {
        let r = ash_normalize_binding_value(BindingType::Device, "  dev_123  ").unwrap();
        assert_eq!(r.value, "dev_123");
        assert!(r.was_trimmed);
    }

    #[test]
    fn test_no_trim_needed() {
        let r = ash_normalize_binding_value(BindingType::Device, "dev_123").unwrap();
        assert_eq!(r.value, "dev_123");
        assert!(!r.was_trimmed);
    }

    #[test]
    fn test_reject_empty() {
        assert!(ash_normalize_binding_value(BindingType::Session, "").is_err());
    }

    #[test]
    fn test_reject_whitespace_only() {
        assert!(ash_normalize_binding_value(BindingType::Session, "   ").is_err());
    }

    #[test]
    fn test_reject_null_byte() {
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\x00abc").is_err());
    }

    #[test]
    fn test_reject_newline() {
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\nabc").is_err());
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\rabc").is_err());
    }

    #[test]
    fn test_reject_control_chars() {
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\x01abc").is_err());
        assert!(ash_normalize_binding_value(BindingType::Device, "dev\x1Fabc").is_err());
    }

    #[test]
    fn test_reject_too_long() {
        let long = "a".repeat(MAX_BINDING_VALUE_LENGTH + 1);
        assert!(ash_normalize_binding_value(BindingType::Custom, &long).is_err());
    }

    #[test]
    fn test_accept_max_length() {
        let max = "a".repeat(MAX_BINDING_VALUE_LENGTH);
        assert!(ash_normalize_binding_value(BindingType::Custom, &max).is_ok());
    }

    // ── Route type redirects ──────────────────────────────────────────

    #[test]
    fn test_route_type_rejected() {
        let err = ash_normalize_binding_value(BindingType::Route, "POST|/api|").unwrap_err();
        assert!(err.message().contains("ash_normalize_binding"));
    }

    // ── IP-specific rules ─────────────────────────────────────────────

    #[test]
    fn test_ip_valid_ipv4() {
        let r = ash_normalize_binding_value(BindingType::Ip, "192.168.1.1").unwrap();
        assert_eq!(r.value, "192.168.1.1");
    }

    #[test]
    fn test_ip_valid_ipv6() {
        let r = ash_normalize_binding_value(BindingType::Ip, "::1").unwrap();
        assert_eq!(r.value, "::1");
    }

    #[test]
    fn test_ip_trimmed() {
        let r = ash_normalize_binding_value(BindingType::Ip, "  10.0.0.1  ").unwrap();
        assert_eq!(r.value, "10.0.0.1");
        assert!(r.was_trimmed);
    }

    #[test]
    fn test_ip_reject_non_ascii() {
        assert!(ash_normalize_binding_value(BindingType::Ip, "192.168.١.1").is_err());
    }

    #[test]
    fn test_ip_reject_spaces() {
        assert!(ash_normalize_binding_value(BindingType::Ip, "192.168.1.1 extra").is_err());
    }

    #[test]
    fn test_ip_reject_invalid_ipv4() {
        // SEC-AUDIT-008: Semantically invalid IP addresses must be rejected
        assert!(ash_normalize_binding_value(BindingType::Ip, "999.999.999.999").is_err());
        assert!(ash_normalize_binding_value(BindingType::Ip, "256.1.1.1").is_err());
        assert!(ash_normalize_binding_value(BindingType::Ip, "1.2.3.4.5").is_err());
    }

    #[test]
    fn test_ip_reject_non_ip_string() {
        // SEC-AUDIT-008: Non-IP strings must be rejected
        assert!(ash_normalize_binding_value(BindingType::Ip, "not_an_ip").is_err());
        assert!(ash_normalize_binding_value(BindingType::Ip, "abc.def.ghi.jkl").is_err());
    }

    #[test]
    fn test_ip_valid_ipv6_full() {
        // BUG-063: IPv6 is now parsed and re-serialized to canonical form.
        // Leading zeros are stripped by Rust's IpAddr::to_string().
        let r = ash_normalize_binding_value(BindingType::Ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap();
        assert_eq!(r.value, "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn test_ip_ipv6_canonical_normalization() {
        // BUG-063: Different representations of the same IPv6 address
        // must produce the same canonical form.
        let r1 = ash_normalize_binding_value(BindingType::Ip, "2001:0db8::1").unwrap();
        let r2 = ash_normalize_binding_value(BindingType::Ip, "2001:db8:0000:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(r1.value, r2.value);
        assert_eq!(r1.value, "2001:db8::1");
    }

    // ── User-specific rules ───────────────────────────────────────────

    #[test]
    fn test_user_nfc_normalization() {
        // e + combining acute accent → é (NFC)
        let decomposed = "caf\u{0065}\u{0301}";
        let r = ash_normalize_binding_value(BindingType::User, decomposed).unwrap();
        assert_eq!(r.value, "café");
    }

    #[test]
    fn test_user_already_nfc() {
        let r = ash_normalize_binding_value(BindingType::User, "user@example.com").unwrap();
        assert_eq!(r.value, "user@example.com");
    }

    // ── Binding type metadata ─────────────────────────────────────────

    #[test]
    fn test_binding_type_preserved() {
        let r = ash_normalize_binding_value(BindingType::Tenant, "acme").unwrap();
        assert_eq!(r.binding_type, BindingType::Tenant);
    }

    #[test]
    fn test_original_length_tracked() {
        let r = ash_normalize_binding_value(BindingType::Device, "  abc  ").unwrap();
        assert_eq!(r.original_length, 7);
        assert_eq!(r.value, "abc");
    }

    #[test]
    fn test_custom_type_accepts_unicode() {
        let r = ash_normalize_binding_value(BindingType::Custom, "مستخدم").unwrap();
        assert_eq!(r.value, "مستخدم");
    }

    #[test]
    fn test_binding_type_display() {
        assert_eq!(BindingType::Route.to_string(), "route");
        assert_eq!(BindingType::Ip.to_string(), "ip");
        assert_eq!(BindingType::Device.to_string(), "device");
        assert_eq!(BindingType::Session.to_string(), "session");
        assert_eq!(BindingType::User.to_string(), "user");
        assert_eq!(BindingType::Tenant.to_string(), "tenant");
        assert_eq!(BindingType::Custom.to_string(), "custom");
    }
}
