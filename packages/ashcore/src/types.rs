//! Core types for ashcore.
//!
//! This module defines the data structures used throughout ASH:
//!
//! ## Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`AshMode`] | Security mode (minimal, balanced, strict) |
//! | [`BuildProofInput`] | Input parameters for proof generation |
//! | [`VerifyInput`] | Input parameters for proof verification |
//! | [`StoredContext`] | Server-side context storage |
//!
//! ## Security Modes
//!
//! | Mode | Use Case | Protection Level |
//! |------|----------|------------------|
//! | `Minimal` | Low-risk operations | Basic integrity |
//! | `Balanced` | Default for most APIs | Good security/performance balance |
//! | `Strict` | Financial/sensitive data | Maximum protection |
//!
//! ## Example
//!
//! ```rust
//! use ashcore::AshMode;
//! use std::str::FromStr;
//!
//! // Parse from string
//! let mode = AshMode::from_str("balanced").unwrap();
//! assert_eq!(mode, AshMode::Balanced);
//!
//! // Default is Balanced
//! assert_eq!(AshMode::default(), AshMode::Balanced);
//!
//! // Display as string
//! assert_eq!(format!("{}", AshMode::Strict), "strict");
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::errors::{AshError, AshErrorCode};

/// Security mode for ASH verification.
///
/// Different modes provide different levels of security and overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AshMode {
    /// Lightweight integrity check.
    /// Lowest overhead, basic protection.
    Minimal,

    /// Default recommended mode.
    /// Good balance between security and performance.
    #[default]
    Balanced,

    /// Highest security level.
    /// Field-level integrity, strongest protection.
    Strict,
}

impl fmt::Display for AshMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AshMode::Minimal => write!(f, "minimal"),
            AshMode::Balanced => write!(f, "balanced"),
            AshMode::Strict => write!(f, "strict"),
        }
    }
}

impl FromStr for AshMode {
    type Err = AshError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(AshMode::Minimal),
            "balanced" => Ok(AshMode::Balanced),
            "strict" => Ok(AshMode::Strict),
            _ => Err(AshError::new(
                AshErrorCode::ModeViolation,
                "Invalid mode. Expected: minimal, balanced, or strict",
            )),
        }
    }
}

/// Input for building a proof.
///
/// # Security Note
///
/// The `nonce` field contains root key material. The `Debug` implementation
/// redacts it to prevent accidental exposure in logs.
#[derive(Clone)]
pub struct BuildProofInput {
    /// Security mode
    pub mode: AshMode,
    /// Canonical binding (e.g., "POST|/api/update|")
    pub binding: String,
    /// Context ID from server
    pub context_id: String,
    /// Optional nonce for server-assisted mode
    pub nonce: Option<String>,
    /// Canonicalized payload string
    pub canonical_payload: String,
}

/// BUG-089: Custom Debug that redacts nonce to prevent accidental log exposure.
impl fmt::Debug for BuildProofInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuildProofInput")
            .field("mode", &self.mode)
            .field("binding", &self.binding)
            .field("context_id", &self.context_id)
            .field("nonce", &self.nonce.as_ref().map(|_| "[REDACTED]"))
            .field("canonical_payload", &"[REDACTED]")
            .finish()
    }
}

impl BuildProofInput {
    /// Create a new BuildProofInput.
    pub fn new(
        mode: AshMode,
        binding: impl Into<String>,
        context_id: impl Into<String>,
        nonce: Option<String>,
        canonical_payload: impl Into<String>,
    ) -> Self {
        Self {
            mode,
            binding: binding.into(),
            context_id: context_id.into(),
            nonce,
            canonical_payload: canonical_payload.into(),
        }
    }
}

/// Input for verifying a proof.
///
/// # Security Note
///
/// Both proof fields contain security-sensitive values. The `Debug` implementation
/// redacts them to prevent accidental exposure in logs.
#[derive(Clone)]
pub struct VerifyInput {
    /// Expected proof (computed by server)
    pub expected_proof: String,
    /// Actual proof (received from client)
    pub actual_proof: String,
}

/// BUG-090: Custom Debug that redacts proof fields to prevent accidental log exposure.
impl fmt::Debug for VerifyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyInput")
            .field("expected_proof", &"[REDACTED]")
            .field("actual_proof", &"[REDACTED]")
            .finish()
    }
}

impl VerifyInput {
    /// Create a new VerifyInput.
    pub fn new(expected_proof: impl Into<String>, actual_proof: impl Into<String>) -> Self {
        Self {
            expected_proof: expected_proof.into(),
            actual_proof: actual_proof.into(),
        }
    }
}

/// Context information returned to client.
///
/// # Security Note
///
/// The `nonce` field contains root key material. The `Debug` implementation
/// redacts it to prevent accidental exposure in logs. Use `.nonce` directly
/// only when intentionally transmitting to the client.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextPublicInfo {
    /// Opaque context ID
    pub context_id: String,
    /// Expiration time (milliseconds since epoch)
    pub expires_at: u64,
    /// Security mode
    pub mode: AshMode,
    /// Optional nonce for server-assisted mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// BUG-059: Custom Debug that redacts nonce to prevent accidental log exposure.
impl fmt::Debug for ContextPublicInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextPublicInfo")
            .field("context_id", &self.context_id)
            .field("expires_at", &self.expires_at)
            .field("mode", &self.mode)
            .field("nonce", &self.nonce.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Stored context (server-side).
///
/// # Security Note
///
/// The `nonce` field contains root key material. The `Debug` implementation
/// redacts it to prevent accidental exposure in logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredContext {
    /// Opaque context ID
    pub context_id: String,
    /// Canonical binding
    pub binding: String,
    /// Security mode
    pub mode: AshMode,
    /// Issue time (milliseconds since epoch)
    pub issued_at: u64,
    /// Expiration time (milliseconds since epoch)
    pub expires_at: u64,
    /// Optional nonce (root key material — never serialize to external consumers).
    ///
    /// BUG-070: `skip_serializing` prevents nonce from leaking when `StoredContext`
    /// is serialized to JSON (e.g., API responses, cache stores, audit logs).
    /// BUG-059 already redacts nonce in `Debug`, but `Serialize` was still exposed.
    /// Use `.nonce` field directly only when intentionally persisting to a secure store.
    #[serde(skip_serializing, skip_deserializing)]
    #[serde(default)]
    pub nonce: Option<String>,
    /// Consumption time (null until consumed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
}

/// BUG-059: Custom Debug that redacts nonce to prevent accidental log exposure.
impl fmt::Debug for StoredContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredContext")
            .field("context_id", &self.context_id)
            .field("binding", &self.binding)
            .field("mode", &self.mode)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("nonce", &self.nonce.as_ref().map(|_| "[REDACTED]"))
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

impl StoredContext {
    /// Check if context has been consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    /// Check if context has expired.
    ///
    /// Returns `true` when `now_ms >= expires_at` (boundary inclusive — the context
    /// is considered expired AT the expiration time, not only after it).
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ash_mode_default() {
        assert_eq!(AshMode::default(), AshMode::Balanced);
    }

    #[test]
    fn test_ash_mode_from_str() {
        assert_eq!("minimal".parse::<AshMode>().unwrap(), AshMode::Minimal);
        assert_eq!("balanced".parse::<AshMode>().unwrap(), AshMode::Balanced);
        assert_eq!("strict".parse::<AshMode>().unwrap(), AshMode::Strict);
        assert_eq!("BALANCED".parse::<AshMode>().unwrap(), AshMode::Balanced);
    }

    #[test]
    fn test_ash_mode_display() {
        assert_eq!(AshMode::Minimal.to_string(), "minimal");
        assert_eq!(AshMode::Balanced.to_string(), "balanced");
        assert_eq!(AshMode::Strict.to_string(), "strict");
    }

    #[test]
    fn test_stored_context_is_expired() {
        let ctx = StoredContext {
            context_id: "test".to_string(),
            binding: "POST|/api|".to_string(),
            mode: AshMode::Balanced,
            issued_at: 1000,
            expires_at: 2000,
            nonce: None,
            consumed_at: None,
        };

        assert!(!ctx.is_expired(1500));
        assert!(ctx.is_expired(2000));
        assert!(ctx.is_expired(3000));
    }

    #[test]
    fn test_stored_context_is_consumed() {
        let mut ctx = StoredContext {
            context_id: "test".to_string(),
            binding: "POST|/api|".to_string(),
            mode: AshMode::Balanced,
            issued_at: 1000,
            expires_at: 2000,
            nonce: None,
            consumed_at: None,
        };

        assert!(!ctx.is_consumed());
        ctx.consumed_at = Some(1500);
        assert!(ctx.is_consumed());
    }
}
