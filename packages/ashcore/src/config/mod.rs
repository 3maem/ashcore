//! ASH Configuration Module.
//!
//! Server-side configuration for ashcore, including:
//!
//! - **Scope Policies**: Define which fields must be protected per endpoint
//!
//! ## Quick Start
//!
//! ```rust
//! use ashcore::config::{ash_register_scope_policy, ash_get_scope_policy, ash_clear_scope_policies};
//!
//! // Clear existing (for tests)
//! ash_clear_scope_policies();
//!
//! // Register at application startup
//! ash_register_scope_policy("POST|/api/transfer|", &["amount", "recipient"]);
//!
//! // Use in request handler
//! let scope = ash_get_scope_policy("POST|/api/transfer|");
//! // scope = ["amount", "recipient"]
//! ```
//!
//! See [`scope_policies`] module for full documentation.

mod scope_policies;

// New canonical names with ash_ prefix
pub use scope_policies::{
    ash_clear_scope_policies, ash_get_all_scope_policies, ash_get_scope_policy,
    ash_has_scope_policy, ash_register_scope_policies, ash_register_scope_policies_ordered,
    ash_register_scope_policy, ScopePolicyRegistry,
};

// Deprecated aliases for backward compatibility
#[allow(deprecated)]
pub use scope_policies::{
    clear_scope_policies, get_all_scope_policies, get_scope_policy, has_scope_policy,
    register_scope_policies, register_scope_policy,
};
