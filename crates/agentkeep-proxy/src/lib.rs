//! Egress proxy with domain allowlist, TLS inspection and data-loss protection for agentkeep
//!
//! This crate is a placeholder created in Phase 0. See `PLAN.md` for the
//! design it will implement and the phase in which it lands.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
