//! Shared helpers used by every agentkeep crate: path expansion and
//! normalisation, human-readable sizes and durations, and the heuristic that
//! decides whether an environment variable name looks like a secret.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod paths;
pub mod secrets;
pub mod units;

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
