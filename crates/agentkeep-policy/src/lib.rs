//! Policy schema, parser, merge and evaluation engine.
//!
//! A policy is assembled from layers, lowest priority first:
//!
//! 1. built-in defaults ([`defaults::DEFAULT_POLICY`]),
//! 2. an agent preset,
//! 3. the global file (`~/.config/agentkeep/agentkeep.toml`),
//! 4. the project file (`agentkeep.toml`, searched upward to the git root),
//! 5. command-line overrides.
//!
//! Merging only ever *adds* `deny` and `hidden` rules; a layer can remove one
//! only through the explicit `[override]` table, which is honoured from the
//! project file alone and reported as a warning so it is never silent.
//!
//! Evaluation is a pure function: [`Compiled::decide`] maps a [`Request`] to a
//! [`Decision`] without I/O, which keeps it cheap to test, fuzz and reason
//! about.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod decide;
pub mod defaults;
pub mod discover;
pub mod merge;
pub mod parse;
pub mod resolved;
pub mod schema;

pub use decide::{Compiled, Decision, Request};
pub use merge::{merge, Layer, Source, Warning};
pub use parse::{parse_str, ParseError};
pub use resolved::{Policy, ResolveError};
pub use schema::PolicyFile;

/// The policy schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
