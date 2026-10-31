//! Static scanner for agent attack surfaces: prompt injection hidden in
//! instruction files, exfiltration beacons, risky shell snippets and
//! over-broad agent configurations.
//!
//! The scanner is detection, not enforcement. It reads repositories that may
//! be hostile (threat actor T1 in `docs/threat-model.md`), so every part of it
//! treats its input as adversarial: the walker never follows symlinks and caps
//! sizes, depth and counts; structured parsers run with recursion and alias
//! budgets; regexes are compiled with size limits and run in linear time; and
//! snippets are escaped before anyone prints them.
//!
//! The moving parts:
//!
//! - [`rule`]: the YAML rule format, loading and validation. Rules carry
//!   inline examples that are run as tests ([`engine::run_examples`]).
//! - `detect` (private): one module per `detect:` kind.
//! - [`walk`]: file discovery under a scan root.
//! - [`engine`]: [`Scanner`], which ties rules and files together.
//! - [`report`]: [`Finding`], [`Report`] and fingerprints.
//! - [`output`]: text, `agentkeep.scan/1` JSON and SARIF 2.1.0 renderers.
//! - [`builtin`]: the rule set compiled into the binary from `rules/`.
//! - [`corpus`]: precision and recall of the rules over a labelled corpus.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod builtin;
pub mod corpus;
mod detect;
pub mod engine;
pub mod output;
pub mod report;
pub mod rule;
mod text;
pub mod walk;

pub use engine::{ExampleFailure, Scanner, TextScan};
pub use report::{FileError, Finding, Position, Report, Severity, SkipReason, Skipped};
pub use rule::{Rule, RuleError};
pub use walk::WalkOptions;

/// The crate version, re-exported so the CLI can report component versions.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
