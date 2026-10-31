//! Findings, scan reports, severities and fingerprints.
//!
//! These types are what the output formats serialise, so their field order
//! is the stable key order of the JSON report: they are structs, never maps.

use std::fmt::{self, Write as _};
use std::ops::Range;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How bad a finding is. Ordered: `Info < Low < Medium < High < Critical`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing, not a problem by itself.
    #[default]
    Info,
    /// Unusual; review when convenient.
    Low,
    /// Likely a problem in context.
    Medium,
    /// A problem that an attacker can use.
    High,
    /// Directly exploitable or a clear sign of an attack.
    Critical,
}

impl Severity {
    /// Every severity, lowest first.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// The lowercase name used in rule files and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A severity name that is not one of `info`, `low`, `medium`, `high`,
/// `critical`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown severity `{0}` (expected info, low, medium, high or critical)")]
pub struct ParseSeverityError(String);

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::ALL
            .into_iter()
            .find(|sev| sev.as_str() == s)
            .ok_or_else(|| ParseSeverityError(s.to_owned()))
    }
}

/// A 1-based line and column. Columns count Unicode scalar values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Position {
    /// 1-based line.
    pub line: usize,
    /// 1-based column in Unicode scalar values.
    pub column: usize,
}

/// One detection in one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The rule that fired, `category/slug`.
    pub rule_id: String,
    /// The rule's severity.
    pub severity: Severity,
    /// The rule's title.
    pub title: String,
    /// The title plus what this particular match is.
    pub message: String,
    /// Path relative to the scan root, `/`-separated.
    pub path: String,
    /// Where the match starts.
    pub start: Position,
    /// Where the match ends (exclusive, as in SARIF).
    pub end: Position,
    /// The matched line(s), escaped, at most 200 characters.
    pub snippet: String,
    /// Stable identity of the finding; see [`fingerprint`].
    pub fingerprint: String,
    /// Byte range of the match in the scanned text. Not part of the
    /// serialised report; used by tests and the property checks.
    #[serde(skip)]
    pub byte_range: Range<usize>,
}

/// Why a path was not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// A symbolic link; the scanner never follows them.
    Symlink,
    /// A directory on the skip list (`.git`, `node_modules`, ...).
    ExcludedDir,
    /// Larger than the size limit.
    TooLarge,
    /// Contains NUL bytes in the first 8 KiB.
    Binary,
    /// Mostly invalid UTF-8.
    NotUtf8,
    /// A FIFO, socket or device.
    NotRegularFile,
    /// Deeper than the depth limit.
    DepthLimit,
    /// The file-count limit was reached here; this and everything after it
    /// was not scanned.
    FileLimit,
    /// The entry changed between listing and opening it.
    ChangedDuringScan,
}

impl SkipReason {
    /// The kebab-case name used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::Symlink => "symlink",
            SkipReason::ExcludedDir => "excluded-dir",
            SkipReason::TooLarge => "too-large",
            SkipReason::Binary => "binary",
            SkipReason::NotUtf8 => "not-utf8",
            SkipReason::NotRegularFile => "not-regular-file",
            SkipReason::DepthLimit => "depth-limit",
            SkipReason::FileLimit => "file-limit",
            SkipReason::ChangedDuringScan => "changed-during-scan",
        }
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A path that was not scanned, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// Path relative to the scan root, `/`-separated.
    pub path: String,
    /// Why.
    pub reason: SkipReason,
}

/// A problem with one file that did not stop the scan: unreadable, or a
/// structured rule could not parse it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileError {
    /// Path relative to the scan root, `/`-separated.
    pub path: String,
    /// What went wrong, escaped for display.
    pub message: String,
}

/// Finding counts per severity, highest first in the serialised form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct BySeverity {
    /// Critical findings.
    pub critical: usize,
    /// High findings.
    pub high: usize,
    /// Medium findings.
    pub medium: usize,
    /// Low findings.
    pub low: usize,
    /// Info findings.
    pub info: usize,
}

impl BySeverity {
    fn bump(&mut self, sev: Severity) {
        let slot = match sev {
            Severity::Critical => &mut self.critical,
            Severity::High => &mut self.high,
            Severity::Medium => &mut self.medium,
            Severity::Low => &mut self.low,
            Severity::Info => &mut self.info,
        };
        *slot += 1;
    }
}

/// Totals for a report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Files read and offered to the rules.
    pub files_scanned: usize,
    /// Total findings.
    pub findings: usize,
    /// Findings per severity.
    pub by_severity: BySeverity,
}

/// The result of scanning a root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The scan root as given.
    pub root: String,
    /// Findings, ordered by path (walk order), then position, then rule id.
    pub findings: Vec<Finding>,
    /// Paths not scanned.
    pub skipped: Vec<Skipped>,
    /// Per-file problems.
    pub errors: Vec<FileError>,
    /// Files read and offered to the rules.
    pub files_scanned: usize,
    /// True when a file-count or depth limit cut the walk short.
    pub truncated: bool,
}

impl Report {
    /// Totals for output.
    pub fn summary(&self) -> Summary {
        let mut by_severity = BySeverity::default();
        for f in &self.findings {
            by_severity.bump(f.severity);
        }
        Summary {
            files_scanned: self.files_scanned,
            findings: self.findings.len(),
            by_severity,
        }
    }

    /// The highest severity among the findings.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Is any finding at or above `threshold`? This drives the exit code.
    pub fn fails_at(&self, threshold: Severity) -> bool {
        self.max_severity().is_some_and(|s| s >= threshold)
    }

    /// Number of directories skipped because they are on the skip list.
    pub fn excluded_dirs(&self) -> usize {
        self.skipped
            .iter()
            .filter(|s| s.reason == SkipReason::ExcludedDir)
            .count()
    }
}

/// Lowercase hex SHA-256 of `rule_id \0 path \0 normalized snippet`, where
/// the snippet is trimmed and runs of whitespace collapse to one space. It
/// does not depend on the line number, so it survives lines moving, which
/// is what GitHub code scanning needs to de-duplicate across runs.
pub fn fingerprint(rule_id: &str, path: &str, snippet: &str) -> String {
    let normalized = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(path.as_bytes());
    hasher.update([0u8]);
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Escape invisible and control characters as `\u{XXXX}` so hostile text
/// (file names, messages) is safe to print in a terminal or on GitHub.
pub fn escape_for_display(s: &str) -> String {
    crate::text::escape_for_display(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_and_names() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        for s in Severity::ALL {
            assert_eq!(s.as_str().parse::<Severity>().unwrap(), s);
            assert_eq!(s.to_string(), s.as_str());
        }
        assert!("HIGH".parse::<Severity>().is_err());
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn fingerprint_ignores_whitespace_but_not_identity() {
        let a = fingerprint("r/x", "a.md", "  curl   x |  sh ");
        let b = fingerprint("r/x", "a.md", "curl x | sh");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, fingerprint("r/y", "a.md", "curl x | sh"));
        assert_ne!(a, fingerprint("r/x", "b.md", "curl x | sh"));
        // The separator keeps field boundaries unambiguous.
        assert_ne!(fingerprint("ab", "c", "d"), fingerprint("a", "bc", "d"));
    }

    #[test]
    fn fingerprint_known_value() {
        // sha256("r\0p\0s"), computed independently.
        assert_eq!(
            fingerprint("r", "p", " s \n"),
            "cadb9ce82a08113c23fce48e75a8bdd96b9ec6fe4686930be35350f32e442396"
        );
        assert_eq!(
            fingerprint(
                "exfiltration/markdown-image-beacon",
                "docs/a.md",
                "![x](https://a.example/p.png?d=1)"
            ),
            "96bdf1a1510cdfd7765a1714d1ce3c80e8e522686136cee84ce6fab46ef651eb"
        );
    }

    #[test]
    fn summary_and_threshold() {
        let mk = |sev| Finding {
            rule_id: "a/b".into(),
            severity: sev,
            title: String::new(),
            message: String::new(),
            path: String::new(),
            start: Position { line: 1, column: 1 },
            end: Position { line: 1, column: 1 },
            snippet: String::new(),
            fingerprint: String::new(),
            byte_range: 0..0,
        };
        let report = Report {
            findings: vec![mk(Severity::Medium), mk(Severity::High), mk(Severity::High)],
            files_scanned: 3,
            ..Report::default()
        };
        let s = report.summary();
        assert_eq!(s.findings, 3);
        assert_eq!(s.by_severity.high, 2);
        assert_eq!(s.by_severity.medium, 1);
        assert_eq!(report.max_severity(), Some(Severity::High));
        assert!(report.fails_at(Severity::High));
        assert!(!report.fails_at(Severity::Critical));
        assert!(!Report::default().fails_at(Severity::Info));
        let json = serde_json::to_string(&s.by_severity).unwrap();
        assert!(json.starts_with("{\"critical\":0,\"high\":2"));
    }
}
