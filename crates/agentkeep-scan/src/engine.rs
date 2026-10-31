//! The scanner: rules applied to files.
//!
//! [`Scanner::scan`] walks a root and scans every file the walker yields;
//! [`Scanner::scan_text`] scans one in-memory file and is what examples, the
//! corpus test and the fuzzer use. Every file is offered to every rule; a
//! rule's `applies_to`/`exclude` globs decide whether it looks.

use std::fmt::{self, Write as _};
use std::path::Path;

use crate::detect::{Input, Match};
use crate::report::{self, FileError, Finding, Report, Skipped};
use crate::rule::{check_unique, Rule, RuleError};
use crate::text::{ceil_char_boundary, escape_for_display, escape_truncated, floor_char_boundary};
use crate::walk::{self, Content, WalkError, WalkOptions};

/// One rule reports at most this many findings per file; a file stuffed
/// with ten thousand zero-width spaces is one problem, not ten thousand.
pub const MAX_FINDINGS_PER_RULE: usize = 1_000;

/// Per-file error messages are cut to this many characters.
const MAX_ERROR_CHARS: usize = 500;

/// A set of rules ready to scan.
#[derive(Debug)]
pub struct Scanner {
    rules: Vec<Rule>,
}

/// Findings and per-file problems from scanning one text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextScan {
    /// Findings, ordered by position then rule id.
    pub findings: Vec<Finding>,
    /// Parse errors and truncation notes, escaped for display.
    pub errors: Vec<String>,
}

impl Scanner {
    /// A scanner over these rules. Rule ids must be unique.
    pub fn new(rules: Vec<Rule>) -> Result<Self, RuleError> {
        check_unique(&rules)?;
        Ok(Self { rules })
    }

    /// A scanner over the rules compiled into the binary.
    pub fn with_builtin_rules() -> Result<Self, RuleError> {
        Self::new(crate::builtin::rules()?)
    }

    /// The rules, in load order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Scan a directory or a single file with default limits.
    pub fn scan(&self, root: &Path) -> Result<Report, WalkError> {
        self.scan_with(root, &WalkOptions::default())
    }

    /// Scan a directory or a single file. Only an unreadable root is an
    /// error; problems with individual files land in the report.
    pub fn scan_with(&self, root: &Path, opts: &WalkOptions) -> Result<Report, WalkError> {
        let walked = walk::walk(root, opts)?;
        let mut report = Report {
            root: root.display().to_string(),
            root_dir: walked.root_dir,
            skipped: walked.skipped,
            errors: walked.errors,
            truncated: walked.truncated,
            ..Report::default()
        };
        for entry in &walked.files {
            match walk::read(entry, opts) {
                Content::Text(text) => {
                    report.files_scanned += 1;
                    let scan = self.scan_text_full(&entry.rel_path, &text);
                    report.findings.extend(scan.findings);
                    report
                        .errors
                        .extend(scan.errors.into_iter().map(|message| FileError {
                            path: entry.rel_path.clone(),
                            message,
                        }));
                }
                Content::Skipped(reason) => report.skipped.push(Skipped {
                    path: entry.rel_path.clone(),
                    reason,
                }),
                Content::Error(message) => report.errors.push(FileError {
                    path: entry.rel_path.clone(),
                    message: escape_truncated(&message, MAX_ERROR_CHARS),
                }),
            }
        }
        Ok(report)
    }

    /// Scan one file's text as if it were at `path` (relative, `/`-separated).
    pub fn scan_text(&self, path: &str, text: &str) -> Vec<Finding> {
        self.scan_text_full(path, text).findings
    }

    /// Like [`Scanner::scan_text`], also returning parse errors.
    pub fn scan_text_full(&self, path: &str, text: &str) -> TextScan {
        scan_with_rules(self.rules.iter(), path, text)
    }

    /// Run every rule's inline examples.
    pub fn run_all_examples(&self) -> Vec<ExampleFailure> {
        self.rules.iter().flat_map(run_examples).collect()
    }
}

fn scan_with_rules<'r>(rules: impl Iterator<Item = &'r Rule>, path: &str, text: &str) -> TextScan {
    let input = Input::new(path, text);
    let mut out = TextScan::default();
    for rule in rules.filter(|r| r.applies_to_path(path)) {
        let mut matches = rule.detector().detect(&input);
        // Detectors promise char-boundary ranges inside the text; clamp
        // anyway so a detector bug cannot become a panic in the report.
        for m in &mut matches {
            let start = floor_char_boundary(text, m.range.start);
            let end = ceil_char_boundary(text, m.range.end.max(start));
            m.range = start..end;
        }
        matches.sort_by_key(|m| (m.range.start, m.range.end));
        matches.dedup_by(|a, b| a.range == b.range);
        if matches.len() > MAX_FINDINGS_PER_RULE {
            out.errors.push(format!(
                "rule {}: {} matches, only the first {MAX_FINDINGS_PER_RULE} are reported",
                rule.id(),
                matches.len()
            ));
            matches.truncate(MAX_FINDINGS_PER_RULE);
        }
        out.findings
            .extend(matches.into_iter().map(|m| finding(rule, &input, m)));
    }
    out.errors.extend(
        input
            .parse_errors()
            .into_iter()
            .map(|e| escape_truncated(&e, MAX_ERROR_CHARS)),
    );
    out.findings.sort_by(|a, b| {
        (a.byte_range.start, a.byte_range.end, &a.rule_id).cmp(&(
            b.byte_range.start,
            b.byte_range.end,
            &b.rule_id,
        ))
    });
    out
}

fn finding(rule: &Rule, input: &Input<'_>, m: Match) -> Finding {
    let text = input.text;
    let lines = input.lines();
    let (start, end) = lines.span(text, &m.range);
    let snippet = crate::text::snippet(text, lines, &m.range);
    let message = match &m.detail {
        Some(detail) => format!("{}: {}", rule.title(), escape_for_display(detail)),
        None => rule.title().to_owned(),
    };
    Finding {
        rule_id: rule.id().to_owned(),
        severity: rule.severity(),
        title: rule.title().to_owned(),
        message,
        path: input.path.to_owned(),
        start,
        end,
        fingerprint: report::fingerprint(rule.id(), input.path, &snippet),
        snippet,
        byte_range: m.range,
    }
}

/// Which list an example came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExampleKind {
    /// `examples.match`: must produce a finding.
    Match,
    /// `examples.nomatch`: must produce none.
    NoMatch,
}

/// An inline example that did not behave as declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExampleFailure {
    /// The rule.
    pub rule_id: String,
    /// Which list.
    pub kind: ExampleKind,
    /// 0-based index in that list.
    pub index: usize,
    /// The path the example was scanned as.
    pub path: String,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for ExampleFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = match self.kind {
            ExampleKind::Match => "match",
            ExampleKind::NoMatch => "nomatch",
        };
        write!(
            f,
            "{}: examples.{list}[{}] (scanned as {}): {}",
            self.rule_id,
            self.index,
            escape_for_display(&self.path),
            self.reason
        )
    }
}

/// Run one rule's inline examples, alone, through the same path as a scan.
pub fn run_examples(rule: &Rule) -> Vec<ExampleFailure> {
    let mut failures = Vec::new();
    let fail = |kind, index, path: &str, reason: String| ExampleFailure {
        rule_id: rule.id().to_owned(),
        kind,
        index,
        path: path.to_owned(),
        reason,
    };
    for (i, ex) in rule.examples().matches.iter().enumerate() {
        let scan = scan_with_rules(std::iter::once(rule), &ex.path, &ex.content);
        if scan.findings.is_empty() {
            let reason = if rule.applies_to_path(&ex.path) {
                let mut r = "expected at least one finding, got none".to_owned();
                if !scan.errors.is_empty() {
                    let _ = write!(r, " ({})", scan.errors.join("; "));
                }
                r
            } else {
                "the example path is not selected by applies_to/exclude".to_owned()
            };
            failures.push(fail(ExampleKind::Match, i, &ex.path, reason));
        }
    }
    for (i, ex) in rule.examples().nomatch.iter().enumerate() {
        let scan = scan_with_rules(std::iter::once(rule), &ex.path, &ex.content);
        if !scan.findings.is_empty() {
            let got: Vec<String> = scan
                .findings
                .iter()
                .map(|f| format!("{}:{} {}", f.start.line, f.start.column, f.message))
                .collect();
            failures.push(fail(
                ExampleKind::NoMatch,
                i,
                &ex.path,
                format!(
                    "expected no finding, got {}: {}",
                    scan.findings.len(),
                    got.join("; ")
                ),
            ));
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Severity, SkipReason};
    use std::fs;

    fn rule(yaml: &str) -> Rule {
        Rule::from_yaml(yaml, "t.yaml", None).unwrap()
    }

    fn regex_rule(id: &str, pattern: &str, applies: &str) -> Rule {
        rule(&format!(
            "id: {id}\nseverity: medium\ntitle: T {id}\ndescription: d\napplies_to: [{applies:?}]\n\
             detect:\n  regex: '{pattern}'\nremediation: r\nexamples:\n  match: ['{pattern}']\n  nomatch: ['zzz']\n"
        ))
    }

    #[test]
    fn scan_text_builds_complete_findings() {
        let s = Scanner::new(vec![regex_rule("t/a", "needle", "**/*.md")]).unwrap();
        let text = "\u{feff}line one\r\nsome needle here\r\n";
        let f = s.scan_text("docs/x.md", text);
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!(f.rule_id, "t/a");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.message, "T t/a");
        assert_eq!(f.path, "docs/x.md");
        assert_eq!((f.start.line, f.start.column), (2, 6));
        assert_eq!((f.end.line, f.end.column), (2, 12));
        assert_eq!(f.snippet, "some needle here");
        assert_eq!(
            f.fingerprint,
            report::fingerprint("t/a", "docs/x.md", "some needle here")
        );
        assert_eq!(&text[f.byte_range.clone()], "needle");
        // Not applicable to other paths.
        assert!(s.scan_text("x.txt", text).is_empty());
    }

    #[test]
    fn findings_are_ordered_and_capped() {
        let s = Scanner::new(vec![
            regex_rule("t/b", "x", "*.md"),
            regex_rule("t/a", "x", "*.md"),
        ])
        .unwrap();
        let f = s.scan_text("a.md", "x");
        assert_eq!(
            f.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["t/a", "t/b"]
        );
        let many = "x ".repeat(MAX_FINDINGS_PER_RULE + 10);
        let scan = s.scan_text_full("a.md", &many);
        assert_eq!(scan.findings.len(), 2 * MAX_FINDINGS_PER_RULE);
        assert_eq!(scan.errors.len(), 2);
        assert!(scan.errors[0].contains("only the first"));
    }

    #[test]
    fn duplicate_rule_ids_are_refused() {
        let e = Scanner::new(vec![
            regex_rule("t/a", "x", "*.md"),
            regex_rule("t/a", "y", "*.md"),
        ])
        .unwrap_err();
        assert!(e.to_string().contains("duplicate"));
    }

    #[test]
    fn parse_errors_are_recorded_once_per_file() {
        let mk = |id: &str| {
            rule(&format!(
                "id: {id}\nseverity: high\ntitle: J\ndescription: d\napplies_to: ['*.json']\n\
                 detect:\n  json_path: {{path: $.a, predicate: {{exists: true}}}}\nremediation: r\n\
                 examples:\n  match: ['{{\"a\": 1}}']\n  nomatch: ['{{}}']\n"
            ))
        };
        let s = Scanner::new(vec![mk("t/one"), mk("t/two")]).unwrap();
        let scan = s.scan_text_full("x.json", "{\"a\": ");
        assert!(scan.findings.is_empty());
        assert_eq!(scan.errors.len(), 1, "{:?}", scan.errors);
        assert!(scan.errors[0].starts_with("JSON parse error"));
        let scan = s.scan_text_full("x.json", "{\"a\": 1}");
        assert_eq!(scan.findings.len(), 2);
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn examples_are_run_and_failures_explained() {
        let good = rule(crate::rule::tests::GOOD);
        assert!(run_examples(&good).is_empty(), "{:?}", run_examples(&good));
        let bad = rule(
            &crate::rule::tests::GOOD
                .replace("    - \"hello\"\n", "    - \"ignore previous, sadly\"\n")
                .replace("path: .cursorrules", "path: notes.txt"),
        );
        let failures = run_examples(&bad);
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert_eq!(failures[0].kind, ExampleKind::Match);
        assert!(
            failures[0].reason.contains("not selected"),
            "{}",
            failures[0]
        );
        assert_eq!(failures[1].kind, ExampleKind::NoMatch);
        assert!(failures[1].to_string().contains("examples.nomatch[0]"));
        assert!(failures[1].reason.contains("expected no finding, got 1"));
    }

    #[test]
    fn scan_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("docs")).unwrap();
        fs::write(tmp.path().join("docs/a.md"), "a needle\n").unwrap();
        fs::write(tmp.path().join("b.md"), "nothing\n").unwrap();
        fs::write(tmp.path().join("c.md"), b"bin\0ary").unwrap();
        let s = Scanner::new(vec![regex_rule("t/a", "needle", "**/*.md")]).unwrap();
        let report = s.scan(tmp.path()).unwrap();
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, "docs/a.md");
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, SkipReason::Binary);
        assert!(report.fails_at(Severity::Medium));
        assert!(!report.fails_at(Severity::High));
        let e = s.scan(&tmp.path().join("missing")).unwrap_err();
        assert!(e.to_string().contains("cannot read scan root"));
    }

    fn path_rule(id: &str, key: &str, glob: &str) -> Rule {
        rule(&format!(
            "id: {id}\nseverity: high\ntitle: P\ndescription: d\napplies_to: ['{glob}']\n\
             detect:\n  {key}: {{path: $.mode, predicate: {{equals: danger}}}}\nremediation: r\n\
             examples:\n  match: ['x']\n  nomatch: ['y']\n"
        ))
    }

    #[test]
    fn columns_in_scalar_values_count_characters() {
        let s = Scanner::new(vec![
            path_rule("t/json", "json_path", "*.json"),
            path_rule("t/yaml", "yaml_path", "*.yml"),
            path_rule("t/toml", "toml_path", "*.toml"),
        ])
        .unwrap();
        let cases = [
            (
                "a.json",
                "{\"n\u{e9}v\": \"\u{fc}n\u{ef}c\u{f6}d\u{e9} \u{1F600}\", \"mode\": \"danger\"}",
                "\"danger\"",
            ),
            (
                "a.yml",
                "title: \"\u{dc}n\u{ef}code \u{1F600}\"\r\nmode:   'danger'   # \u{f6}k\r\n",
                "'danger'",
            ),
            (
                "a.toml",
                "\u{feff}name = \"\u{1F600}\u{1F600}\"\nmode = \"danger\"\n",
                "\"danger\"",
            ),
        ];
        for (path, text, needle) in cases {
            let f = s.scan_text(path, text);
            assert_eq!(f.len(), 1, "{path}: {f:?}");
            let at = text.find(needle).unwrap();
            assert_eq!(&text[f[0].byte_range.clone()], needle, "{path}");
            let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
            let line_start = if line_start == 0 && text.starts_with('\u{feff}') {
                3
            } else {
                line_start
            };
            let column = text[line_start..at].chars().count() + 1;
            assert_eq!(f[0].start.column, column, "{path}");
            assert_eq!(f[0].end.column, column + needle.chars().count(), "{path}");
            assert_eq!(
                f[0].start.line,
                text[..at].matches('\n').count() + 1,
                "{path}"
            );
        }
        // The JSON case really has multi-byte characters before the value.
        let json = cases[0].1;
        assert!(json.find("\"danger\"").unwrap() + 1 > s.scan_text("a.json", json)[0].start.column);
    }

    #[test]
    fn hostile_messages_are_escaped() {
        let r = rule(
            "id: t/u\nseverity: low\ntitle: U\ndescription: d\napplies_to: ['*.md']\n\
             detect:\n  unicode: {classes: [tag]}\nremediation: r\n\
             examples:\n  match: [\"\\U000E0041\"]\n  nomatch: ['a']\n",
        );
        let s = Scanner::new(vec![r]).unwrap();
        // Tag text that decodes to an ANSI-looking sequence stays inert.
        let hidden: String = "x\u{1b}[31m"
            .chars()
            .map(|c| char::from_u32(u32::from(c) + 0xE0000).unwrap_or(c))
            .collect();
        let f = s.scan_text("a.md", &format!("hi{hidden}"));
        assert_eq!(f.len(), 1);
        assert!(
            !f[0].message.chars().any(char::is_control),
            "{}",
            f[0].message
        );
        assert!(!f[0].snippet.chars().any(|c| c.is_control() && c != '\t'));
    }
}
