//! The `agentkeep.scan/1` JSON report.
//!
//! ```text
//! {"schema": "agentkeep.scan/1",
//!  "tool": {"name", "version"},
//!  "root",
//!  "findings": [{rule_id, severity, title, message, path,
//!                start: {line, column}, end: {line, column},
//!                snippet, fingerprint}],
//!  "skipped": [{path, reason}],
//!  "errors": [{path, message}],
//!  "summary": {files_scanned, findings,
//!              by_severity: {critical, high, medium, low, info}}}
//! ```
//!
//! Every object is a struct, so keys come out in the order above on every
//! run. Lines and columns are 1-based, columns count Unicode scalar values
//! and `end` is exclusive. Adding a key is a compatible change; renaming or
//! removing one bumps the schema to `agentkeep.scan/2`.

use serde::Serialize;

use super::OutputError;
use crate::report::{FileError, Finding, Report, Skipped, Summary};

/// The schema identifier written into every JSON report.
pub const SCHEMA: &str = "agentkeep.scan/1";

#[derive(Serialize)]
struct Document<'a> {
    schema: &'static str,
    tool: Tool,
    root: &'a str,
    findings: &'a [Finding],
    skipped: &'a [Skipped],
    errors: &'a [FileError],
    summary: Summary,
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

/// Render `report` as pretty-printed `agentkeep.scan/1` JSON with a trailing
/// newline.
pub fn render(report: &Report) -> Result<String, OutputError> {
    let doc = Document {
        schema: SCHEMA,
        tool: Tool {
            name: "agentkeep",
            version: crate::VERSION,
        },
        root: &report.root,
        findings: &report.findings,
        skipped: &report.skipped,
        errors: &report.errors,
        summary: report.summary(),
    };
    let mut out = serde_json::to_string_pretty(&doc).map_err(|source| OutputError::Encode {
        format: "json",
        source,
    })?;
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample;

    /// Byte offset of `"key"` in `s`, for key-order checks.
    fn at(s: &str, key: &str) -> usize {
        s.find(&format!("\"{key}\""))
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    #[test]
    fn keys_come_out_in_schema_order() {
        let (_rules, report) = sample();
        let out = render(&report).unwrap();
        assert!(out.ends_with("}\n"));
        let top = [
            "schema", "tool", "root", "findings", "skipped", "errors", "summary",
        ];
        for pair in top.windows(2) {
            assert!(at(&out, pair[0]) < at(&out, pair[1]), "{pair:?}\n{out}");
        }
        let finding = [
            "rule_id",
            "severity",
            "title",
            "message",
            "path",
            "start",
            "end",
            "snippet",
            "fingerprint",
        ];
        for pair in finding.windows(2) {
            assert!(at(&out, pair[0]) < at(&out, pair[1]), "{pair:?}");
        }
        for pair in [
            "files_scanned",
            "by_severity",
            "critical",
            "high",
            "medium",
            "low",
            "info",
        ]
        .windows(2)
        {
            let summary = &out[at(&out, "summary")..];
            assert!(at(summary, pair[0]) < at(summary, pair[1]), "{pair:?}");
        }
        // Byte ranges are internal and never serialised.
        assert!(!out.contains("byte_range"));
        assert!(!out.contains("root_dir"));
    }

    #[test]
    fn values_round_trip() {
        let (_rules, report) = sample();
        let out = render(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["tool"]["name"], "agentkeep");
        assert_eq!(v["tool"]["version"], crate::VERSION);
        assert_eq!(v["root"], "repo");
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), report.findings.len());
        let first = &findings[0];
        assert_eq!(first["rule_id"], "t/high");
        assert_eq!(first["severity"], "high");
        assert_eq!(first["path"], "docs/a.md");
        assert_eq!(first["start"]["line"], 1);
        assert_eq!(first["start"]["column"], 3);
        assert_eq!(first["end"]["column"], 9);
        assert_eq!(first["fingerprint"], report.findings[0].fingerprint);
        assert_eq!(v["skipped"][0]["reason"], "excluded-dir");
        assert_eq!(v["errors"][0]["path"], "bad.json");
        assert_eq!(v["summary"]["files_scanned"], 4);
        assert_eq!(v["summary"]["findings"], 3);
        assert_eq!(v["summary"]["by_severity"]["critical"], 1);
        assert_eq!(v["summary"]["by_severity"]["info"], 1);
        // A hostile path is data: the encoder escapes the control character.
        assert!(out.contains("we\\u001b[31mird name.txt"), "{out}");
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn an_empty_report_is_complete() {
        let out = render(&Report::default()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["findings"], serde_json::json!([]));
        assert_eq!(v["summary"]["findings"], 0);
        assert_eq!(v["summary"]["by_severity"]["high"], 0);
    }
}
