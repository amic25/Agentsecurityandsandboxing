//! Report renderers: human text, the versioned JSON schema and SARIF 2.1.0.
//!
//! Every renderer returns the whole document as a `String`, so the caller
//! decides where it goes (stdout or `--output FILE`) and a write error never
//! leaves half a JSON document behind without the caller knowing.
//!
//! Finding text (snippets, messages) is escaped by the engine. Paths come
//! from the file system and may contain anything a file name can, so the
//! text renderer escapes them itself; JSON and SARIF rely on the JSON
//! encoder, which escapes every control character.

pub mod json;
pub mod sarif;
pub mod text;

use crate::report::Report;
use crate::rule::Rule;

/// The output formats `agentkeep scan --format` offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Grouped, human-readable text with snippets.
    Text,
    /// `agentkeep.scan/1` JSON.
    Json,
    /// SARIF 2.1.0 for GitHub code scanning.
    Sarif,
}

/// A report that could not be rendered. In practice only serialisation can
/// fail, and only on a bug, but the CLI must not panic on one.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// The JSON encoder refused the document.
    #[error("cannot encode the report as {format}: {source}")]
    Encode {
        /// `json` or `sarif`.
        format: &'static str,
        /// The encoder error.
        #[source]
        source: serde_json::Error,
    },
}

/// Render `report` in `format`. `rules` are the rules the scan ran with:
/// SARIF lists them all as `tool.driver.rules`, and the text format prints
/// each rule's remediation once. `colour` only affects [`Format::Text`].
pub fn render(
    report: &Report,
    rules: &[Rule],
    format: Format,
    colour: bool,
) -> Result<String, OutputError> {
    match format {
        Format::Text => Ok(text::render(report, rules, colour)),
        Format::Json => json::render(report),
        Format::Sarif => sarif::render(report, rules),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::engine::Scanner;
    use crate::report::{FileError, SkipReason, Skipped};

    /// A rule set and a report with findings of three severities, a skip, an
    /// error and a hostile file name.
    pub(crate) fn sample() -> (Vec<Rule>, Report) {
        let mk = |id: &str, sev: &str, pattern: &str, glob: &str| {
            Rule::from_yaml(
                &format!(
                    "id: {id}\nseverity: {sev}\ntitle: Title of {id}\ndescription: Why {id} matters.\n\
                     applies_to: ['{glob}']\ndetect:\n  regex: '{pattern}'\nremediation: Fix {id}.\n\
                     references: ['https://example.com/{id}']\ntags: [sample, {sev}]\n\
                     examples:\n  match: ['{pattern}']\n  nomatch: ['zzz']\n"
                ),
                "t.yaml",
                None,
            )
            .unwrap()
        };
        let rules = || {
            vec![
                mk("t/high", "high", "needle", "*.md"),
                mk("t/info", "info", "pin", "*.md"),
                mk("t/crit", "critical", "danger", "*"),
            ]
        };
        let scanner = Scanner::new(rules()).unwrap();
        let mut findings = scanner.scan_text("docs/a.md", "a needle\nand a pin\n");
        findings.extend(scanner.scan_text("we\u{1b}[31mird name.txt", "danger \u{202E}x\n"));
        let report = Report {
            root: "repo".into(),
            root_dir: std::path::PathBuf::from("/srv/repo"),
            findings,
            skipped: vec![Skipped {
                path: "node_modules".into(),
                reason: SkipReason::ExcludedDir,
            }],
            errors: vec![FileError {
                path: "bad.json".into(),
                message: "JSON parse error at line 1".into(),
            }],
            files_scanned: 4,
            truncated: false,
        };
        (rules(), report)
    }

    #[test]
    fn render_dispatches_on_format() {
        let (rules, report) = sample();
        let text = render(&report, &rules, Format::Text, false).unwrap();
        assert!(text.contains("docs/a.md:1:3"), "{text}");
        let json = render(&report, &rules, Format::Json, true).unwrap();
        assert!(json.starts_with("{\n  \"schema\": \"agentkeep.scan/1\""));
        let sarif = render(&report, &rules, Format::Sarif, true).unwrap();
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        // Colour never leaks into machine formats.
        assert!(!json.contains('\u{1b}') && !sarif.contains('\u{1b}'));
    }
}
