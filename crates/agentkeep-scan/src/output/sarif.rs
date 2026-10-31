//! SARIF 2.1.0 for GitHub code scanning and other SARIF consumers.
//!
//! One run. `tool.driver.rules` lists every rule the scan ran with, in load
//! order, so `ruleIndex` is stable for a given rule set. Each result has one
//! location whose `artifactLocation.uri` is the path relative to the scan
//! root (percent-encoded, `/`-separated) with `uriBaseId: "%SRCROOT%"`;
//! `originalUriBaseIds` resolves `%SRCROOT%` to the scan root as an absolute
//! `file://` URI. `partialFingerprints["agentkeep/v1"]` carries the finding's
//! fingerprint, which ignores line numbers, so code scanning de-duplicates
//! alerts across runs when lines move.
//!
//! Columns count Unicode scalar values, so the run declares `columnKind:
//! "unicodeCodePoints"` (SARIF's default is UTF-16 code units). Snippets are
//! the escaped text shown in every other format, not raw file bytes: a raw
//! snippet could carry the very control characters being reported.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use super::OutputError;
use crate::report::{Finding, Report, Severity};
use crate::rule::Rule;

/// The `$schema` written into every SARIF document.
pub const SCHEMA_URI: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// `tool.driver.informationUri`.
pub const INFORMATION_URI: &str = "https://github.com/amic25/Agentsecurityandsandboxing";

/// The key of the fingerprint in `partialFingerprints`. Bump the version if
/// the fingerprint formula ever changes, so old and new alerts do not merge.
pub const FINGERPRINT_KEY: &str = "agentkeep/v1";

const SRCROOT: &str = "%SRCROOT%";

#[derive(Serialize)]
struct Log<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run<'a>; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Run<'a> {
    tool: Tool<'a>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    original_uri_base_ids: BTreeMap<&'static str, BaseUri>,
    column_kind: &'static str,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver<'a> {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    rules: Vec<Descriptor<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor<'a> {
    id: &'a str,
    name: String,
    short_description: Text<'a>,
    full_description: Text<'a>,
    help: Help,
    default_configuration: Configuration,
    properties: Properties<'a>,
}

#[derive(Serialize)]
struct Text<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct Help {
    text: String,
    markdown: String,
}

#[derive(Serialize)]
struct Configuration {
    level: &'static str,
}

#[derive(Serialize)]
struct Properties<'a> {
    tags: &'a [String],
    precision: &'static str,
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
}

#[derive(Serialize)]
struct BaseUri {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult<'a> {
    rule_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    level: &'static str,
    message: Text<'a>,
    locations: [Location<'a>; 1],
    partial_fingerprints: BTreeMap<&'static str, &'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Location<'a> {
    physical_location: PhysicalLocation<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation<'a> {
    artifact_location: ArtifactLocation,
    region: Region<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
    uri_base_id: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region<'a> {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
    snippet: Text<'a>,
}

/// SARIF `level` for a severity: critical and high are errors, medium a
/// warning, low and info notes.
pub fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// GitHub's `security-severity` score for a severity (a decimal string; 9.0
/// and above is shown as critical, 7.0 high, 4.0 medium, above 0 low).
pub fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

/// Render `report` as a SARIF 2.1.0 log, pretty-printed with a trailing
/// newline. `rules` are the rules the scan ran with.
pub fn render(report: &Report, rules: &[Rule]) -> Result<String, OutputError> {
    let index: BTreeMap<&str, usize> = rules.iter().enumerate().map(|(i, r)| (r.id(), i)).collect();
    let mut base_ids = BTreeMap::new();
    if let Some(uri) = root_uri(&report.root_dir) {
        base_ids.insert(SRCROOT, BaseUri { uri });
    }
    let log = Log {
        schema: SCHEMA_URI,
        version: "2.1.0",
        runs: [Run {
            tool: Tool {
                driver: Driver {
                    name: "agentkeep",
                    version: crate::VERSION,
                    information_uri: INFORMATION_URI,
                    rules: rules.iter().map(descriptor).collect(),
                },
            },
            original_uri_base_ids: base_ids,
            column_kind: "unicodeCodePoints",
            results: report
                .findings
                .iter()
                .map(|f| result(f, index.get(f.rule_id.as_str()).copied()))
                .collect(),
        }],
    };
    let mut out = serde_json::to_string_pretty(&log).map_err(|source| OutputError::Encode {
        format: "sarif",
        source,
    })?;
    out.push('\n');
    Ok(out)
}

fn descriptor(rule: &Rule) -> Descriptor<'_> {
    Descriptor {
        id: rule.id(),
        name: pascal_name(rule.id()),
        short_description: Text { text: rule.title() },
        full_description: Text {
            text: rule.description(),
        },
        help: Help {
            text: help_text(rule),
            markdown: help_markdown(rule),
        },
        default_configuration: Configuration {
            level: level(rule.severity()),
        },
        properties: Properties {
            tags: rule.tags(),
            precision: "medium",
            security_severity: security_severity(rule.severity()),
        },
    }
}

fn result(f: &Finding, rule_index: Option<usize>) -> SarifResult<'_> {
    let mut fingerprints = BTreeMap::new();
    fingerprints.insert(FINGERPRINT_KEY, f.fingerprint.as_str());
    SarifResult {
        rule_id: &f.rule_id,
        rule_index,
        level: level(f.severity),
        message: Text { text: &f.message },
        locations: [Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: encode_path(&f.path),
                    uri_base_id: SRCROOT,
                },
                region: Region {
                    start_line: f.start.line,
                    start_column: f.start.column,
                    end_line: f.end.line,
                    end_column: f.end.column,
                    snippet: Text { text: &f.snippet },
                },
            },
        }],
        partial_fingerprints: fingerprints,
    }
}

/// `exfiltration/markdown-image-beacon` -> `MarkdownImageBeacon`: SARIF
/// wants a readable identifier without the category path.
fn pascal_name(id: &str) -> String {
    let slug = id.rsplit('/').next().unwrap_or(id);
    let mut out = String::with_capacity(slug.len());
    for word in slug.split(|c: char| !c.is_ascii_alphanumeric()) {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    out
}

fn help_text(rule: &Rule) -> String {
    let mut out = format!(
        "{}\n\nRemediation: {}",
        rule.description(),
        rule.remediation()
    );
    if !rule.references().is_empty() {
        out.push_str("\n\nReferences:");
        for r in rule.references() {
            let _ = write!(out, "\n- {r}");
        }
    }
    out
}

fn help_markdown(rule: &Rule) -> String {
    let mut out = format!(
        "{}\n\n**Remediation:** {}",
        rule.description(),
        rule.remediation()
    );
    if !rule.references().is_empty() {
        out.push_str("\n\n**References:**\n");
        for r in rule.references() {
            let _ = write!(out, "\n- <{r}>");
        }
    }
    let _ = write!(
        out,
        "\n\nRule `{}`, severity {}.",
        rule.id(),
        rule.severity()
    );
    out
}

/// Percent-encode a relative path for a URI reference: everything except
/// RFC 3986 unreserved characters and `/` is encoded, byte by byte.
fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The scan root as an absolute `file://` URI ending in `/`, or `None` when
/// it cannot be made absolute or is not valid UTF-8 (the base is then left
/// for the consumer to supply, which GitHub does from the checkout).
fn root_uri(root_dir: &Path) -> Option<String> {
    if root_dir.as_os_str().is_empty() {
        return None;
    }
    let abs = std::path::absolute(root_dir).ok()?;
    let s = abs.to_str()?;
    // Windows paths become /C:/x; `\` separators become `/`.
    let s = s.replace('\\', "/");
    let s = if s.starts_with('/') {
        s
    } else {
        format!("/{s}")
    };
    let mut uri = String::from("file://");
    uri.push_str(&encode_path(&s).replace("%3A", ":"));
    if !uri.ends_with('/') {
        uri.push('/');
    }
    Some(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests::sample;
    use serde_json::Value;

    fn sarif() -> (Vec<Rule>, Report, Value, String) {
        let (rules, report) = sample();
        let out = render(&report, &rules).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        (rules, report, v, out)
    }

    #[test]
    fn top_level_and_driver() {
        let (rules, _report, v, out) = sarif();
        assert!(out.ends_with("}\n"));
        assert_eq!(v["$schema"], SCHEMA_URI);
        assert_eq!(v["version"], "2.1.0");
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        assert_eq!(run["columnKind"], "unicodeCodePoints");
        let srcroot = run["originalUriBaseIds"]["%SRCROOT%"]["uri"]
            .as_str()
            .unwrap();
        // On Windows `/srv/repo` gains the current drive: file:///C:/srv/repo/.
        if cfg!(windows) {
            assert!(
                srcroot.starts_with("file:///") && srcroot.ends_with(":/srv/repo/"),
                "{srcroot}"
            );
        } else {
            assert_eq!(srcroot, "file:///srv/repo/");
        }
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "agentkeep");
        assert_eq!(driver["version"], crate::VERSION);
        assert_eq!(driver["informationUri"], INFORMATION_URI);
        let descs = driver["rules"].as_array().unwrap();
        assert_eq!(descs.len(), rules.len());
        let high = &descs[0];
        assert_eq!(high["id"], "t/high");
        assert_eq!(high["name"], "High");
        assert_eq!(high["shortDescription"]["text"], "Title of t/high");
        assert_eq!(high["fullDescription"]["text"], "Why t/high matters.");
        let help = high["help"]["text"].as_str().unwrap();
        assert!(help.contains("Remediation: Fix t/high."), "{help}");
        assert!(help.contains("https://example.com/t/high"));
        let md = high["help"]["markdown"].as_str().unwrap();
        assert!(md.contains("**Remediation:** Fix t/high."), "{md}");
        assert_eq!(high["defaultConfiguration"]["level"], "error");
        assert_eq!(
            high["properties"]["tags"],
            serde_json::json!(["sample", "high"])
        );
        assert_eq!(high["properties"]["precision"], "medium");
        assert_eq!(high["properties"]["security-severity"], "8.0");
        assert_eq!(descs[1]["defaultConfiguration"]["level"], "note");
        assert_eq!(descs[1]["properties"]["security-severity"], "1.0");
        assert_eq!(descs[2]["properties"]["security-severity"], "9.5");
    }

    #[test]
    fn results_point_at_rules_and_regions() {
        let (_rules, report, v, _out) = sarif();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), report.findings.len());
        let descs = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        for (r, f) in results.iter().zip(&report.findings) {
            let idx = usize::try_from(r["ruleIndex"].as_u64().unwrap()).unwrap();
            assert_eq!(descs[idx]["id"], r["ruleId"]);
            assert_eq!(r["ruleId"], f.rule_id.as_str());
            assert_eq!(r["message"]["text"], f.message.as_str());
            assert_eq!(
                r["partialFingerprints"][FINGERPRINT_KEY],
                f.fingerprint.as_str()
            );
            let loc = &r["locations"][0]["physicalLocation"];
            assert_eq!(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%");
            assert_eq!(loc["region"]["startLine"], f.start.line);
            assert_eq!(loc["region"]["startColumn"], f.start.column);
            assert_eq!(loc["region"]["endLine"], f.end.line);
            assert_eq!(loc["region"]["endColumn"], f.end.column);
            assert_eq!(loc["region"]["snippet"]["text"], f.snippet.as_str());
        }
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
        let uri = &results[2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert_eq!(uri, "we%1B%5B31mird%20name.txt");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "docs/a.md"
        );
    }

    #[test]
    fn levels_and_scores_cover_every_severity() {
        let want = [
            (Severity::Critical, "error", "9.5"),
            (Severity::High, "error", "8.0"),
            (Severity::Medium, "warning", "5.5"),
            (Severity::Low, "note", "3.0"),
            (Severity::Info, "note", "1.0"),
        ];
        for (sev, lvl, score) in want {
            assert_eq!(level(sev), lvl);
            assert_eq!(security_severity(sev), score);
        }
    }

    #[test]
    fn names_and_uris() {
        assert_eq!(
            pascal_name("exfiltration/markdown-image-beacon"),
            "MarkdownImageBeacon"
        );
        assert_eq!(pascal_name("a/b_c-9d"), "BC9d");
        assert_eq!(encode_path("a b/ü?#%.md"), "a%20b/%C3%BC%3F%23%25.md");
        assert_eq!(root_uri(Path::new("")), None);
        let rel = root_uri(Path::new("some dir")).unwrap();
        assert!(
            rel.starts_with("file:///") && rel.ends_with("/some%20dir/"),
            "{rel}"
        );
    }

    #[test]
    fn a_finding_of_an_unknown_rule_has_no_index() {
        let (_rules, report) = sample();
        let out = render(&report, &[]).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let r = &v["runs"][0]["results"][0];
        assert!(r.get("ruleIndex").is_none());
        assert_eq!(r["ruleId"], "t/high");
    }
}
