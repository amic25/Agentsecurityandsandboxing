//! Detectors: the `detect:` block of a rule.
//!
//! A rule names exactly one primary kind (`regex`, `unicode`, `json_path`,
//! `yaml_path`, `toml_path`, `markdown_image_url`, `shell_pattern`,
//! `builtin`). `detect` is a struct of optional fields plus a validation
//! step rather than an enum, so modifiers such as `unless` compose with more
//! than one kind without a combinatorial schema.
//!
//! Every detector returns byte ranges into the file text. The engine turns
//! them into positions, snippets and findings.

pub(crate) mod builtin;
pub(crate) mod markdown;
pub(crate) mod regex;
pub(crate) mod shell;
pub(crate) mod structured;
pub(crate) mod unicode;

use std::cell::OnceCell;
use std::ops::Range;

use serde::Deserialize;
use serde_json::Value;

use crate::text::LineIndex;

/// One match of a detector in one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Match {
    /// Byte range into the file text, on char boundaries.
    pub(crate) range: Range<usize>,
    /// What this match is, appended to the rule title in the message.
    pub(crate) detail: Option<String>,
}

impl Match {
    pub(crate) fn new(range: Range<usize>) -> Self {
        Self {
            range,
            detail: None,
        }
    }

    pub(crate) fn with_detail(range: Range<usize>, detail: impl Into<String>) -> Self {
        Self {
            range,
            detail: Some(detail.into()),
        }
    }
}

/// A file as the detectors see it: its path, its text and lazily built
/// views (line index, parsed JSON/YAML/TOML) shared by every rule that runs
/// on it, so ten structured rules parse a file once.
pub(crate) struct Input<'a> {
    pub(crate) path: &'a str,
    pub(crate) text: &'a str,
    lines: OnceCell<LineIndex>,
    json: OnceCell<Result<Value, String>>,
    yaml: OnceCell<Result<Vec<Value>, String>>,
    toml: OnceCell<Result<Value, String>>,
}

impl<'a> Input<'a> {
    pub(crate) fn new(path: &'a str, text: &'a str) -> Self {
        Self {
            path,
            text,
            lines: OnceCell::new(),
            json: OnceCell::new(),
            yaml: OnceCell::new(),
            toml: OnceCell::new(),
        }
    }

    pub(crate) fn lines(&self) -> &LineIndex {
        self.lines.get_or_init(|| LineIndex::new(self.text))
    }

    /// The file parsed as JSON (comments and trailing commas tolerated).
    pub(crate) fn json(&self) -> Result<&Value, &str> {
        self.json
            .get_or_init(|| structured::parse_json(self.text))
            .as_ref()
            .map_err(String::as_str)
    }

    /// The file parsed as a YAML stream, one value per document.
    pub(crate) fn yaml(&self) -> Result<&[Value], &str> {
        self.yaml
            .get_or_init(|| structured::parse_yaml(self.text))
            .as_ref()
            .map(Vec::as_slice)
            .map_err(String::as_str)
    }

    /// The file parsed as TOML.
    pub(crate) fn toml(&self) -> Result<&Value, &str> {
        self.toml
            .get_or_init(|| structured::parse_toml(self.text))
            .as_ref()
            .map_err(String::as_str)
    }

    /// Parse errors from every format some rule asked for, once each.
    pub(crate) fn parse_errors(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(Err(e)) = self.json.get() {
            out.push(format!("JSON parse error: {e}"));
        }
        if let Some(Err(e)) = self.yaml.get() {
            out.push(format!("YAML parse error: {e}"));
        }
        if let Some(Err(e)) = self.toml.get() {
            out.push(format!("TOML parse error: {e}"));
        }
        out
    }
}

/// The `detect:` block as written in a rule file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DetectSpec {
    regex: Option<String>,
    multiline: Option<bool>,
    unless: Option<String>,
    unicode: Option<unicode::UnicodeSpec>,
    json_path: Option<structured::PathSpec>,
    yaml_path: Option<structured::PathSpec>,
    toml_path: Option<structured::PathSpec>,
    markdown_image_url: Option<markdown::MarkdownImageSpec>,
    shell_pattern: Option<shell::ShellSpec>,
    builtin: Option<String>,
    options: Option<Value>,
}

/// A compiled detector.
#[derive(Debug)]
pub(crate) struct Detector {
    kind: Kind,
    unless: Option<::regex::Regex>,
}

#[derive(Debug)]
enum Kind {
    Regex(::regex::Regex),
    Unicode(unicode::UnicodeDetector),
    Structured(structured::StructuredDetector),
    MarkdownImage(markdown::MarkdownImageDetector),
    Shell(shell::ShellDetector),
    Builtin(Box<dyn builtin::BuiltinDetector>),
}

impl DetectSpec {
    /// Validate and compile. Errors are human-readable reasons; the rule
    /// loader adds the file name.
    pub(crate) fn compile(self) -> Result<Detector, String> {
        let primary: Vec<&str> = [
            ("regex", self.regex.is_some()),
            ("unicode", self.unicode.is_some()),
            ("json_path", self.json_path.is_some()),
            ("yaml_path", self.yaml_path.is_some()),
            ("toml_path", self.toml_path.is_some()),
            ("markdown_image_url", self.markdown_image_url.is_some()),
            ("shell_pattern", self.shell_pattern.is_some()),
            ("builtin", self.builtin.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
        .collect();
        match primary.as_slice() {
            [] => {
                return Err(
                    "detect: needs exactly one of regex, unicode, json_path, yaml_path, \
                            toml_path, markdown_image_url, shell_pattern, builtin"
                        .into(),
                )
            }
            [_] => {}
            many => {
                return Err(format!(
                    "detect: has more than one detector ({}); use exactly one",
                    many.join(", ")
                ))
            }
        }
        if self.multiline.is_some() && self.regex.is_none() {
            return Err("detect.multiline only applies to regex".into());
        }
        if self.unless.is_some() && self.regex.is_none() && self.shell_pattern.is_none() {
            return Err("detect.unless only applies to regex and shell_pattern".into());
        }
        if self.options.is_some() && self.builtin.is_none() {
            return Err("detect.options only applies to builtin".into());
        }
        let unless = self
            .unless
            .as_deref()
            .map(|p| regex::compile(p, true).map_err(|e| format!("detect.unless: {e}")))
            .transpose()?;

        let kind = if let Some(pattern) = self.regex {
            let multiline = self.multiline.unwrap_or(true);
            Kind::Regex(
                regex::compile(&pattern, multiline).map_err(|e| format!("detect.regex: {e}"))?,
            )
        } else if let Some(spec) = self.unicode {
            Kind::Unicode(spec.compile()?)
        } else if let Some(spec) = self.json_path {
            Kind::Structured(spec.compile(structured::Format::Json)?)
        } else if let Some(spec) = self.yaml_path {
            Kind::Structured(spec.compile(structured::Format::Yaml)?)
        } else if let Some(spec) = self.toml_path {
            Kind::Structured(spec.compile(structured::Format::Toml)?)
        } else if let Some(spec) = self.markdown_image_url {
            Kind::MarkdownImage(spec.compile()?)
        } else if let Some(spec) = self.shell_pattern {
            Kind::Shell(spec.compile()?)
        } else if let Some(name) = self.builtin {
            Kind::Builtin(builtin::compile(&name, self.options.as_ref())?)
        } else {
            // The count check above makes this unreachable; failing closed
            // with an error keeps it panic-free.
            return Err("detect: no detector".into());
        };
        Ok(Detector { kind, unless })
    }
}

impl Detector {
    /// Run on one file.
    pub(crate) fn detect(&self, input: &Input<'_>) -> Vec<Match> {
        let mut matches = match &self.kind {
            Kind::Regex(re) => regex::detect(re, input.text),
            Kind::Unicode(d) => d.detect(input.text),
            Kind::Structured(d) => d.detect(input),
            Kind::MarkdownImage(d) => d.detect(input.text),
            Kind::Shell(d) => d.detect(input.text),
            Kind::Builtin(d) => d.detect(input),
        };
        if let Some(unless) = &self.unless {
            let lines = input.lines();
            matches.retain(|m| {
                let first = lines.line_of(m.range.start);
                let last = lines.line_of(m.range.end.saturating_sub(1).max(m.range.start));
                let from = lines.line_start(first);
                let to = lines.line_end(input.text, last.max(first)).max(from);
                !input.text.get(from..to).is_some_and(|l| unless.is_match(l))
            });
        }
        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(yaml: &str) -> Result<Detector, String> {
        let spec: DetectSpec = serde_saphyr::from_str(yaml).map_err(|e| e.to_string())?;
        spec.compile()
    }

    #[test]
    fn exactly_one_primary_kind() {
        assert!(spec("regex: 'a'").is_ok());
        let none = spec("multiline: true").unwrap_err();
        assert!(none.contains("multiline only applies") || none.contains("exactly one"));
        let e = spec("{}").unwrap_err();
        assert!(e.contains("exactly one"), "{e}");
        let e = spec("regex: a\nbuiltin: x").unwrap_err();
        assert!(e.contains("more than one"), "{e}");
    }

    #[test]
    fn modifiers_must_fit_the_kind() {
        let e = spec("unicode: {classes: [bidi]}\nunless: x").unwrap_err();
        assert!(e.contains("unless only applies"), "{e}");
        let e = spec("unicode: {classes: [bidi]}\nmultiline: false").unwrap_err();
        assert!(e.contains("multiline only applies"), "{e}");
        let e = spec("regex: a\noptions: {a: 1}").unwrap_err();
        assert!(e.contains("options only applies"), "{e}");
        assert!(spec("shell_pattern: {from: [curl], to: [sh]}\nunless: sha256sum").is_ok());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(spec("regexp: a").is_err());
    }

    #[test]
    fn bad_regexes_are_errors() {
        let e = spec("regex: '('").unwrap_err();
        assert!(e.contains("detect.regex"), "{e}");
        let e = spec("regex: a\nunless: '['").unwrap_err();
        assert!(e.contains("detect.unless"), "{e}");
    }

    #[test]
    fn unless_suppresses_on_the_same_line() {
        let d = spec("regex: 'curl'\nunless: 'sha256sum'").unwrap();
        let text = "curl x | sha256sum -c\ncurl y\n";
        let m = d.detect(&Input::new("a.sh", text));
        assert_eq!(m.len(), 1);
        assert_eq!(&text[m[0].range.clone()], "curl");
        assert_eq!(m[0].range.start, text.find("curl y").unwrap());
    }

    #[test]
    fn unknown_builtin_is_an_error() {
        let e = spec("builtin: no_such_builtin").unwrap_err();
        assert!(e.contains("unknown builtin"), "{e}");
    }
}
