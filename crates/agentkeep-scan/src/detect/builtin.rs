//! `detect.builtin`: detectors written in Rust because YAML cannot express
//! them (bidi analysis, base64-decoded commands, CI workflow analysis,
//! agentkeep policy loosening).
//!
//! A builtin is a name plus a constructor that validates `detect.options`
//! and returns a [`BuiltinDetector`]. To add one, implement the trait in its
//! own module under `detect/` and add an entry to [`BUILTINS`]; rule files
//! then refer to it by name. Each builtin carries its own unit tests.

use std::fmt;

use serde_json::Value;

use super::{Input, Match};

/// A detector implemented in Rust.
pub(crate) trait BuiltinDetector: fmt::Debug + Send + Sync {
    /// Run on one file. Parsed views (`input.yaml()`, `input.toml()`, ...)
    /// are shared with every other rule on the same file; a parse failure is
    /// recorded by the engine, so return no matches for it.
    fn detect(&self, input: &Input<'_>) -> Vec<Match>;
}

/// Validates `detect.options` (absent when `None`) and builds a detector.
pub(crate) type BuildFn = fn(Option<&Value>) -> Result<Box<dyn BuiltinDetector>, String>;

/// A registry entry.
pub(crate) struct Builtin {
    /// The name used in `detect.builtin`.
    pub(crate) name: &'static str,
    /// Constructor.
    pub(crate) build: BuildFn,
}

/// Every builtin this build knows. Phase 3 adds `bidi_trojan_source`,
/// `base64_command`, `ci_agent_token_exposure` and
/// `agentkeep_policy_loosening` here.
const BUILTINS: &[Builtin] = &[];

fn registry() -> impl Iterator<Item = &'static Builtin> {
    let base = BUILTINS.iter();
    #[cfg(test)]
    let base = base.chain(tests::TEST_BUILTINS.iter());
    base
}

/// Look up and build a builtin; unknown names are a rule validation error.
pub(crate) fn compile(
    name: &str,
    options: Option<&Value>,
) -> Result<Box<dyn BuiltinDetector>, String> {
    let Some(builtin) = registry().find(|b| b.name == name) else {
        let known: Vec<&str> = BUILTINS.iter().map(|b| b.name).collect();
        return Err(format!(
            "detect.builtin: unknown builtin `{name}` (known: {})",
            if known.is_empty() {
                "none in this build".to_owned()
            } else {
                known.join(", ")
            }
        ));
    };
    (builtin.build)(options).map_err(|e| format!("builtin `{name}`: {e}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Flags every line that equals the configured `word` (default `BOOM`).
    #[derive(Debug)]
    struct LineEquals(String);

    impl BuiltinDetector for LineEquals {
        fn detect(&self, input: &Input<'_>) -> Vec<Match> {
            let mut out = Vec::new();
            let mut offset = 0;
            for line in input.text.split_inclusive('\n') {
                let content = line.trim_end_matches(['\n', '\r']);
                if content == self.0 {
                    out.push(Match::with_detail(
                        offset..offset + content.len(),
                        "line matched",
                    ));
                }
                offset += line.len();
            }
            out
        }
    }

    fn build_line_equals(options: Option<&Value>) -> Result<Box<dyn BuiltinDetector>, String> {
        let word = match options {
            None => "BOOM".to_owned(),
            Some(Value::Object(map)) => {
                if let Some(extra) = map.keys().find(|k| k.as_str() != "word") {
                    return Err(format!("unknown option `{extra}`"));
                }
                map.get("word")
                    .and_then(Value::as_str)
                    .ok_or("option `word` must be a string")?
                    .to_owned()
            }
            Some(_) => return Err("options must be a mapping".into()),
        };
        Ok(Box::new(LineEquals(word)))
    }

    pub(crate) const TEST_BUILTINS: &[Builtin] = &[Builtin {
        name: "test_line_equals",
        build: build_line_equals,
    }];

    #[test]
    fn dispatches_to_the_registry() {
        let d = compile("test_line_equals", None).unwrap();
        let m = d.detect(&Input::new("a.txt", "x\nBOOM\r\ny\n"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].range, 2..6);
    }

    #[test]
    fn options_are_validated_by_the_builtin() {
        let opts = serde_json::json!({"word": "HIT"});
        let d = compile("test_line_equals", Some(&opts)).unwrap();
        assert_eq!(d.detect(&Input::new("a", "HIT\n")).len(), 1);
        let bad = serde_json::json!({"wrod": "HIT"});
        let e = compile("test_line_equals", Some(&bad)).unwrap_err();
        assert!(
            e.contains("builtin `test_line_equals`: unknown option"),
            "{e}"
        );
    }

    #[test]
    fn unknown_names_list_what_exists() {
        let e = compile("nope", None).unwrap_err();
        assert!(e.contains("unknown builtin `nope`"), "{e}");
        // The test-only builtin is never advertised.
        assert!(!e.contains("test_line_equals"), "{e}");
    }
}
