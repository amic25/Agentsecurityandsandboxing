//! The rule set compiled into the binary.
//!
//! `build.rs` embeds every `rules/**/*.yaml` from the workspace with
//! `include_str!`. The rules are parsed and validated at startup like any
//! other rule file; a built-in rule that fails validation is caught by this
//! crate's tests, and at runtime it is an error, never a panic.

use crate::rule::{check_unique, Rule, RuleError};

include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));

/// The embedded rule files: path relative to `rules/` and contents.
pub fn sources() -> &'static [(&'static str, &'static str)] {
    EMBEDDED
}

/// Parse and validate the embedded rules. Each id must equal
/// `<category>/<file stem>` of its path.
pub fn rules() -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::with_capacity(EMBEDDED.len());
    for (rel, text) in EMBEDDED {
        let origin = format!("builtin:rules/{rel}");
        let expected = expected_id(rel).ok_or_else(|| RuleError::Invalid {
            origin: origin.clone(),
            message: "built-in rules live at rules/<category>/<slug>.yaml".into(),
        })?;
        rules.push(Rule::from_yaml(text, &origin, Some(&expected))?);
    }
    check_unique(&rules)?;
    Ok(rules)
}

fn expected_id(rel: &str) -> Option<String> {
    let (category, file) = rel.split_once('/')?;
    let slug = file.strip_suffix(".yaml")?;
    if slug.contains('/') {
        return None;
    }
    Some(format!("{category}/{slug}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::run_examples;

    #[test]
    fn every_embedded_rule_loads() {
        let rules = rules().unwrap_or_else(|e| panic!("built-in rules must load: {e}"));
        assert_eq!(rules.len(), sources().len());
        for id in [
            "hidden-unicode/tag-characters",
            "exfiltration/markdown-image-beacon",
            "risky-shell/curl-pipe-shell",
        ] {
            assert!(rules.iter().any(|r| r.id() == id), "missing {id}");
        }
    }

    #[test]
    fn every_embedded_rule_passes_its_examples() {
        let rules = rules().unwrap();
        let failures: Vec<String> = rules
            .iter()
            .flat_map(run_examples)
            .map(|f| f.to_string())
            .collect();
        assert!(
            failures.is_empty(),
            "inline examples failed:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn expected_ids_follow_the_layout() {
        assert_eq!(expected_id("a/b.yaml").as_deref(), Some("a/b"));
        assert_eq!(expected_id("b.yaml"), None);
        assert_eq!(expected_id("a/b/c.yaml"), None);
        assert_eq!(expected_id("a/b.yml"), None);
    }
}
