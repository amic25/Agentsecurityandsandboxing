//! Precision and recall of the rules over a labelled corpus.
//!
//! Layout, under a corpus root such as `tests/corpus`:
//!
//! - `positive/<category>/<slug>/<case>`: cases rule `<category>/<slug>`
//!   must report;
//! - `negative/<group>/<case>`: cases no rule may report. Every rule
//!   category needs a group of its own name; other groups are allowed.
//!
//! A case is a single file or a directory. A file case is scanned as root =
//! its parent directory with only that file, so its relative path is its
//! file name; a directory case is scanned as its own root, so
//! `case/.github/workflows/x.yml` is seen as `.github/workflows/x.yml`.
//! Both go through [`Scanner::scan`], the walker included.
//!
//! Per rule R: TP = positive cases of R where R reports at least one
//! finding, FN = positive cases of R where it reports none, FP = negative
//! cases where R reports anything. Findings of other rules on R's positive
//! cases are ignored. Precision is TP / (TP + FP), 1.0 when both are 0;
//! recall is TP / (TP + FN), 1.0 when both are 0. Overall numbers sum TP, FP
//! and FN across rules.
//!
//! The corpus itself is data that imitates attacks, so it is walked the same
//! way a scan root is: symlinks are refused, never followed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::engine::Scanner;
use crate::text::escape_for_display;

/// Every rule needs at least this many positive cases.
pub const MIN_POSITIVE_CASES: usize = 3;

/// Baseline values are rounded down to this many decimal places, so a
/// freshly written baseline never sits above the value it came from.
const BASELINE_DECIMALS: i32 = 4;

/// Slack when comparing against the baseline, for float noise only.
const EPSILON: f64 = 1e-9;

/// The corpus could not be read at all.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// A directory of the corpus could not be listed.
    #[error("{path}: cannot read corpus: {source}")]
    Io {
        /// The directory.
        path: String,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The baseline file is not valid baseline JSON.
    #[error("invalid corpus baseline: {0}")]
    Baseline(#[from] serde_json::Error),
}

/// True positives, false positives and false negatives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Positive cases the rule reported.
    pub tp: usize,
    /// Negative cases the rule reported.
    pub fp: usize,
    /// Positive cases the rule missed.
    pub fn_: usize,
}

impl Counts {
    /// TP / (TP + FP), or 1.0 when the rule reported nothing at all.
    pub fn precision(&self) -> f64 {
        ratio(self.tp, self.tp + self.fp)
    }

    /// TP / (TP + FN), or 1.0 when there are no positive cases.
    pub fn recall(&self) -> f64 {
        ratio(self.tp, self.tp + self.fn_)
    }

    fn add(&mut self, other: Counts) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_ += other.fn_;
    }
}

// Case counts are far below 2^52, so the conversion is exact.
#[allow(clippy::cast_precision_loss)]
fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        1.0
    } else {
        num as f64 / den as f64
    }
}

/// One rule's results.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleResult {
    /// The rule.
    pub rule_id: String,
    /// Its counts.
    pub counts: Counts,
    /// How many positive cases it has.
    pub positive_cases: usize,
    /// Positive cases it missed, relative to the corpus root.
    pub missed: Vec<String>,
    /// Negative cases it reported, relative to the corpus root.
    pub false_positives: Vec<String>,
}

/// The result of evaluating a corpus.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evaluation {
    /// Per rule, sorted by rule id; every rule of the scanner appears.
    pub rules: Vec<RuleResult>,
    /// Sums across rules.
    pub overall: Counts,
    /// Number of positive cases.
    pub positive_cases: usize,
    /// Number of negative cases.
    pub negative_cases: usize,
    /// Ways the corpus does not meet its requirements: a rule with fewer
    /// than [`MIN_POSITIVE_CASES`] positive cases, a category without a
    /// negative group, a positive directory for an unknown rule, a symlink,
    /// a case that could not be scanned. The corpus test fails on any.
    pub problems: Vec<String>,
}

/// A case: where it is on disk and how to name it in output.
struct Case {
    path: PathBuf,
    label: String,
}

/// Evaluate `scanner`'s rules over the corpus at `root`.
pub fn evaluate(scanner: &Scanner, root: &Path) -> Result<Evaluation, CorpusError> {
    let mut eval = Evaluation::default();
    let mut results: BTreeMap<String, RuleResult> = scanner
        .rules()
        .iter()
        .map(|r| {
            (
                r.id().to_owned(),
                RuleResult {
                    rule_id: r.id().to_owned(),
                    ..RuleResult::default()
                },
            )
        })
        .collect();

    // Positive cases: positive/<category>/<slug>/<case>.
    let positive = root.join("positive");
    for (category, cat_dir) in subdirs(&positive, "positive", &mut eval.problems)? {
        let cat_label = format!("positive/{category}");
        for (slug, slug_dir) in subdirs(&cat_dir, &cat_label, &mut eval.problems)? {
            let id = format!("{category}/{slug}");
            let slug_label = format!("{cat_label}/{slug}");
            let cases = cases(&slug_dir, &slug_label, &mut eval.problems)?;
            let Some(result) = results.get_mut(&id) else {
                eval.problems.push(format!(
                    "{slug_label}: no rule `{id}` is loaded; positive cases live under positive/<category>/<slug>"
                ));
                continue;
            };
            for case in cases {
                eval.positive_cases += 1;
                result.positive_cases += 1;
                let Some(fired) = fired_rules(scanner, &case, &mut eval.problems) else {
                    continue;
                };
                if fired.contains(id.as_str()) {
                    result.counts.tp += 1;
                } else {
                    result.counts.fn_ += 1;
                    result.missed.push(case.label);
                }
            }
        }
    }

    // Negative cases: negative/<group>/<case>.
    let negative = root.join("negative");
    let mut groups = BTreeSet::new();
    for (group, group_dir) in subdirs(&negative, "negative", &mut eval.problems)? {
        let group_label = format!("negative/{group}");
        let cases = cases(&group_dir, &group_label, &mut eval.problems)?;
        if !cases.is_empty() {
            groups.insert(group);
        }
        for case in cases {
            eval.negative_cases += 1;
            let Some(fired) = fired_rules(scanner, &case, &mut eval.problems) else {
                continue;
            };
            for id in fired {
                if let Some(result) = results.get_mut(&id) {
                    result.counts.fp += 1;
                    result.false_positives.push(case.label.clone());
                }
            }
        }
    }

    // Requirements on the corpus itself.
    let categories: BTreeSet<&str> = results
        .keys()
        .filter_map(|id| id.split_once('/').map(|(c, _)| c))
        .collect();
    for category in categories {
        if !groups.contains(category) {
            eval.problems.push(format!(
                "category `{category}` has no negative cases (expected negative/{category}/)"
            ));
        }
    }
    for result in results.values() {
        if result.positive_cases < MIN_POSITIVE_CASES {
            eval.problems.push(format!(
                "rule `{}` has {} positive case(s); at least {MIN_POSITIVE_CASES} are required",
                result.rule_id, result.positive_cases
            ));
        }
    }

    for result in results.values() {
        eval.overall.add(result.counts);
    }
    eval.rules = results.into_values().collect();
    Ok(eval)
}

/// Scan one case and return the ids of the rules that reported anything,
/// or `None` (with a problem recorded) when it could not be scanned.
fn fired_rules(
    scanner: &Scanner,
    case: &Case,
    problems: &mut Vec<String>,
) -> Option<BTreeSet<String>> {
    match scanner.scan(&case.path) {
        Ok(report) => Some(report.findings.into_iter().map(|f| f.rule_id).collect()),
        Err(e) => {
            problems.push(format!("{}: {e}", case.label));
            None
        }
    }
}

/// Sorted entries of `dir`, without following symlinks. A missing `dir` is
/// an empty list (the caller's requirements report what is missing).
fn entries(dir: &Path, label: &str) -> Result<Vec<(String, PathBuf, fs::FileType)>, CorpusError> {
    let io = |source| CorpusError::Io {
        path: dir.display().to_string(),
        source,
    };
    let list = match fs::read_dir(dir) {
        Ok(list) => list,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(e)),
    };
    let mut out = Vec::new();
    for entry in list {
        let entry = entry.map_err(io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let ft = entry.file_type().map_err(|source| CorpusError::Io {
            path: format!("{label}/{name}"),
            source,
        })?;
        out.push((name, entry.path(), ft));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The subdirectories of `dir`; anything else there is a problem.
fn subdirs(
    dir: &Path,
    label: &str,
    problems: &mut Vec<String>,
) -> Result<Vec<(String, PathBuf)>, CorpusError> {
    let mut out = Vec::new();
    for (name, path, ft) in entries(dir, label)? {
        if ft.is_dir() {
            out.push((name, path));
        } else {
            problems.push(format!(
                "{label}/{}: expected only directories here{}",
                escape_for_display(&name),
                if ft.is_symlink() {
                    " (symlinks are not followed)"
                } else {
                    ""
                }
            ));
        }
    }
    Ok(out)
}

/// The cases in `dir`: every file or directory directly inside it.
fn cases(dir: &Path, label: &str, problems: &mut Vec<String>) -> Result<Vec<Case>, CorpusError> {
    let mut out = Vec::new();
    for (name, path, ft) in entries(dir, label)? {
        let case_label = format!("{label}/{}", escape_for_display(&name));
        if ft.is_symlink() {
            problems.push(format!("{case_label}: symlinks are not followed"));
        } else if ft.is_dir() || ft.is_file() {
            out.push(Case {
                path,
                label: case_label,
            });
        } else {
            problems.push(format!("{case_label}: not a regular file or directory"));
        }
    }
    Ok(out)
}

/// The evaluation as a Markdown table, for stdout and the GitHub job
/// summary: one row per rule, an overall row, then every miss.
pub fn markdown(eval: &Evaluation) -> String {
    let mut out = String::from("### agentkeep scan corpus\n\n");
    let _ = writeln!(
        out,
        "{} rules, {} positive cases, {} negative cases.\n",
        eval.rules.len(),
        eval.positive_cases,
        eval.negative_cases
    );
    out.push_str("| Rule | Positive cases | TP | FN | FP | Precision | Recall |\n");
    out.push_str("|:--|--:|--:|--:|--:|--:|--:|\n");
    for r in &eval.rules {
        let c = r.counts;
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} | {:.3} | {:.3} |",
            r.rule_id,
            r.positive_cases,
            c.tp,
            c.fn_,
            c.fp,
            c.precision(),
            c.recall()
        );
    }
    let c = eval.overall;
    let _ = writeln!(
        out,
        "| **Overall** | {} | {} | {} | {} | **{:.3}** | **{:.3}** |",
        eval.positive_cases,
        c.tp,
        c.fn_,
        c.fp,
        c.precision(),
        c.recall()
    );
    let misses: Vec<String> = eval
        .rules
        .iter()
        .flat_map(|r| {
            r.missed
                .iter()
                .map(move |case| format!("- `{}` missed `{case}`", r.rule_id))
        })
        .collect();
    if !misses.is_empty() {
        out.push_str("\nFalse negatives:\n\n");
        out.push_str(&misses.join("\n"));
        out.push('\n');
    }
    let fps: Vec<String> = eval
        .rules
        .iter()
        .flat_map(|r| {
            r.false_positives
                .iter()
                .map(move |case| format!("- `{}` reported `{case}`", r.rule_id))
        })
        .collect();
    if !fps.is_empty() {
        out.push_str("\nFalse positives:\n\n");
        out.push_str(&fps.join("\n"));
        out.push('\n');
    }
    if !eval.problems.is_empty() {
        out.push_str("\nCorpus problems:\n\n");
        for p in &eval.problems {
            let _ = writeln!(out, "- {p}");
        }
    }
    out
}

/// Append `markdown` to a file such as `$GITHUB_STEP_SUMMARY`.
pub fn append_summary(path: &Path, markdown: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(markdown.as_bytes())?;
    file.write_all(b"\n")
}

/// The committed floor for the metrics: `tests/corpus/baseline.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// Overall precision and recall.
    pub overall: OverallBaseline,
    /// Recall per rule id.
    pub rules: BTreeMap<String, RuleBaseline>,
}

/// Overall floor.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverallBaseline {
    /// Overall precision may not drop below this.
    pub precision: f64,
    /// Overall recall may not drop below this.
    pub recall: f64,
}

/// One rule's floor.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBaseline {
    /// The rule's recall may not drop below this.
    pub recall: f64,
}

/// Round down to [`BASELINE_DECIMALS`] places.
fn floor_to_places(x: f64) -> f64 {
    let scale = 10f64.powi(BASELINE_DECIMALS);
    (x * scale).floor() / scale
}

impl Baseline {
    /// The current numbers as a baseline, rounded down.
    pub fn from_evaluation(eval: &Evaluation) -> Self {
        Self {
            overall: OverallBaseline {
                precision: floor_to_places(eval.overall.precision()),
                recall: floor_to_places(eval.overall.recall()),
            },
            rules: eval
                .rules
                .iter()
                .map(|r| {
                    (
                        r.rule_id.clone(),
                        RuleBaseline {
                            recall: floor_to_places(r.counts.recall()),
                        },
                    )
                })
                .collect(),
        }
    }

    /// Parse baseline JSON.
    pub fn parse(text: &str) -> Result<Self, CorpusError> {
        Ok(serde_json::from_str(text)?)
    }

    /// Pretty JSON with a trailing newline; rules sorted by id.
    pub fn to_json(&self) -> Result<String, CorpusError> {
        let mut out = serde_json::to_string_pretty(self)?;
        out.push('\n');
        Ok(out)
    }
}

/// Every way `eval` falls below `baseline`: overall precision or recall
/// below the floor, a rule's recall below its floor, or a rule in the
/// baseline that no longer exists (regenerate the baseline when removing a
/// rule, so the removal is reviewed). Rules not yet in the baseline only
/// have to meet the overall numbers.
pub fn regressions(eval: &Evaluation, baseline: &Baseline) -> Vec<String> {
    let mut out = Vec::new();
    let precision = eval.overall.precision();
    if precision + EPSILON < baseline.overall.precision {
        out.push(format!(
            "overall precision {precision:.4} is below the baseline {:.4}",
            baseline.overall.precision
        ));
    }
    let recall = eval.overall.recall();
    if recall + EPSILON < baseline.overall.recall {
        out.push(format!(
            "overall recall {recall:.4} is below the baseline {:.4}",
            baseline.overall.recall
        ));
    }
    for (id, floor) in &baseline.rules {
        match eval.rules.iter().find(|r| &r.rule_id == id) {
            Some(r) => {
                let recall = r.counts.recall();
                if recall + EPSILON < floor.recall {
                    out.push(format!(
                        "rule `{id}` recall {recall:.4} is below the baseline {:.4} (missed: {})",
                        floor.recall,
                        r.missed.join(", ")
                    ));
                }
            }
            None => out.push(format!(
                "rule `{id}` is in the baseline but not loaded; regenerate the baseline if it was removed on purpose"
            )),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Rule;

    fn rule(id: &str, pattern: &str, glob: &str) -> Rule {
        Rule::from_yaml(
            &format!(
                "id: {id}\nseverity: high\ntitle: T\ndescription: d\napplies_to: ['{glob}']\n\
                 detect:\n  regex: '{pattern}'\nremediation: r\n\
                 examples:\n  match: ['{pattern}']\n  nomatch: ['zzz']\n"
            ),
            "t.yaml",
            None,
        )
        .unwrap()
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }

    fn scanner() -> Scanner {
        Scanner::new(vec![
            rule("cat-a/needle", "needle", "*.md"),
            // Only workflow files: proves directory cases keep their layout.
            rule("cat-b/flow", "agent", ".github/workflows/*.yml"),
        ])
        .unwrap()
    }

    /// A corpus where cat-a/needle has 3 hits and 1 miss and one false
    /// positive, and cat-b/flow has 3 directory-case hits.
    fn corpus(root: &Path) {
        for i in 0..3 {
            write(
                root,
                &format!("positive/cat-a/needle/hit{i}.md"),
                "a needle\n",
            );
        }
        write(root, "positive/cat-a/needle/miss.md", "a pin\n");
        for i in 0..3 {
            write(
                root,
                &format!("positive/cat-b/flow/case{i}/.github/workflows/x.yml"),
                "run: agent\n",
            );
        }
        write(root, "negative/cat-a/clean.md", "nothing\n");
        write(root, "negative/cat-a/fp.md", "needle in a haystack\n");
        // The word is there, but not at a workflow path: no finding.
        write(root, "negative/cat-b/notflow/x.yml", "run: agent\n");
        write(
            root,
            "negative/general/also-clean.txt",
            "needle but not markdown\n",
        );
    }

    #[test]
    fn counts_follow_the_definitions() {
        let tmp = tempfile::tempdir().unwrap();
        corpus(tmp.path());
        let eval = evaluate(&scanner(), tmp.path()).unwrap();
        assert!(eval.problems.is_empty(), "{:?}", eval.problems);
        assert_eq!(eval.positive_cases, 7);
        assert_eq!(eval.negative_cases, 4);
        let a = &eval.rules[0];
        assert_eq!(a.rule_id, "cat-a/needle");
        assert_eq!(
            a.counts,
            Counts {
                tp: 3,
                fp: 1,
                fn_: 1
            }
        );
        assert_eq!(a.missed, vec!["positive/cat-a/needle/miss.md"]);
        assert_eq!(a.false_positives, vec!["negative/cat-a/fp.md"]);
        assert!((a.counts.precision() - 0.75).abs() < 1e-12);
        assert!((a.counts.recall() - 0.75).abs() < 1e-12);
        let b = &eval.rules[1];
        assert_eq!(
            b.counts,
            Counts {
                tp: 3,
                fp: 0,
                fn_: 0
            }
        );
        assert_eq!(
            eval.overall,
            Counts {
                tp: 6,
                fp: 1,
                fn_: 1
            }
        );
        assert!((eval.overall.precision() - 6.0 / 7.0).abs() < 1e-12);
    }

    #[test]
    fn other_rules_on_a_positive_case_are_not_false_positives() {
        let tmp = tempfile::tempdir().unwrap();
        corpus(tmp.path());
        // cat-a/needle fires on a cat-b positive case too: ignored.
        write(
            tmp.path(),
            "positive/cat-b/flow/case9/.github/workflows/x.yml",
            "run: agent\n",
        );
        write(
            tmp.path(),
            "positive/cat-b/flow/case9/README.md",
            "needle\n",
        );
        let eval = evaluate(&scanner(), tmp.path()).unwrap();
        assert_eq!(eval.rules[0].counts.fp, 1);
        assert_eq!(eval.rules[1].counts.tp, 4);
    }

    #[test]
    fn empty_counts_are_perfect() {
        let c = Counts::default();
        assert!((c.precision() - 1.0).abs() < f64::EPSILON);
        assert!((c.recall() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn requirements_are_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "positive/cat-a/needle/one.md", "needle\n");
        write(root, "positive/cat-z/ghost/one.md", "needle\n");
        write(root, "positive/stray.md", "x\n");
        write(root, "negative/cat-a/clean.md", "x\n");
        fs::create_dir_all(root.join("negative/cat-b")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("clean.md", root.join("negative/cat-a/link.md")).unwrap();
        let eval = evaluate(&scanner(), root).unwrap();
        let all = eval.problems.join("\n");
        assert!(
            all.contains("rule `cat-a/needle` has 1 positive case(s)"),
            "{all}"
        );
        assert!(
            all.contains("rule `cat-b/flow` has 0 positive case(s)"),
            "{all}"
        );
        assert!(all.contains("no rule `cat-z/ghost` is loaded"), "{all}");
        assert!(
            all.contains("positive/stray.md: expected only directories"),
            "{all}"
        );
        assert!(
            all.contains("category `cat-b` has no negative cases"),
            "{all}"
        );
        assert!(!all.contains("category `cat-a`"), "{all}");
        #[cfg(unix)]
        {
            assert!(
                all.contains("negative/cat-a/link.md: symlinks are not followed"),
                "{all}"
            );
            assert_eq!(eval.negative_cases, 1);
        }
    }

    #[test]
    fn a_missing_corpus_is_all_problems_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let eval = evaluate(&scanner(), &tmp.path().join("nope")).unwrap();
        assert_eq!(eval.positive_cases, 0);
        assert_eq!(eval.problems.len(), 4, "{:?}", eval.problems);
    }

    #[test]
    fn markdown_table() {
        let tmp = tempfile::tempdir().unwrap();
        corpus(tmp.path());
        let eval = evaluate(&scanner(), tmp.path()).unwrap();
        let md = markdown(&eval);
        assert!(md.starts_with(
            "### agentkeep scan corpus\n\n2 rules, 7 positive cases, 4 negative cases.\n"
        ));
        assert!(
            md.contains("| `cat-a/needle` | 4 | 3 | 1 | 1 | 0.750 | 0.750 |\n"),
            "{md}"
        );
        assert!(
            md.contains("| `cat-b/flow` | 3 | 3 | 0 | 0 | 1.000 | 1.000 |\n"),
            "{md}"
        );
        assert!(
            md.contains("| **Overall** | 7 | 6 | 1 | 1 | **0.857** | **0.857** |\n"),
            "{md}"
        );
        assert!(md.contains("- `cat-a/needle` missed `positive/cat-a/needle/miss.md`"));
        assert!(md.contains("- `cat-a/needle` reported `negative/cat-a/fp.md`"));
        assert!(!md.contains("Corpus problems"));
        let out = tmp.path().join("summary.md");
        append_summary(&out, "first").unwrap();
        append_summary(&out, &md).unwrap();
        let written = fs::read_to_string(&out).unwrap();
        assert!(written.starts_with("first\n### agentkeep scan corpus"));
    }

    #[test]
    fn baseline_round_trip_and_regressions() {
        let tmp = tempfile::tempdir().unwrap();
        corpus(tmp.path());
        let eval = evaluate(&scanner(), tmp.path()).unwrap();
        let base = Baseline::from_evaluation(&eval);
        // Rounded down: 6/7 = 0.857142... -> 0.8571.
        assert!((base.overall.precision - 0.8571).abs() < 1e-12);
        assert!((base.rules["cat-a/needle"].recall - 0.75).abs() < 1e-12);
        let json = base.to_json().unwrap();
        assert!(
            json.starts_with("{\n  \"overall\": {\n    \"precision\": 0.8571,"),
            "{json}"
        );
        assert_eq!(Baseline::parse(&json).unwrap(), base);
        assert!(regressions(&eval, &base).is_empty());

        // The baseline sits above the current numbers.
        let mut strict = base.clone();
        strict.overall.recall = 0.9;
        strict.overall.precision = 0.9;
        strict.rules.get_mut("cat-a/needle").unwrap().recall = 1.0;
        strict
            .rules
            .insert("cat-c/gone".into(), RuleBaseline { recall: 1.0 });
        let r = regressions(&eval, &strict).join("\n");
        assert!(
            r.contains("overall precision 0.8571 is below the baseline 0.9000"),
            "{r}"
        );
        assert!(
            r.contains("overall recall 0.8571 is below the baseline 0.9000"),
            "{r}"
        );
        assert!(r.contains("rule `cat-a/needle` recall 0.7500 is below the baseline 1.0000 (missed: positive/cat-a/needle/miss.md)"), "{r}");
        assert!(
            r.contains("rule `cat-c/gone` is in the baseline but not loaded"),
            "{r}"
        );

        // A rule missing from the baseline is fine; unknown keys are not.
        let mut loose = base.clone();
        loose.rules.remove("cat-b/flow");
        assert!(regressions(&eval, &loose).is_empty());
        assert!(Baseline::parse(
            "{\"overall\":{\"precision\":1,\"recall\":1},\"rules\":{},\"x\":1}"
        )
        .is_err());
        assert!(Baseline::parse("not json").is_err());
    }
}
