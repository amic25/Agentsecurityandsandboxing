//! Precision and recall of the built-in rules over `tests/corpus`.
//!
//! Prints the table (run with `--nocapture` to see it), appends it to
//! `$GITHUB_STEP_SUMMARY` when that is set, and fails when the corpus does
//! not meet its requirements (every rule has at least three positive cases,
//! every category has negative cases) or when overall precision or recall,
//! or any rule's recall, falls below `tests/corpus/baseline.json`.
//!
//! `scripts/corpus-baseline.sh` sets `AGENTKEEP_CORPUS_WRITE_BASELINE=1` to
//! rewrite the baseline from the current numbers instead of comparing. The
//! new file needs human review before it is committed: a lower number in it
//! is a regression being accepted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use agentkeep_scan::corpus::{self, Baseline};
use agentkeep_scan::Scanner;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("corpus")
}

/// An unset or empty variable counts as unset, so a CI matrix can clear it.
fn set(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[test]
fn corpus_meets_the_baseline() {
    let dir = corpus_dir();
    let scanner = Scanner::with_builtin_rules().expect("built-in rules load");
    let eval = corpus::evaluate(&scanner, &dir).expect("corpus is readable");
    let table = corpus::markdown(&eval);
    println!("{table}");
    if let Some(summary) = set("GITHUB_STEP_SUMMARY") {
        corpus::append_summary(Path::new(&summary), &table)
            .unwrap_or_else(|e| panic!("cannot append to {summary}: {e}"));
    }

    assert!(
        eval.problems.is_empty(),
        "the corpus does not meet its requirements:\n{}",
        eval.problems.join("\n")
    );

    let baseline_path = dir.join("baseline.json");
    if set("AGENTKEEP_CORPUS_WRITE_BASELINE").is_some() {
        let json = Baseline::from_evaluation(&eval).to_json().unwrap();
        fs::write(&baseline_path, json).unwrap();
        println!(
            "wrote {}; review it before committing",
            baseline_path.display()
        );
        return;
    }

    let text = fs::read_to_string(&baseline_path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/corpus-baseline.sh",
            baseline_path.display()
        )
    });
    let baseline = Baseline::parse(&text).unwrap();
    let regressions = corpus::regressions(&eval, &baseline);
    assert!(
        regressions.is_empty(),
        "corpus metrics fell below tests/corpus/baseline.json:\n{}",
        regressions.join("\n")
    );
}
