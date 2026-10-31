//! Every built-in rule's inline examples behave as declared. This is the
//! same check `agentkeep scan --test-rules` runs for community rules.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use agentkeep_scan::Scanner;

#[test]
fn rules_examples() {
    let scanner =
        Scanner::with_builtin_rules().unwrap_or_else(|e| panic!("built-in rules must load: {e}"));
    assert!(!scanner.rules().is_empty(), "no built-in rules embedded");
    let failures: Vec<String> = scanner
        .run_all_examples()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        failures.is_empty(),
        "inline examples failed:\n{}",
        failures.join("\n")
    );
}
