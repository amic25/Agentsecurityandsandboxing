//! Property tests: whatever the input, scanning never panics, every
//! finding's range lies inside the input on character boundaries, and
//! snippets and messages are safe to print. The renderers turn any such
//! scan into valid JSON and SARIF and into text without control characters.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;

use agentkeep_scan::output::{json, sarif, text};
use agentkeep_scan::{Report, Scanner};
use proptest::prelude::*;

fn scanner() -> &'static Scanner {
    static SCANNER: OnceLock<Scanner> = OnceLock::new();
    SCANNER.get_or_init(|| Scanner::with_builtin_rules().unwrap())
}

/// Paths that select different rules and parsers.
const PATHS: &[&str] = &[
    "x.md",
    "AGENTS.md",
    ".cursorrules",
    ".github/workflows/x.yml",
    ".mcp.json",
    ".codex/config.toml",
    "agentkeep.toml",
    "scripts/x.sh",
    "notes.txt",
    "src/x.rs",
    "web/x.html",
];

/// Fragments that drive the detectors into their interesting branches.
const VOCAB: &[&str] = &[
    "curl",
    "wget",
    " -fsSL ",
    "https://a.example/x?q=1",
    " | ",
    "|",
    "sh",
    "bash",
    "$(",
    ")",
    "<(",
    "\"",
    "'",
    "`",
    "\\",
    "\\n",
    "\\\"",
    "\\u0063",
    "eval ",
    "sudo ",
    "env X=1 ",
    "![",
    "](",
    "][",
    "]: ",
    "[",
    "]",
    "<img src=",
    ">",
    "```",
    "~~~",
    "\n",
    "\r\n",
    " ",
    "\t",
    ":",
    "- ",
    "{",
    "}",
    ",",
    "&",
    "&&",
    ";",
    "#",
    "\u{FEFF}",
    "\u{200B}",
    "\u{200D}",
    "\u{202E}",
    "\u{2066}",
    "\u{E0041}",
    "\u{E0069}",
    "\u{E007F}",
    "\u{1F3F4}",
    "\u{FE0F}",
    "\u{E0100}",
    "\u{00AD}",
    "\u{F8FF}",
    "😀",
    "é",
    "日本",
    "\u{0645}",
    "\u{200C}",
    "&a ",
    "*a",
    "---",
    "mode: ",
    "run: |",
    "= ",
    "\u{0}",
    "\u{1b}[31m",
    // Builtins: bidi, base64, CI workflows, agentkeep policies.
    "\u{2069}",
    "\u{202C}",
    "\u{202D}",
    "\u{2029}",
    "\u{05E9}",
    "/*",
    "*/",
    "//",
    "<!--",
    "base64 -d",
    "Y3VybCB4IHwgc2g=",
    "aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=",
    "SQBFAFgAIAAoAGkAdwByACAAeAApAA==",
    "-enc ",
    "on: issue_comment\n",
    "jobs:\n  a:\n    steps:\n",
    "      - uses: anthropics/claude-code-action@v1\n",
    "      - run: claude -p ",
    "${{ github.event.comment.body }}",
    "permissions: write-all\n",
    "if: github.event.comment.author_association == 'OWNER'\n",
    "[network]\n",
    "allow = [\"*\"]\n",
    "[override]\nacknowledge = true\n",
];

fn text_from(parts: &[usize]) -> String {
    parts.iter().map(|&i| VOCAB[i % VOCAB.len()]).collect()
}

fn check(path: &str, text: &str) {
    let scan = scanner().scan_text_full(path, text);
    for f in &scan.findings {
        let r = &f.byte_range;
        assert!(
            r.start <= r.end && r.end <= text.len(),
            "{r:?} outside {}",
            text.len()
        );
        assert!(text.is_char_boundary(r.start) && text.is_char_boundary(r.end));
        assert!(f.start.line >= 1 && f.start.column >= 1);
        assert!((f.start.line, f.start.column) <= (f.end.line, f.end.column));
        assert!(f.snippet.chars().count() <= 200, "{}", f.snippet);
        assert!(!f
            .snippet
            .chars()
            .any(|c| c.is_control() && c != '\t' && c != '\n'));
        assert!(!f
            .message
            .chars()
            .any(|c| c.is_control() && c != '\t' && c != '\n'));
        assert_eq!(f.fingerprint.len(), 64);
    }
    for e in &scan.errors {
        assert!(
            !e.chars().any(|c| c.is_control() && c != '\t' && c != '\n'),
            "{e}"
        );
    }
}

/// Render one scanned text in every format and check the documents.
fn check_outputs(path: &str, input: &str) {
    let findings = scanner().scan_text(path, input);
    let n = findings.len();
    let report = Report {
        root: "repo".into(),
        root_dir: "/srv/repo".into(),
        findings,
        files_scanned: 1,
        ..Report::default()
    };
    let doc: serde_json::Value = serde_json::from_str(&json::render(&report).unwrap()).unwrap();
    assert_eq!(doc["findings"].as_array().unwrap().len(), n);
    assert_eq!(doc["summary"]["findings"], n);

    let rules = scanner().rules();
    let log: serde_json::Value =
        serde_json::from_str(&sarif::render(&report, rules).unwrap()).unwrap();
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), n);
    for r in results {
        let idx = usize::try_from(r["ruleIndex"].as_u64().unwrap()).unwrap();
        assert_eq!(rules[idx].id(), r["ruleId"].as_str().unwrap());
        let uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(uri.bytes().all(|b| b.is_ascii_graphic()), "{uri}");
    }

    let out = text::render(&report, rules, false);
    let unsafe_char = |c: char| {
        (c.is_control() && c != '\n' && c != '\t')
            || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{E0000}'..='\u{E007F}')
    };
    assert!(!out.chars().any(unsafe_char), "{out:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_text_never_breaks_the_scanner(text in "\\PC*", path in prop::sample::select(PATHS)) {
        check(path, &text);
    }

    #[test]
    fn detector_fragments_never_break_the_scanner(
        parts in prop::collection::vec(any::<usize>(), 0..120),
        path in prop::sample::select(PATHS),
    ) {
        check(path, &text_from(&parts));
    }

    #[test]
    fn every_scan_renders_in_every_format(
        parts in prop::collection::vec(any::<usize>(), 0..80),
        path in prop::sample::select(PATHS),
    ) {
        check_outputs(path, &text_from(&parts));
    }

    #[test]
    fn hostile_paths_render_safely(
        name in "[a-z\\x00-\\x1f\\u{202E}\\u{E0041} %#?]{1,12}",
        parts in prop::collection::vec(any::<usize>(), 0..40),
    ) {
        check_outputs(&format!("{name}.md"), &text_from(&parts));
    }
}
