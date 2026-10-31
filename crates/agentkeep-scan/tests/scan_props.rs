//! Property tests: whatever the input, scanning never panics, every
//! finding's range lies inside the input on character boundaries, and
//! snippets and messages are safe to print.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;

use agentkeep_scan::Scanner;
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
}
