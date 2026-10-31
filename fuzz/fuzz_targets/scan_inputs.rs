//! Fuzz the scanner with hostile files and hostile rules. Any panic is a bug.
//!
//! - The input as a file (lossy UTF-8, as the walker decodes it) under the
//!   paths that select the structured parsers and the builtins, through
//!   `scan_text` with the built-in rules; every finding must lie inside the
//!   input, and the report must render in every output format.
//! - The input as a rule file through the rule loader, and when it loads,
//!   its own inline examples through the engine.
#![no_main]

use std::sync::OnceLock;

use agentkeep_scan::engine::run_examples;
use agentkeep_scan::output::{render, Format};
use agentkeep_scan::{Report, Rule, Scanner};
use libfuzzer_sys::fuzz_target;

const PATHS: &[&str] = &[
    "x.md",
    ".github/workflows/x.yml",
    ".mcp.json",
    ".codex/config.toml",
    "agentkeep.toml",
];

fn scanner() -> &'static Scanner {
    static SCANNER: OnceLock<Scanner> = OnceLock::new();
    SCANNER.get_or_init(|| match Scanner::with_builtin_rules() {
        Ok(s) => s,
        Err(e) => panic!("built-in rules must load: {e}"),
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let scanner = scanner();
    for path in PATHS {
        let scan = scanner.scan_text_full(path, &text);
        for f in &scan.findings {
            let r = &f.byte_range;
            assert!(r.start <= r.end && r.end <= text.len());
            assert!(text.is_char_boundary(r.start) && text.is_char_boundary(r.end));
        }
        let report = Report {
            root: "fuzz".into(),
            root_dir: "/fuzz".into(),
            findings: scan.findings,
            files_scanned: 1,
            ..Report::default()
        };
        for format in [Format::Text, Format::Json, Format::Sarif] {
            assert!(render(&report, scanner.rules(), format, false).is_ok());
        }
    }

    if let Ok(yaml) = std::str::from_utf8(data) {
        if let Ok(rule) = Rule::from_yaml(yaml, "fuzz.yaml", None) {
            let _ = run_examples(&rule);
        }
    }
});
