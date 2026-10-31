//! `detect.regex`: a Rust `regex` pattern, plus the shared regex compiler.
//!
//! Patterns come from rule files, which may be community-written, and run
//! over hostile text. The `regex` crate guarantees linear-time matching; the
//! size limits stop a pattern from compiling into something huge.

use ::regex::{Regex, RegexBuilder};

use super::Match;

/// Compiled-program size limit for rule regexes.
const SIZE_LIMIT: usize = 1 << 20;
/// Lazy-DFA cache limit for rule regexes.
const DFA_SIZE_LIMIT: usize = 1 << 22;

/// Compile a rule-supplied pattern with the scanner's limits. `multiline`
/// turns on `(?m)`; `^`/`$` then also treat `\r\n` as a line end so CRLF
/// files behave like LF files.
pub(crate) fn compile(pattern: &str, multiline: bool) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .multi_line(multiline)
        .crlf(true)
        .size_limit(SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map_err(|e| e.to_string())
}

/// Every non-empty match. Empty matches (`^`, `a*`) point at nothing and are
/// dropped rather than reported.
pub(crate) fn detect(re: &Regex, text: &str) -> Vec<Match> {
    re.find_iter(text)
        .filter(|m| !m.is_empty())
        .map(|m| Match::new(m.range()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(pattern: &str, multiline: bool, text: &str) -> Vec<String> {
        let re = compile(pattern, multiline).unwrap();
        detect(&re, text)
            .into_iter()
            .map(|m| text[m.range].to_string())
            .collect()
    }

    #[test]
    fn multiline_is_the_default_behaviour() {
        assert_eq!(ranges("^foo$", true, "x\nfoo\nfoo bar"), vec!["foo"]);
        assert!(ranges("^foo$", false, "x\nfoo\nbar").is_empty());
    }

    #[test]
    fn crlf_line_ends() {
        assert_eq!(ranges("^foo$", true, "x\r\nfoo\r\nbar"), vec!["foo"]);
        assert_eq!(ranges("bar$", true, "x\r\nfoo bar\r\n"), vec!["bar"]);
    }

    #[test]
    fn empty_matches_are_dropped() {
        assert!(ranges("a*", true, "bbb").is_empty());
        assert_eq!(ranges("a*", true, "baab"), vec!["aa"]);
    }

    #[test]
    fn size_limit_rejects_huge_patterns() {
        // A counted repetition that expands far past the size limit.
        let e = compile(r"(\w{100}){100}", true).unwrap_err();
        assert!(e.to_lowercase().contains("size"), "{e}");
    }

    #[test]
    fn unicode_aware() {
        assert_eq!(ranges(r"(?i)ignore", true, "IGNORE ïgnore"), vec!["IGNORE"]);
        assert_eq!(ranges(r"\u{202E}", true, "a\u{202e}b").len(), 1);
    }
}
