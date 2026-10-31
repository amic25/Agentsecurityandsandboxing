//! `builtin: bidi_trojan_source`: bidi controls that make code or text
//! display differently from how it is parsed (Trojan Source,
//! CVE-2021-42574).
//!
//! Only the nine embedding, override and isolate controls are considered:
//! LRE, RLE, PDF, LRO, RLO (U+202A-202E) and LRI, RLI, FSI, PDI
//! (U+2066-2069). The directional marks LRM, RLM and ALM behave like one
//! invisible letter, cannot reorder a run on their own and are part of
//! correct Hebrew, Arabic and Persian typography, so they are left to the
//! `unicode` detector.
//!
//! A control is reported when
//!
//! - it is unbalanced within its line: an embedding, override or isolate
//!   still open at the end of the line, or a PDF or PDI that closes
//!   nothing. The bidi algorithm ends every scope at a paragraph break, so
//!   an unclosed control reorders everything after it on its line; that is
//!   how the published attacks move code visually into or out of a comment
//!   or string. Line ends are LF, CR, NEL, U+2029 and U+001C-001E;
//! - it sits in a source file (chosen by extension or file name) inside a
//!   comment or a string literal, or outside both, where it has no business
//!   at all. The context comes from a small per-language lexer and is named
//!   in the message. In markup (HTML, XML, SVG, Vue, Svelte) text outside
//!   comments is prose and is judged like a text file;
//! - it is an override (LRO or RLO) whose scope covers at least two
//!   visible characters, some of which would display in the other
//!   direction: the override visibly reverses text.
//!
//! Balanced embeddings and isolates in prose, such as Hebrew or Arabic text
//! that embeds a Latin word, stay quiet, and so do data files (JSON, YAML,
//! translation catalogs), which are judged as prose. One match per line,
//! from the first to the last flagged control.

use std::ops::Range;

use serde_json::Value;

use super::builtin::{no_options, BuiltinDetector};
use super::unicode::{describe, is_hidden};
use super::{Input, Match};

/// Stop one past the engine's cap; the engine reports the truncation.
const MAX_MATCHES: usize = crate::engine::MAX_FINDINGS_PER_RULE + 1;

/// Controls listed per message; the rest are counted.
const MAX_LISTED: usize = 6;

const LRE: char = '\u{202A}';
const RLE: char = '\u{202B}';
const PDF: char = '\u{202C}';
const LRO: char = '\u{202D}';
const RLO: char = '\u{202E}';
const LRI: char = '\u{2066}';
const RLI: char = '\u{2067}';
const FSI: char = '\u{2068}';
const PDI: char = '\u{2069}';

/// Why a control is reported (bit set).
const UNCLOSED: u8 = 1;
const STRAY: u8 = 2;
const REORDERS: u8 = 4;
const MISPLACED: u8 = 8;

pub(crate) fn build(options: Option<&Value>) -> Result<Box<dyn BuiltinDetector>, String> {
    no_options(options)?;
    Ok(Box::new(BidiTrojanSource))
}

#[derive(Debug)]
struct BidiTrojanSource;

impl BuiltinDetector for BidiTrojanSource {
    fn detect(&self, input: &Input<'_>) -> Vec<Match> {
        detect(input.path, input.text)
    }
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Paragraph separators (bidi class B) and CR: every scope ends here.
fn is_paragraph_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{1C}'..='\u{1E}' | '\u{85}' | '\u{2029}')
}

/// Scripts written right to left (strong R and AL, approximately: the
/// blocks, not the per-character property).
fn is_rtl(c: char) -> bool {
    matches!(
        u32::from(c),
        0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFE | 0x10800..=0x10FFF | 0x1E800..=0x1EFFF
    )
}

fn detect(path: &str, text: &str) -> Vec<Match> {
    let mut out = Vec::new();
    if !text.contains(is_bidi_control) {
        return out;
    }
    let syntax = syntax_for(path);
    let regions = syntax.map(|s| regions(text, s)).unwrap_or_default();
    let markup = syntax.is_some_and(|s| s.markup);
    let mut line = Line::default();
    for (at, c) in text.char_indices() {
        if is_paragraph_break(c) {
            line.finish(&mut out);
            if out.len() >= MAX_MATCHES {
                return out;
            }
        } else if is_bidi_control(c) {
            let ctx = match (syntax, context_at(&regions, at)) {
                (None, _) => Context::Prose,
                (Some(_), Context::Code) if markup => Context::Prose,
                (Some(_), ctx) => ctx,
            };
            line.control(at, c, ctx);
        } else {
            line.other(at, c);
        }
    }
    line.finish(&mut out);
    out
}

// ---------------------------------------------------------------------------
// One line

/// Where a control sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Context {
    /// A text file, a data file or markup text.
    Prose,
    /// Source code outside strings and comments.
    Code,
    Comment,
    Str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Ltr,
    Rtl,
}

#[derive(Debug)]
struct Ctrl {
    at: usize,
    c: char,
    ctx: Context,
    why: u8,
    /// End of the text to report for this control: the control itself, or
    /// the end of what an override reorders.
    end: usize,
}

#[derive(Debug)]
struct Open {
    /// Index into `Line::controls`.
    idx: usize,
    isolate: bool,
    /// Set for overrides.
    dir: Option<Dir>,
    visible: usize,
    /// Covers a visible character of the other direction.
    foreign: bool,
}

#[derive(Debug, Default)]
struct Line {
    controls: Vec<Ctrl>,
    stack: Vec<Open>,
    /// End of the last character seen on this line.
    last_end: usize,
}

impl Line {
    fn control(&mut self, at: usize, c: char, ctx: Context) {
        let end = at + c.len_utf8();
        self.last_end = end;
        let idx = self.controls.len();
        let why = if ctx == Context::Prose { 0 } else { MISPLACED };
        self.controls.push(Ctrl {
            at,
            c,
            ctx,
            why,
            end,
        });
        let open = |isolate, dir| Open {
            idx,
            isolate,
            dir,
            visible: 0,
            foreign: false,
        };
        match c {
            LRE | RLE => self.stack.push(open(false, None)),
            LRO => self.stack.push(open(false, Some(Dir::Ltr))),
            RLO => self.stack.push(open(false, Some(Dir::Rtl))),
            LRI | RLI | FSI => {
                // An isolate is one neutral unit to the scope around it; an
                // RLO moves it like a character.
                if let Some(top) = self.stack.last_mut() {
                    if let Some(dir) = top.dir {
                        top.visible += 1;
                        top.foreign |= dir == Dir::Rtl;
                    }
                }
                self.stack.push(open(true, None));
            }
            // A PDF closes the innermost embedding, but never reaches past
            // an isolate (UAX #9, X7).
            PDF => match self.stack.pop() {
                Some(o) if !o.isolate => self.close(&o, end),
                Some(o) => {
                    self.stack.push(o);
                    self.mark(idx, STRAY);
                }
                None => self.mark(idx, STRAY),
            },
            // A PDI closes the innermost isolate and every embedding opened
            // inside it (X6a).
            PDI => match self.stack.iter().rposition(|o| o.isolate) {
                Some(pos) => {
                    for o in self.stack.split_off(pos) {
                        self.close(&o, end);
                    }
                }
                None => self.mark(idx, STRAY),
            },
            _ => {}
        }
    }

    fn other(&mut self, at: usize, c: char) {
        self.last_end = at + c.len_utf8();
        if c.is_whitespace() || c.is_control() || is_hidden(c) {
            return;
        }
        // The innermost scope decides how this character is displayed.
        if let Some(top) = self.stack.last_mut() {
            if let Some(dir) = top.dir {
                top.visible += 1;
                top.foreign |= match dir {
                    Dir::Rtl => !is_rtl(c),
                    Dir::Ltr => is_rtl(c),
                };
            }
        }
    }

    fn mark(&mut self, idx: usize, why: u8) {
        if let Some(ctrl) = self.controls.get_mut(idx) {
            ctrl.why |= why;
        }
    }

    /// A scope ends at `end` (its closer, or the end of the line).
    fn close(&mut self, open: &Open, end: usize) {
        if open.dir.is_some() && open.visible >= 2 && open.foreign {
            if let Some(ctrl) = self.controls.get_mut(open.idx) {
                ctrl.why |= REORDERS;
                ctrl.end = ctrl.end.max(end);
            }
        }
    }

    fn finish(&mut self, out: &mut Vec<Match>) {
        let line_end = self.last_end;
        while let Some(open) = self.stack.pop() {
            self.mark(open.idx, UNCLOSED);
            self.close(&open, line_end);
        }
        let flagged: Vec<&Ctrl> = self.controls.iter().filter(|c| c.why != 0).collect();
        if let (Some(first), Some(end)) = (flagged.first(), flagged.iter().map(|c| c.end).max()) {
            out.push(Match::with_detail(first.at..end, detail(&flagged)));
        }
        self.controls.clear();
        self.stack.clear();
    }
}

fn detail(flagged: &[&Ctrl]) -> String {
    let mut parts: Vec<String> = flagged
        .iter()
        .take(MAX_LISTED)
        .map(|ctrl| {
            let mut reasons: Vec<&str> = Vec::new();
            if ctrl.why & MISPLACED != 0 {
                reasons.push(match ctrl.ctx {
                    Context::Comment => "in a comment",
                    Context::Str => "in a string literal",
                    Context::Code | Context::Prose => "in code outside strings and comments",
                });
            }
            if ctrl.why & UNCLOSED != 0 {
                reasons.push("not closed before the end of the line");
            }
            if ctrl.why & STRAY != 0 {
                reasons.push("closes nothing");
            }
            if ctrl.why & REORDERS != 0 {
                reasons.push("reverses the visible text it covers");
            }
            format!("{} {}", describe(ctrl.c), reasons.join(", "))
        })
        .collect();
    if flagged.len() > MAX_LISTED {
        parts.push(format!("(+{} more)", flagged.len() - MAX_LISTED));
    }
    let noun = if flagged.len() == 1 {
        "control"
    } else {
        "controls"
    };
    format!("{} bidi {noun}: {}", flagged.len(), parts.join("; "))
}

// ---------------------------------------------------------------------------
// Source languages

/// A string delimiter.
#[derive(Debug)]
struct Quote {
    open: &'static str,
    close: &'static str,
    /// A backslash escapes the next byte.
    escapes: bool,
    /// May span lines; otherwise an unclosed string ends at the newline.
    multiline: bool,
}

const fn quote(open: &'static str, escapes: bool, multiline: bool) -> Quote {
    Quote {
        open,
        close: open,
        escapes,
        multiline,
    }
}

const DQ: Quote = quote("\"", true, false);
const SQ: Quote = quote("'", true, false);
const DQ_MULTI: Quote = quote("\"", true, true);
const SQ_RAW_MULTI: Quote = quote("'", false, true);
const BACKTICK: Quote = quote("`", true, true);
const TRIPLE_DQ: Quote = quote("\"\"\"", true, true);
const TRIPLE_SQ: Quote = quote("'''", true, true);

/// Just enough syntax to tell comments and strings from code.
#[derive(Debug)]
struct Syntax {
    line: &'static [&'static str],
    /// Checked before `line`, so `--[[` wins over `--`.
    block: &'static [(&'static str, &'static str)],
    /// Longest opener first.
    quotes: &'static [Quote],
    /// Text outside comments and strings is prose, not code.
    markup: bool,
}

static C_LIKE: Syntax = Syntax {
    line: &["//"],
    block: &[("/*", "*/")],
    quotes: &[TRIPLE_DQ, DQ, SQ, BACKTICK],
    markup: false,
};
// `'` starts lifetimes as well as char literals, and strings span lines.
static RUST: Syntax = Syntax {
    line: &["//"],
    block: &[("/*", "*/")],
    quotes: &[DQ_MULTI],
    markup: false,
};
static CSS: Syntax = Syntax {
    line: &[],
    block: &[("/*", "*/")],
    quotes: &[DQ, SQ],
    markup: false,
};
static HASH: Syntax = Syntax {
    line: &["#"],
    block: &[],
    quotes: &[TRIPLE_DQ, TRIPLE_SQ, DQ, SQ],
    markup: false,
};
static SHELL: Syntax = Syntax {
    line: &["#"],
    block: &[],
    quotes: &[DQ_MULTI, SQ_RAW_MULTI, BACKTICK],
    markup: false,
};
static POWERSHELL: Syntax = Syntax {
    line: &["#"],
    block: &[("<#", "#>")],
    quotes: &[DQ_MULTI, SQ_RAW_MULTI],
    markup: false,
};
static NIX: Syntax = Syntax {
    line: &["#"],
    block: &[("/*", "*/")],
    quotes: &[quote("''", false, true), DQ_MULTI],
    markup: false,
};
static DASH: Syntax = Syntax {
    line: &["--"],
    block: &[("--[[", "]]"), ("{-", "-}"), ("/*", "*/")],
    quotes: &[DQ, SQ],
    markup: false,
};
static LISP: Syntax = Syntax {
    line: &[";"],
    block: &[],
    quotes: &[DQ_MULTI],
    markup: false,
};
static PERCENT: Syntax = Syntax {
    line: &["%"],
    block: &[],
    quotes: &[DQ],
    markup: false,
};
static BATCH: Syntax = Syntax {
    line: &["::", "REM ", "rem ", "@REM ", "@rem "],
    block: &[],
    quotes: &[DQ],
    markup: false,
};
static MARKUP: Syntax = Syntax {
    line: &[],
    block: &[("<!--", "-->")],
    quotes: &[],
    markup: true,
};

/// The syntax of a source file, or `None` for text and data files, which
/// are judged as prose.
fn syntax_for(path: &str) -> Option<&'static Syntax> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let by_name = match name {
        "Makefile" | "makefile" | "GNUmakefile" | "Dockerfile" | "Containerfile" | "Rakefile"
        | "Gemfile" | "Podfile" | "Vagrantfile" | "Brewfile" | "Justfile" | "justfile"
        | "CMakeLists.txt" | "BUILD" | "BUILD.bazel" | "WORKSPACE" => Some(&HASH),
        "Jenkinsfile" => Some(&C_LIKE),
        ".bashrc" | ".bash_profile" | ".zshrc" | ".zprofile" | ".profile" | ".envrc" => {
            Some(&SHELL)
        }
        _ if name.starts_with("Dockerfile.") || name.starts_with("Containerfile.") => Some(&HASH),
        _ => None,
    };
    if by_name.is_some() {
        return by_name;
    }
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    let syntax =
        match ext.to_ascii_lowercase().as_str() {
            "rs" => &RUST,
            "c" | "h" | "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" | "ipp" | "inl"
            | "m" | "mm" | "cs" | "java" | "kt" | "kts" | "scala" | "sc" | "swift" | "go"
            | "dart" | "groovy" | "gradle" | "sol" | "proto" | "js" | "mjs" | "cjs" | "jsx"
            | "ts" | "mts" | "cts" | "tsx" | "php" | "zig" | "d" | "fs" | "fsx" | "hx" | "scss"
            | "less" | "cu" | "glsl" | "hlsl" | "wgsl" | "ino" => &C_LIKE,
            "css" => &CSS,
            "py" | "pyi" | "pyw" | "pyx" | "rb" | "rake" | "gemspec" | "pl" | "pm" | "t" | "r"
            | "jl" | "cr" | "ex" | "exs" | "nim" | "tcl" | "cmake" | "coffee" | "bzl" | "star"
            | "mk" | "just" => &HASH,
            "sh" | "bash" | "zsh" | "ksh" | "fish" => &SHELL,
            "ps1" | "psm1" | "psd1" => &POWERSHELL,
            "nix" => &NIX,
            "sql" | "lua" | "hs" | "lhs" | "elm" | "ada" | "adb" | "ads" | "vhd" | "vhdl"
            | "purs" => &DASH,
            "lisp" | "lsp" | "cl" | "el" | "clj" | "cljs" | "cljc" | "scm" | "ss" | "rkt"
            | "fnl" => &LISP,
            "erl" | "hrl" | "tex" | "sty" => &PERCENT,
            "bat" | "cmd" => &BATCH,
            "html" | "htm" | "xhtml" | "xml" | "svg" | "vue" | "svelte" | "xsl" | "xslt" => &MARKUP,
            _ => return None,
        };
    Some(syntax)
}

/// Comment and string regions of `text`, in order and disjoint. Every
/// delimiter is ASCII, so a match always starts on a char boundary.
/// Linear: each byte is examined a bounded number of times.
fn regions(text: &str, syntax: &Syntax) -> Vec<(Range<usize>, Context)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rest) = b.get(i..).filter(|r| !r.is_empty()) {
        if let Some(&(open, close)) = syntax
            .block
            .iter()
            .find(|(o, _)| rest.starts_with(o.as_bytes()))
        {
            let body = i + open.len();
            let end = text
                .get(body..)
                .and_then(|r| r.find(close))
                .map_or(b.len(), |p| body + p + close.len());
            out.push((i..end, Context::Comment));
            i = end;
        } else if syntax.line.iter().any(|p| rest.starts_with(p.as_bytes())) {
            let end = rest
                .iter()
                .position(|&c| c == b'\n')
                .map_or(b.len(), |p| i + p);
            out.push((i..end, Context::Comment));
            i = end;
        } else if let Some(q) = syntax
            .quotes
            .iter()
            .find(|q| rest.starts_with(q.open.as_bytes()))
        {
            let mut j = i + q.open.len();
            let end = loop {
                let Some(&c) = b.get(j) else {
                    break b.len();
                };
                if q.escapes && c == b'\\' {
                    j += 2;
                } else if b
                    .get(j..)
                    .is_some_and(|r| r.starts_with(q.close.as_bytes()))
                {
                    break j + q.close.len();
                } else if !q.multiline && c == b'\n' {
                    break j;
                } else {
                    j += 1;
                }
            };
            out.push((i..end, Context::Str));
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn context_at(regions: &[(Range<usize>, Context)], at: usize) -> Context {
    let idx = regions.partition_point(|(r, _)| r.start <= at);
    match idx.checked_sub(1).and_then(|i| regions.get(i)) {
        Some((r, ctx)) if r.contains(&at) => *ctx,
        _ => Context::Code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(path: &str, text: &str) -> Vec<Match> {
        detect(path, text)
    }

    fn details(path: &str, text: &str) -> Vec<String> {
        run(path, text)
            .into_iter()
            .map(|m| m.detail.unwrap_or_default())
            .collect()
    }

    fn assert_quiet(path: &str, text: &str) {
        let m = run(path, text);
        assert!(m.is_empty(), "unexpected match in {path} {text:?}: {m:?}");
    }

    #[test]
    fn commenting_out_attack_in_c_and_js() {
        // From the Trojan Source paper: the reviewer sees the check
        // commented out, the compiler sees it as code (and vice versa).
        let text = "int main() {\n    bool isAdmin = false;\n    \
                    /*\u{202E} } \u{2066}if (isAdmin)\u{2069} \u{2066} begin admins only */\n    \
                    puts(\"admin\");\n}\n";
        for path in ["src/main.c", "src/app.js", "Main.java"] {
            let m = run(path, text);
            assert_eq!(m.len(), 1, "{path}");
            let d = m[0].detail.as_deref().unwrap();
            assert!(d.starts_with("4 bidi controls: "), "{d}");
            assert!(
                d.contains("U+202E (RLO) in a comment, not closed before the end of the line"),
                "{d}"
            );
            assert!(d.contains("U+2066 (LRI) in a comment"), "{d}");
            assert!(d.contains("reverses the visible text"), "{d}");
            // The range starts at the RLO and stays on its line.
            assert_eq!(m[0].range.start, text.find('\u{202E}').unwrap());
            assert!(!text[m[0].range.clone()].contains('\n'));
        }
    }

    #[test]
    fn stretched_string_attack_in_python() {
        let text = "access_level = \"user\"\n\
                    if access_level != \"user\u{202E} \u{2066}# Check if admin\u{2069} \u{2066}\":\n    \
                    print(\"You are an admin.\")\n";
        let d = details("auth.py", text);
        assert_eq!(d.len(), 1);
        assert!(
            d[0].contains("U+202E (RLO) in a string literal"),
            "{}",
            d[0]
        );
        assert!(d[0].contains("not closed"), "{}", d[0]);
    }

    #[test]
    fn rust_strings_and_lifetimes() {
        let text = "fn f<'a>(x: &'a str) -> bool {\n    \
                    x == \"admin\u{2067}\u{2066}\" // ok\n}\n";
        let d = details("src/lib.rs", text);
        assert_eq!(d.len(), 1);
        assert!(
            d[0].contains("U+2067 (RLI) in a string literal"),
            "{}",
            d[0]
        );
        // Balanced but inside a string of code: still reported.
        let text = "let s = \"\u{2067}abc\u{2069}\";\n";
        let d = details("src/lib.rs", text);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("in a string literal"), "{}", d[0]);
        assert!(!d[0].contains("not closed"), "{}", d[0]);
    }

    #[test]
    fn controls_outside_strings_and_comments_in_code() {
        let d = details("x.go", "x := 1\u{2066}\u{2069}\n");
        assert_eq!(d.len(), 1);
        assert!(
            d[0].contains("in code outside strings and comments"),
            "{}",
            d[0]
        );
    }

    #[test]
    fn hebrew_and_arabic_prose_is_quiet() {
        // Plain right-to-left prose, directional marks, balanced isolates
        // and embeddings around a Latin word or a number.
        let cases = [
            "\u{05E9}\u{05DC}\u{05D5}\u{05DD} \u{05E2}\u{05D5}\u{05DC}\u{05DD}\n",
            "\u{0645}\u{0631}\u{062D}\u{0628}\u{0627} \u{0628}\u{0627}\u{0644}\u{0639}\u{0627}\u{0644}\u{0645}\n",
            "\u{05D4}\u{05D2}\u{05E8}\u{05E1}\u{05D4} \u{200F}2.0\u{200F} \u{05D6}\u{05DE}\u{05D9}\u{05E0}\u{05D4}\n",
            "\u{05D4}\u{05EA}\u{05E7}\u{05E0}\u{05EA} \u{2066}agentkeep scan\u{2069} \u{05D1}\u{05DE}\u{05E2}\u{05E8}\u{05DB}\u{05EA}\n",
            "\u{0627}\u{0633}\u{062A}\u{062E}\u{062F}\u{0645} \u{202A}cargo build\u{202C} \u{0627}\u{0644}\u{0622}\u{0646}\n",
            "Hello \u{2067}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{2069} world, \u{2068}\u{0633}\u{0644}\u{0627}\u{0645}\u{2069}!\n",
            "\u{061C}\u{0661}\u{0662}\u{0663} \u{0639}\u{0646}\u{0635}\u{0631}\n",
        ];
        for text in cases {
            for path in [
                "docs/he/README.md",
                "notes.txt",
                "locale/he.json",
                "i18n/ar.yaml",
            ] {
                assert_quiet(path, text);
            }
        }
        // An RLO over right-to-left text displays it the same way.
        assert_quiet("a.md", "\u{202E}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{202C}\n");
        // An LRO over Latin text changes nothing.
        assert_quiet("a.md", "\u{202D}hello\u{202C}\n");
    }

    #[test]
    fn unbalanced_controls_in_prose() {
        let d = details("README.md", "Click \u{2067}here\nnext line\n");
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0],
            "1 bidi control: U+2067 (RLI) not closed before the end of the line"
        );
        let d = details("README.md", "a\u{202C}b\n");
        assert_eq!(d, vec!["1 bidi control: U+202C (PDF) closes nothing"]);
        let d = details("README.md", "a\u{2069}b\n");
        assert_eq!(d, vec!["1 bidi control: U+2069 (PDI) closes nothing"]);
        // A PDF cannot close an embedding outside the current isolate.
        let d = details("a.txt", "\u{202B}x\u{2066}y\u{202C}z\u{2069}\u{202C}\n");
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("U+202C (PDF) closes nothing"), "{}", d[0]);
        assert!(!d[0].contains("not closed"), "{}", d[0]);
    }

    #[test]
    fn a_pdi_closes_embeddings_inside_its_isolate() {
        assert_quiet("a.md", "\u{2067}\u{202B}abc\u{2069}\n");
    }

    #[test]
    fn overrides_that_reverse_visible_text() {
        // The classic file name spoof: "invoice_txt.exe" shown as
        // "invoice_exe.txt".
        let text = "Attachment: invoice_\u{202E}txt.exe\u{202C} attached\n";
        let m = run("mail.md", text);
        assert_eq!(m.len(), 1);
        let d = m[0].detail.clone().unwrap();
        assert_eq!(
            d,
            "1 bidi control: U+202E (RLO) reverses the visible text it covers"
        );
        // The range covers the overridden text and its PDF.
        assert_eq!(&text[m[0].range.clone()], "\u{202E}txt.exe\u{202C}");
        // LRO over right-to-left letters reorders them.
        let d = details("a.md", "\u{202D}\u{05E9}\u{05DC}\u{05D5}\u{05DD}\u{202C}\n");
        assert!(d[0].contains("U+202D (LRO) reverses"), "{d:?}");
        // One visible character cannot be reordered.
        assert_quiet("a.md", "x\u{202E}y\u{202C}z\n");
    }

    #[test]
    fn markup_text_is_prose_but_comments_are_not() {
        let html = "<p>\u{05E9}\u{05DC}\u{05D5}\u{05DD} \u{2066}Rust\u{2069}</p>\n";
        assert_quiet("index.html", html);
        let d = details("index.html", "<!-- \u{2066}note\u{2069} -->\n");
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("in a comment"), "{}", d[0]);
    }

    #[test]
    fn paragraph_separators_end_scopes() {
        let d = details("a.md", "\u{202E}abc\u{2029}def\u{202C}\n");
        assert_eq!(d.len(), 2);
        assert!(d[0].contains("not closed"), "{}", d[0]);
        assert!(d[1].contains("closes nothing"), "{}", d[1]);
        // CRLF line ends.
        let d = details("a.md", "x\u{2067}y\r\nz\u{2069}\r\n");
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn one_match_per_line_and_ranges_on_char_boundaries() {
        let text = "\u{e9}\u{202E}a\u{e9}\u{2066}\n\u{1F600}\u{2069}\u{202C}\n";
        let m = run("a.md", text);
        assert_eq!(m.len(), 2);
        for m in &m {
            assert!(text.is_char_boundary(m.range.start));
            assert!(text.is_char_boundary(m.range.end));
            assert!(m.range.start < m.range.end && m.range.end <= text.len());
        }
    }

    #[test]
    fn long_runs_are_summarised() {
        let text = format!("{}\n", "\u{202E}".repeat(20));
        let d = details("a.md", &text);
        assert!(d[0].starts_with("20 bidi controls: "), "{}", d[0]);
        assert!(d[0].ends_with("(+14 more)"), "{}", d[0]);
    }

    #[test]
    fn syntax_selection() {
        let is = |path: &str, s: &'static Syntax| {
            syntax_for(path).is_some_and(|got| std::ptr::eq(got, s))
        };
        assert!(is("src/main.rs", &RUST));
        assert!(is("a/b/App.TSX", &C_LIKE));
        assert!(is("tool.py", &HASH));
        assert!(is("Makefile", &HASH));
        assert!(is("deploy/Dockerfile.prod", &HASH));
        assert!(is("scripts/x.sh", &SHELL));
        assert!(is(".bashrc", &SHELL));
        assert!(is("q.sql", &DASH));
        assert!(is("site/index.html", &MARKUP));
        for prose in [
            "README.md",
            "notes.txt",
            "he.json",
            "ci.yml",
            "a.toml",
            ".gitignore",
            "LICENSE",
        ] {
            assert!(syntax_for(prose).is_none(), "{prose}");
        }
    }

    #[test]
    fn lexer_regions() {
        let text = "a = \"x // y\" // c \"q\"\n/* b\n c */ 'z' `t\nu`";
        let r = regions(text, &C_LIKE);
        let got: Vec<(&str, Context)> = r.iter().map(|(r, c)| (&text[r.clone()], *c)).collect();
        assert_eq!(
            got,
            vec![
                ("\"x // y\"", Context::Str),
                ("// c \"q\"", Context::Comment),
                ("/* b\n c */", Context::Comment),
                ("'z'", Context::Str),
                ("`t\nu`", Context::Str),
            ]
        );
        let text = "s = \"\"\"doc\n\u{202E}\"\"\" # c\nx = 'a\\'b'";
        let r = regions(text, &HASH);
        assert_eq!(context_at(&r, text.find('\u{202E}').unwrap()), Context::Str);
        assert_eq!(
            context_at(&r, text.find("# c").unwrap() + 2),
            Context::Comment
        );
        assert_eq!(context_at(&r, text.find("x =").unwrap()), Context::Code);
        // Unterminated block comments and strings run to the end, a
        // single-line string stops at its newline.
        let r = regions("/* never closed", &C_LIKE);
        assert_eq!(r, vec![(0..15, Context::Comment)]);
        let r = regions("\"open\nnext", &C_LIKE);
        assert_eq!(r, vec![(0..5, Context::Str)]);
        let r = regions("--[[ long ]] -- short", &DASH);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, 0..12);
        // A trailing backslash cannot run past the end.
        assert_eq!(regions("\"\\", &C_LIKE), vec![(0..2, Context::Str)]);
    }

    #[test]
    fn hostile_inputs_stay_fast_and_bounded() {
        let cases = [
            "\u{202A}".repeat(300_000),
            "\u{2066}\u{202C}".repeat(150_000),
            format!("{}\n", "\u{202E}\n".repeat(200_000)),
            format!("/*{}", "\u{202E}x".repeat(200_000)),
            format!("\"{}", "\\\u{2067}".repeat(200_000)),
        ];
        for text in &cases {
            let start = std::time::Instant::now();
            let m = run("a.c", text);
            assert!(m.len() <= MAX_MATCHES);
            for m in &m {
                assert!(text.is_char_boundary(m.range.start) && text.is_char_boundary(m.range.end));
                assert!(m.detail.as_ref().unwrap().len() < 1_000);
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    #[test]
    fn options_are_rejected() {
        assert!(build(None).is_ok());
        assert!(build(Some(&serde_json::json!({"mode": "code"}))).is_err());
    }
}
